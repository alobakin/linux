// SPDX-License-Identifier: GPL-2.0-only
/*
 * This contains the routines needed to reorder the kernel text section
 * at boot time.
 *
 * Copyright (C) 2020-2022, Intel Corporation.
 * Author: Kristen Carlson Accardi <kristen@linux.intel.com>
 */

#include "misc.h"
#include "error.h"
#include "pgtable.h"
#include "../string.h"
#include "../voffset.h"
#include <linux/sort.h>
#include <linux/random.h>
#include <linux/bsearch.h>
#include "../../include/asm/extable.h"
#include "../../include/asm/orc_types.h"

/*
 * Use normal definitions of mem*() from string.c. There are already
 * included header files which expect a definition of memset() and by
 * the time we define memset macro, it is too late.
 */
#undef memcpy
#undef memset
#define memmove		memmove

void *memmove(void *dest, const void *src, size_t n);

static int nofgkaslr;

static unsigned long percpu_start;
static unsigned long percpu_end;

#define GEN(s)		static long addr_##s;
#include "gen-symbols.h"
#undef GEN

/* addresses in mapped address space */
static int *kallsyms_base;
static u8 *names;
static unsigned long relative_base;
static unsigned int *markers_addr;

struct kallsyms_name {
	u8 len;
	u8 indices[256];
};

static struct kallsyms_name *names_table;

/* Array of pointers to sections headers for randomized sections */
static Elf_Shdr **sections;

/* Number of elements in the randomized section header array (sections) */
static int sections_size;

/* Array of all section headers, randomized or otherwise */
static Elf_Shdr *sechdrs;

static bool is_orc_unwind(long addr)
{
	if (addr >= addr___start_orc_unwind_ip &&
	    addr < addr___stop_orc_unwind_ip)
		return true;
	return false;
}

static bool is_text(long addr)
{
	if ((addr >= addr__stext && addr < addr__etext) ||
	    (addr >= addr__sinittext && addr < addr__einittext) ||
	    (addr >= addr___altinstr_replacement &&
	     addr < addr___altinstr_replacement_end))
		return true;
	return false;
}

bool is_percpu_addr(long pc, long offset)
{
	unsigned long ptr;
	long address;

	address = pc + offset + 4;

	ptr = (unsigned long)address;

	if (ptr >= percpu_start && ptr < percpu_end)
		return true;

	return false;
}

static bool cur_addr_orc;

static int cmp_section_addr(const void *a, const void *b)
{
	const Elf_Shdr *s = *(const Elf_Shdr **)b;
	unsigned long end = s->sh_addr + s->sh_size;
	unsigned long ptr = (unsigned long)a;

	if (cur_addr_orc)
		/* orc relocations can be one past the end of the section */
		end++;

	if (ptr >= s->sh_addr && ptr < end)
		return 0;

	if (ptr < s->sh_addr)
		return -1;

	return 1;
}

/*
 * Discover if the address is in a randomized section and if so,
 * adjust by the saved offset.
 */
Elf_Shdr *adjust_address(long *address)
{
	Elf_Shdr **s, *shdr;

	if (nofgkaslr)
		return NULL;

	s = bsearch((const void *)*address, sections, sections_size,
		    sizeof(*s), cmp_section_addr);
	if (!s)
		return NULL;

	shdr = *s;
	*address += shdr->sh_offset;

	return shdr;
}

void adjust_relative_offset(long pc, long *value, Elf_Shdr *section)
{
	long address;
	Elf_Shdr *s;

	if (nofgkaslr)
		return;

	/*
	 * sometimes we are updating a relative offset that would
	 * normally be relative to the next instruction (such as a call).
	 * In this case to calculate the target, you need to add 32bits to
	 * the pc to get the next instruction value. However, sometimes
	 * targets are just data that was stored in a table such as ksymtab
	 * or cpu alternatives. In this case our target is not relative to
	 * the next instruction.
	 */

	/* Calculate the address that this offset would call. */
	if (!is_text(pc))
		address = pc + *value;
	else
		address = pc + *value + 4;

	/*
	 * orc ip addresses are sorted at build time after relocs have
	 * been applied, making the relocs no longer valid. Skip any
	 * relocs for the orc_unwind_ip table. These will be updated
	 * separately.
	 */
	if (is_orc_unwind(pc))
		return;

	s = adjust_address(&address);

	/*
	 * if the address is in section that was randomized,
	 * we need to adjust the offset.
	 */
	if (s)
		*value += s->sh_offset;

	/*
	 * If the PC that this offset was calculated for was in a section
	 * that has been randomized, the value needs to be adjusted by the
	 * same amount as the randomized section was adjusted from it's original
	 * location.
	 */
	if (section)
		*value -= section->sh_offset;
}

static void kallsyms_swp(void *a, void *b, int size)
{
	struct kallsyms_name name_a;
	int idx1, idx2;

	/* Determine our index into the array. */
	idx1 = (const int *)a - kallsyms_base;
	idx2 = (const int *)b - kallsyms_base;
	swap(kallsyms_base[idx1], kallsyms_base[idx2]);

	/* Swap the names table. */
	memcpy(&name_a, &names_table[idx1], sizeof(name_a));
	memcpy(&names_table[idx1], &names_table[idx2],
	       sizeof(struct kallsyms_name));
	memcpy(&names_table[idx2], &name_a, sizeof(struct kallsyms_name));
}

static int kallsyms_cmp(const void *a, const void *b)
{
	unsigned long uaddr_a, uaddr_b;
	int addr_a, addr_b;

	addr_a = *(const int *)a;
	addr_b = *(const int *)b;

	if (addr_a >= 0)
		uaddr_a = addr_a;
	if (addr_b >= 0)
		uaddr_b = addr_b;

	if (addr_a < 0)
		uaddr_a = relative_base - 1 - addr_a;
	if (addr_b < 0)
		uaddr_b = relative_base - 1 - addr_b;

	if (uaddr_b > uaddr_a)
		return -1;

	return 0;
}

static void deal_with_names(int num_syms)
{
	int num_bytes;
	int offset;
	int i, j;

	/* we should have num_syms kallsyms_name entries */
	num_bytes = num_syms * sizeof(*names_table);
	names_table = malloc(num_syms * sizeof(*names_table));
	if (!names_table) {
		debug_putstr("\nbytes requested: ");
		debug_puthex(num_bytes);
		error("\nunable to allocate space for names table\n");
	}

	/* read all the names entries */
	offset = 0;
	for (i = 0; i < num_syms; i++) {
		names_table[i].len = names[offset];
		offset++;
		for (j = 0; j < names_table[i].len; j++) {
			names_table[i].indices[j] = names[offset];
			offset++;
		}
	}
}

static void write_sorted_names(int num_syms)
{
	unsigned int *markers;
	int offset = 0;
	int i, j;

	/*
	 * we are going to need to regenerate the markers table, which is a
	 * table of offsets into the compressed stream every 256 symbols.
	 * this code copied almost directly from scripts/kallsyms.c
	 */
	markers = malloc(sizeof(unsigned int) * ((num_syms + 255) / 256));
	if (!markers) {
		debug_putstr("\nfailed to allocate heap space of ");
		debug_puthex(((num_syms + 255) / 256));
		debug_putstr(" bytes\n");
		error("Unable to allocate space for markers table");
	}

	for (i = 0; i < num_syms; i++) {
		if ((i & 0xFF) == 0)
			markers[i >> 8] = offset;

		names[offset] = (u8)names_table[i].len;
		offset++;
		for (j = 0; j < names_table[i].len; j++) {
			names[offset] = names_table[i].indices[j];
			offset++;
		}
	}

	/* write new markers table over old one */
	for (i = 0; i < ((num_syms + 255) >> 8); i++)
		markers_addr[i] = markers[i];

	free(markers);
	free(names_table);
}

static void sort_kallsyms(unsigned long map)
{
	int num_syms;
	int i;

	debug_putstr("\nRe-sorting kallsyms...\n");

	num_syms = *(int *)(addr_kallsyms_num_syms + map);
	kallsyms_base = (int *)(addr_kallsyms_offsets + map);
	relative_base = *(unsigned long *)(addr_kallsyms_relative_base + map);
	markers_addr = (unsigned int *)(addr_kallsyms_markers + map);
	names = (u8 *)(addr_kallsyms_names + map);

	/*
	 * the kallsyms table was generated prior to any randomization.
	 * it is a bunch of offsets from "relative base". In order for
	 * us to check if a symbol has an address that was in a randomized
	 * section, we need to reconstruct the address to it's original
	 * value prior to handle_relocations.
	 */
	for (i = 0; i < num_syms; i++) {
		unsigned long addr;

		/*
		 * according to kernel/kallsyms.c, positive offsets are absolute
		 * values and negative offsets are relative to the base.
		 */
		if (kallsyms_base[i] >= 0)
			addr = kallsyms_base[i];
		else
			addr = relative_base - 1 - kallsyms_base[i];

		if (adjust_address(&addr))
			/* here we need to recalcuate the offset */
			kallsyms_base[i] = relative_base - 1 - addr;
	}

	/*
	 * here we need to read in all the kallsyms_names info
	 * so that we can regenerate it.
	 */
	deal_with_names(num_syms);

	sort(kallsyms_base, num_syms, sizeof(int), kallsyms_cmp, kallsyms_swp);

	/* write the newly sorted names table over the old one */
	write_sorted_names(num_syms);
}

/*
 * We need to include this file here rather than in utils.c because
 * some of the helper functions in extable.c are used to update
 * the extable below and are defined as "static" in extable.c
 */
#include "../../../../lib/extable.c"

static inline unsigned long
ex_fixup_addr(const struct exception_table_entry *x)
{
	return ((unsigned long)&x->fixup + x->fixup);
}

static void update_ex_table(unsigned long map)
{
	struct exception_table_entry *start_ex_table =
		(struct exception_table_entry *)(addr___start___ex_table + map);
	int num_entries =
		(addr___stop___ex_table - addr___start___ex_table) /
		sizeof(struct exception_table_entry);
	int i;

	debug_putstr("\nUpdating exception table...");
	for (i = 0; i < num_entries; i++) {
		unsigned long fixup = ex_fixup_addr(&start_ex_table[i]);
		unsigned long insn = ex_to_insn(&start_ex_table[i]);
		unsigned long addr;
		Elf_Shdr *s;

		/* check each address to see if it needs adjusting */
		addr = insn - map;
		s = adjust_address(&addr);
		if (s)
			start_ex_table[i].insn += s->sh_offset;

		addr = fixup - map;
		s = adjust_address(&addr);
		if (s)
			start_ex_table[i].fixup += s->sh_offset;
	}
}

static void sort_ex_table(unsigned long map)
{
	struct exception_table_entry *start_ex_table =
		(struct exception_table_entry *)(addr___start___ex_table + map);
	struct exception_table_entry *stop_ex_table =
		(struct exception_table_entry *)(addr___stop___ex_table + map);

	debug_putstr("\nRe-sorting exception table...");

	sort_extable(start_ex_table, stop_ex_table);
}

static void update_orc_table(unsigned long map)
{
	int *ip_table = (int *)(addr___start_orc_unwind_ip + map);
	int num_entries, i;

	num_entries = addr___stop_orc_unwind_ip - addr___start_orc_unwind_ip;
	num_entries /= sizeof(int);

	debug_putstr("\nUpdating orc tables...\n");
	cur_addr_orc = true;

	for (i = 0; i < num_entries; i++) {
		unsigned long ip = orc_ip(ip_table + i);
		Elf_Shdr *s;

		/* check each address to see if it needs adjusting */
		ip = ip - map;

		/*
		 * objtool places terminator entries just outside the end of
		 * the section. To identify an orc_unwind_ip address that might
		 * need adjusting, the address should be compared differently
		 * than a normal address.
		 */
		s = adjust_address(&ip);
		if (s)
			ip_table[i] += s->sh_offset;
	}

	cur_addr_orc = false;
}

static void sort_orc_table(unsigned long map)
{
	struct orc_entry *orc_table;
	int num_entries;
	int *ip_table;

	orc_table = (struct orc_entry *)(addr___start_orc_unwind + map);
	ip_table = (int *)(addr___start_orc_unwind_ip + map);

	num_entries = addr___stop_orc_unwind_ip - addr___start_orc_unwind_ip;
	num_entries /= sizeof(int);

	debug_putstr("\nRe-sorting orc tables...\n");
	orc_sort(ip_table, orc_table, num_entries);
}

void post_relocations_cleanup(unsigned long map)
{
	if (!nofgkaslr) {
		update_ex_table(map);
		sort_ex_table(map);
		update_orc_table(map);
		sort_orc_table(map);
	}

	/*
	 * maybe one day free will do something. So, we "free" this memory
	 * in either case
	 */
	free(sections);
	free(sechdrs);
}

void pre_relocations_cleanup(unsigned long map)
{
	if (nofgkaslr)
		return;

	sort_kallsyms(map);
}

static void move_text(int num_sections, char *secstrings, Elf_Shdr *text,
		      void *source, void *dest, Elf64_Phdr *phdr)
{
	unsigned long adjusted_addr;
	int *index_list;
	int copy_bytes;
	void *stash;
	int i, j;

	memmove(dest, source + text->sh_offset, text->sh_size);
	copy_bytes = text->sh_size;
	dest += text->sh_size;
	adjusted_addr = text->sh_addr + text->sh_size;

	/*
	 * we leave the sections sorted in their original order
	 * by s->sh_addr, but shuffle the indexes in a random
	 * order for copying.
	 */
	index_list = malloc(sizeof(int) * num_sections);
	if (!index_list)
		error("Failed to allocate space for index list");

	for (i = 0; i < num_sections; i++)
		index_list[i] = i;

#define get_random_long()	kaslr_get_random_long(NULL)
	shuffle_array(index_list, num_sections);
#undef get_random_long

	/*
	 * to avoid overwriting earlier sections before they can get
	 * copied to dest, stash everything into a buffer first.
	 * this will cause our source address to be off by
	 * phdr->p_offset though, so we'll adjust s->sh_offset below.
	 *
	 * TBD: ideally we'd simply decompress higher up so that our
	 * copy wasn't in danger of overwriting anything important.
	 */
	stash = malloc(phdr->p_filesz);
	if (!stash)
		error("Failed to allocate space for text stash");

	memcpy(stash, source + phdr->p_offset, phdr->p_filesz);

	/* now we'd walk through the sections. */
	for (j = 0; j < num_sections; j++) {
		unsigned long aligned_addr;
		int pad_bytes;
		Elf_Shdr *s;
		void *src;

		s = sections[index_list[j]];

		/* align addr for this section */
		aligned_addr = ALIGN(adjusted_addr, s->sh_addralign);

		/*
		 * copy out of stash, so adjust offset
		 */
		src = stash + s->sh_offset - phdr->p_offset;

		/*
		 * Fill any space between sections with int3
		 */
		pad_bytes = aligned_addr - adjusted_addr;
		memset(dest, 0xcc, pad_bytes);

		dest = (void *)ALIGN((unsigned long)dest, s->sh_addralign);

		memmove(dest, src, s->sh_size);

		dest += s->sh_size;
		copy_bytes += s->sh_size + pad_bytes;
		adjusted_addr = aligned_addr + s->sh_size;

		/* we can blow away sh_offset for our own uses */
		s->sh_offset = aligned_addr - s->sh_addr;
	}

	free(index_list);

	/*
	 * move remainder of text segment. Ok to just use original source
	 * here since this area is untouched.
	 */
	memmove(dest, source + text->sh_offset + copy_bytes,
		phdr->p_filesz - copy_bytes);
	free(stash);
}

static void parse_symtab(const Elf64_Sym *symtab, const char *strtab,
			 long num_syms)
{
	const Elf64_Sym *sym;

	if (!symtab || !strtab)
		return;

	debug_putstr("\nLooking for symbols... ");

	/*
	 * walk through the symbol table looking for the symbols
	 * that we care about.
	 */
	for (sym = symtab; --num_syms >= 0; sym++) {
		if (!sym->st_name)
			continue;

#define GEN(s) ({						\
	if (!addr_##s && !strcmp(#s, strtab + sym->st_name)) {	\
		addr_##s = sym->st_value;			\
		continue;					\
	}							\
});
#include "gen-symbols.h"
#undef GEN
	}
}

void layout_randomized_image(void *output, Elf64_Ehdr *ehdr, Elf64_Phdr *phdrs)
{
	Elf64_Sym *symtab = NULL;
	Elf_Shdr *percpu = NULL;
	Elf_Shdr *text = NULL;
	unsigned int shstrndx;
	int num_sections = 0;
	unsigned long shnum;
	char *strtab = NULL;
	long num_syms = 0;
	const char *sname;
	char *secstrings;
	Elf_Shdr shdr;
	Elf_Shdr *s;
	void *dest;
	int i;

	debug_putstr("\nParsing ELF section headers... ");

	/*
	 * Even though fgkaslr may have been disabled, we still
	 * need to parse through the section headers to get the
	 * start and end of the percpu section. This is because
	 * if we were built with CONFIG_FG_KASLR, there are more
	 * relative relocations present in vmlinux.relocs than
	 * just the percpu, and only the percpu relocs need to be
	 * adjusted when using just normal base address kaslr.
	 */
	if (cmdline_find_option_bool("nofgkaslr")) {
		warn("FG_KASLR disabled on cmdline.");
		nofgkaslr = 1;
	}

	/* read the first section header */
	shnum = ehdr->e_shnum;
	shstrndx = ehdr->e_shstrndx;
	if (shnum == SHN_UNDEF || shstrndx == SHN_XINDEX) {
		memcpy(&shdr, output + ehdr->e_shoff, sizeof(shdr));
		if (shnum == SHN_UNDEF)
			shnum = shdr.sh_size;
		if (shstrndx == SHN_XINDEX)
			shstrndx = shdr.sh_link;
	}

	/* we are going to need to allocate space for the section headers */
	sechdrs = malloc(sizeof(*sechdrs) * shnum);
	if (!sechdrs)
		error("Failed to allocate space for shdrs");

	sections = malloc(sizeof(*sections) * shnum);
	if (!sections)
		error("Failed to allocate space for section pointers");

	memcpy(sechdrs, output + ehdr->e_shoff,
	       sizeof(*sechdrs) * shnum);

	/* we need to allocate space for the section string table */
	s = &sechdrs[shstrndx];

	secstrings = malloc(s->sh_size);
	if (!secstrings)
		error("Failed to allocate space for shstr");

	memcpy(secstrings, output + s->sh_offset, s->sh_size);

	/*
	 * now we need to walk through the section headers and collect the
	 * sizes of the .text sections to be randomized.
	 */
	for (i = 0; i < shnum; i++) {
		s = &sechdrs[i];
		sname = secstrings + s->sh_name;

		if (s->sh_type == SHT_SYMTAB) {
			/* only one symtab per image */
			if (symtab)
				error("Unexpected duplicate symtab");

			symtab = malloc(s->sh_size);
			if (!symtab)
				error("Failed to allocate space for symtab");

			memcpy(symtab, output + s->sh_offset, s->sh_size);
			num_syms = s->sh_size / sizeof(*symtab);
			continue;
		}

		if (s->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
			if (strtab)
				error("Unexpected duplicate strtab");

			strtab = malloc(s->sh_size);
			if (!strtab)
				error("Failed to allocate space for strtab");

			memcpy(strtab, output + s->sh_offset, s->sh_size);
		}

		if (!strcmp(sname, ".text")) {
			if (text)
				error("Unexpected duplicate .text section");

			text = s;
			continue;
		}

		if (!strcmp(sname, ".data..percpu")) {
			/* get start addr for later */
			percpu = s;
			continue;
		}

		if (!(s->sh_flags & SHF_ALLOC) ||
		    !(s->sh_flags & SHF_EXECINSTR) ||
		    !(strstarts(sname, ".text")))
			continue;

		sections[num_sections] = s;

		num_sections++;
	}
	sections[num_sections] = NULL;
	sections_size = num_sections;

	parse_symtab(symtab, strtab, num_syms);

	for (i = 0; i < ehdr->e_phnum; i++) {
		Elf64_Phdr *phdr = &phdrs[i];

		switch (phdr->p_type) {
		case PT_LOAD:
			if ((phdr->p_align % 0x200000) != 0)
				error("Alignment of LOAD segment isn't multiple of 2MB");
			dest = output;
			dest += (phdr->p_paddr - LOAD_PHYSICAL_ADDR);
			if (!nofgkaslr &&
			    (text && phdr->p_offset == text->sh_offset)) {
				move_text(num_sections, secstrings, text,
					  output, dest, phdr);
			} else {
				if (percpu &&
				    phdr->p_offset == percpu->sh_offset) {
					percpu_start = percpu->sh_addr;
					percpu_end = percpu_start +
							phdr->p_filesz;
				}
				memmove(dest, output + phdr->p_offset,
					phdr->p_filesz);
			}
			break;
		default: /* Ignore other PT_* */
			break;
		}
	}

	/* we need to keep the section info to redo relocs */
	free(secstrings);
	free(phdrs);
}
