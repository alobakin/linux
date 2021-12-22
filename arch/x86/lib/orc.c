// SPDX-License-Identifier: GPL-2.0-only
/*
 * ORC sorting shared by the compressed boot code and ORC module
 * support.
 */

#include <asm/orc_types.h>
#include <linux/mutex.h>
#include <linux/sort.h>

#ifndef ORC_COMPRESSED_BOOT
static DEFINE_MUTEX(sort_mutex);

#define sort_mutex_lock()	mutex_lock(&sort_mutex)
#define sort_mutex_unlock()	mutex_unlock(&sort_mutex)
#else /* ORC_COMPRESSED_BOOT */
#define sort_mutex_lock()
#define sort_mutex_unlock()
#endif /* ORC_COMPRESSED_BOOT */

static int *cur_orc_ip_table;
static struct orc_entry *cur_orc_table;

static void orc_sort_swap(void *_a, void *_b, int size)
{
	struct orc_entry *orc_a, *orc_b;
	int *a = _a, *b = _b, tmp;
	int delta = _b - _a;

	/* Swap the .orc_unwind_ip entries: */
	tmp = *a;
	*a = *b + delta;
	*b = tmp - delta;

	/* Swap the corresponding .orc_unwind entries: */
	orc_a = cur_orc_table + (a - cur_orc_ip_table);
	orc_b = cur_orc_table + (b - cur_orc_ip_table);
	swap(*orc_a, *orc_b);
}

static int orc_sort_cmp(const void *_a, const void *_b)
{
	const int *a = _a, *b = _b;
	unsigned long a_val = orc_ip(a);
	unsigned long b_val = orc_ip(b);
	struct orc_entry *orc_a;

	if (a_val > b_val)
		return 1;
	if (a_val < b_val)
		return -1;

	/*
	 * The "weak" section terminator entries need to always be on the left
	 * to ensure the lookup code skips them in favor of real entries.
	 * These terminator entries exist to handle any gaps created by
	 * whitelisted .o files which didn't get objtool generation.
	 */
	orc_a = cur_orc_table + (a - cur_orc_ip_table);

	return orc_a->sp_reg == ORC_REG_UNDEFINED && !orc_a->end ? -1 : 1;
}

void orc_sort(int *ip_table, struct orc_entry *orc_table, u32 num_orcs)
{
	/*
	 * The 'cur_orc_*' globals allow the orc_sort_swap() callback to
	 * associate an .orc_unwind_ip table entry with its corresponding
	 * .orc_unwind entry so they can both be swapped.
	 */
	sort_mutex_lock();

	cur_orc_ip_table = ip_table;
	cur_orc_table = orc_table;
	sort(ip_table, num_orcs, sizeof(int), orc_sort_cmp, orc_sort_swap);

	sort_mutex_unlock();
}
