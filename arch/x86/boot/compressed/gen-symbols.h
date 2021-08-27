/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * List of symbols needed for both C code and objcopy when FG-KASLR is on.
 * We declare them once and then just use GEN() definition.
 *
 * Copyright (C) 2021-2022, Intel Corporation.
 * Author: Alexander Lobakin <alexandr.lobakin@intel.com>
 */

#ifdef GEN
GEN(__altinstr_replacement)
GEN(__altinstr_replacement_end)
GEN(__start___ex_table)
GEN(__start_orc_unwind)
GEN(__start_orc_unwind_ip)
GEN(__stop___ex_table)
GEN(__stop_orc_unwind_ip)
GEN(_einittext)
GEN(_etext)
GEN(_sinittext)
GEN(_stext)
GEN(kallsyms_addresses)
GEN(kallsyms_markers)
GEN(kallsyms_names)
GEN(kallsyms_num_syms)
GEN(kallsyms_offsets)
GEN(kallsyms_relative_base)
GEN(kallsyms_token_index)
GEN(kallsyms_token_table)
#endif /* GEN */
