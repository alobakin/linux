// SPDX-License-Identifier: GPL-2.0-only
/*
 * This contains various libraries that are needed for FG-KASLR.
 *
 * Copyright (C) 2020-2022, Intel Corporation.
 * Author: Kristen Carlson Accardi <kristen@linux.intel.com>
 */

#define _LINUX_KPROBES_H
#define NOKPROBE_SYMBOL(fname)

#include "../../../../lib/sort.c"
#include "../../../../lib/bsearch.c"

#define ORC_COMPRESSED_BOOT
#include "../../lib/orc.c"
