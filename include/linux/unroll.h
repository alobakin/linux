/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (C) 2024 Intel Corporation */

#ifndef __LINUX_UNROLL_H
#define __LINUX_UNROLL_H

#include <linux/build_bug.h>

#ifdef CONFIG_CC_IS_CLANG
#define __pick_unrolled(x, y)	_Pragma(#x)
#elif CONFIG_GCC_VERSION >= 80000
#define __pick_unrolled(x, y)	_Pragma(#y)
#else
#define __pick_unrolled(x, y)	/* not supported */
#endif

/**
 * unrolled - loop attributes to ask the compiler to unroll it
 *
 * Usage:
 * #define BATCH 4
 *	unrolled_count(BATCH)
 *	for (u32 i = 0; i < BATCH; i++)
 *		// loop body without cross-iteration dependencies
 *
 * This is only a hint and the compiler is free to disable unrolling if it
 * thinks the count is suboptimal and may hurt performance and/or hugely
 * increase object code size.
 * Not having any cross-iteration dependencies (i.e. when iter x + 1 depends
 * on what iter x will do with variables) is not a strict requirement, but
 * provides best performance and object code size.
 * Available only on Clang and GCC 8.x onwards.
 */

/* Ask the compiler to pick an optimal unroll count, Clang only */
#define unrolled							    \
	__pick_unrolled(clang loop unroll(enable), /* nothing */)

/* Unroll each @n iterations of a loop */
#define unrolled_count(n)						    \
	__pick_unrolled(clang loop unroll_count(n), GCC unroll n)

/* Unroll the whole loop */
#define unrolled_full							    \
	__pick_unrolled(clang loop unroll(full), GCC unroll 65534)

/* Never unroll a loop */
#define unrolled_none							    \
	__pick_unrolled(clang loop unroll(disable), GCC unroll 1)

/**
 * unrolled_call - explicitly unroll a loop
 * @times: number of times to call @fn, in range [1, 32]
 * @fn: function to call repeatedly
 *
 * Usage:
 * #define BATCH 4
 * #define func(ptr, i)	// loop body without cross-iteration dependencies
 *	u32 i = 0;
 *	unrolled_call(BATCH, func, ptr, i++);
 *
 * Less convenient than unrolled* above, but available on every compiler
 * and always performs unrolling even if the compiler wouldn't do that
 * under an unrolled* hint due to his optimization decisions.
 */
#define unrolled_call(times, fn, ...) do {				    \
	static_assert(__builtin_constant_p(times));			    \
									    \
	switch (times) {						    \
	case 32: fn(__VA_ARGS__); fallthrough;				    \
	case 31: fn(__VA_ARGS__); fallthrough;				    \
	case 30: fn(__VA_ARGS__); fallthrough;				    \
	case 29: fn(__VA_ARGS__); fallthrough;				    \
	case 28: fn(__VA_ARGS__); fallthrough;				    \
	case 27: fn(__VA_ARGS__); fallthrough;				    \
	case 26: fn(__VA_ARGS__); fallthrough;				    \
	case 25: fn(__VA_ARGS__); fallthrough;				    \
	case 24: fn(__VA_ARGS__); fallthrough;				    \
	case 23: fn(__VA_ARGS__); fallthrough;				    \
	case 22: fn(__VA_ARGS__); fallthrough;				    \
	case 21: fn(__VA_ARGS__); fallthrough;				    \
	case 20: fn(__VA_ARGS__); fallthrough;				    \
	case 19: fn(__VA_ARGS__); fallthrough;				    \
	case 18: fn(__VA_ARGS__); fallthrough;				    \
	case 17: fn(__VA_ARGS__); fallthrough;				    \
	case 16: fn(__VA_ARGS__); fallthrough;				    \
	case 15: fn(__VA_ARGS__); fallthrough;				    \
	case 14: fn(__VA_ARGS__); fallthrough;				    \
	case 13: fn(__VA_ARGS__); fallthrough;				    \
	case 12: fn(__VA_ARGS__); fallthrough;				    \
	case 11: fn(__VA_ARGS__); fallthrough;				    \
	case 10: fn(__VA_ARGS__); fallthrough;				    \
	case 9: fn(__VA_ARGS__); fallthrough;				    \
	case 8: fn(__VA_ARGS__); fallthrough;				    \
	case 7: fn(__VA_ARGS__); fallthrough;				    \
	case 6: fn(__VA_ARGS__); fallthrough;				    \
	case 5: fn(__VA_ARGS__); fallthrough;				    \
	case 4: fn(__VA_ARGS__); fallthrough;				    \
	case 3: fn(__VA_ARGS__); fallthrough;				    \
	case 2: fn(__VA_ARGS__); fallthrough;				    \
	case 1: fn(__VA_ARGS__); break;					    \
	default:							    \
		/*							    \
		 * Either the iteration count is unreasonable or we need    \
		 * to add more cases above.				    \
		 */							    \
		BUILD_BUG_ON_MSG(1, "Unsupported unroll count: " #times);   \
		break;							    \
	}								    \
} while (0)

#endif /* __LINUX_UNROLL_H */
