/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Build environment for the zstd sources imported from Linux v7.2, forced
 * into every lib/zstd object so the imported files stay verbatim.
 */
#ifndef __ZSTD_COMPAT_H
#define __ZSTD_COMPAT_H

/* INT_MAX and UINT_MAX are in <linux/kernel.h> on 3.10, not <linux/limits.h>. */
#include <linux/kernel.h>

/* 3.10 still has an abs64() macro; zstd_preSplit.c defines its own. */
#undef abs64

/* The fallthrough pseudo-keyword arrived in 5.4. */
#ifndef fallthrough
#define fallthrough do {} while (0)
#endif

#endif /* __ZSTD_COMPAT_H */
