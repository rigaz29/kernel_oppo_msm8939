/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2026 Samsung Electronics Co., Ltd.
 * Author: Michal Wilczynski <m.wilczynski@samsung.com>
 *
 * Freestanding <limits.h> for the vendored upstream LZ4 sources; lz4.c needs
 * UINT_MAX and lz4hc.c needs INT_MAX.
 */
#ifndef __LZ4_FREESTANDING_LIMITS_H__
#define __LZ4_FREESTANDING_LIMITS_H__

#include <linux/kernel.h>	/* INT_MAX, UINT_MAX live here on 3.10 */

/* 3.10 builds gnu89, so lz4.c takes its C90 path, which checks UINT_MAX
 * in #if.  The kernel's (~0U) is 64-bit to the preprocessor.
 */
#undef UINT_MAX
#define UINT_MAX 4294967295U

#endif
