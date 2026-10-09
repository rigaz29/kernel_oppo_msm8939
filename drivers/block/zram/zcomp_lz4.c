/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/lz4.h>

#include "zcomp_lz4.h"

static void *zcomp_lz4_create(void)
{
	return kzalloc(LZ4_MEM_COMPRESS, GFP_KERNEL);
}

static void zcomp_lz4_destroy(void *private)
{
	kfree(private);
}

static int zcomp_lz4_compress(const unsigned char *src, unsigned char *dst,
		size_t *dst_len, void *private)
{
	int len;

	/* zcomp_strm_alloc() gives the destination two pages. */
	len = LZ4_compress_default((const char *)src, (char *)dst, PAGE_SIZE,
				   PAGE_SIZE * 2, private);
	if (!len)
		return -EINVAL;
	*dst_len = len;
	return 0;
}

static int zcomp_lz4_decompress(const unsigned char *src, size_t src_len,
		unsigned char *dst)
{
	int len;

	len = LZ4_decompress_safe((const char *)src, (char *)dst, src_len,
				  PAGE_SIZE);
	if (len < 0)
		return -EINVAL;
	return 0;
}

struct zcomp_backend zcomp_lz4 = {
	.compress = zcomp_lz4_compress,
	.decompress = zcomp_lz4_decompress,
	.create = zcomp_lz4_create,
	.destroy = zcomp_lz4_destroy,
	.name = "lz4",
};
