/*
 * zstd backend for zram.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/zstd.h>

#include "zcomp_zstd.h"

/* Read when a stream is created, so set it before zram is sized. */
static int zstd_level = 1;
module_param(zstd_level, int, 0644);
MODULE_PARM_DESC(zstd_level, "zstd compression level for new zram streams");

struct zcomp_zstd {
	zstd_parameters params;
	zstd_cctx *cctx;
	void *ws;
};

/*
 * zram decompresses under bit_spin_lock without a stream, so each CPU gets
 * its own decompression context. They live while any stream does.
 */
static DEFINE_MUTEX(zstd_dctx_lock);
static unsigned int zstd_dctx_users;
static DEFINE_PER_CPU(zstd_dctx *, zcomp_zstd_dctx);
static DEFINE_PER_CPU(void *, zcomp_zstd_dctx_ws);

static void *zstd_ws_alloc(size_t size)
{
	return __vmalloc(size, GFP_NOIO | __GFP_HIGHMEM | __GFP_ZERO,
			 PAGE_KERNEL);
}

/* Called with zstd_dctx_lock held. */
static void zstd_dctx_put(void)
{
	int cpu;

	if (--zstd_dctx_users)
		return;
	for_each_possible_cpu(cpu) {
		vfree(per_cpu(zcomp_zstd_dctx_ws, cpu));
		per_cpu(zcomp_zstd_dctx_ws, cpu) = NULL;
		per_cpu(zcomp_zstd_dctx, cpu) = NULL;
	}
}

static int zstd_dctx_get(void)
{
	size_t size = zstd_dctx_workspace_bound();
	int cpu, ret = 0;

	mutex_lock(&zstd_dctx_lock);
	if (zstd_dctx_users++)
		goto out;
	for_each_possible_cpu(cpu) {
		void *ws = zstd_ws_alloc(size);

		if (!ws) {
			ret = -ENOMEM;
			break;
		}
		per_cpu(zcomp_zstd_dctx_ws, cpu) = ws;
		per_cpu(zcomp_zstd_dctx, cpu) = zstd_init_dctx(ws, size);
		if (!per_cpu(zcomp_zstd_dctx, cpu)) {
			ret = -EINVAL;
			break;
		}
	}
	if (ret)
		zstd_dctx_put();
out:
	mutex_unlock(&zstd_dctx_lock);
	return ret;
}

static void *zcomp_zstd_create(void)
{
	struct zcomp_zstd *zs;
	size_t size;
	int level;

	zs = kzalloc(sizeof(*zs), GFP_NOIO);
	if (!zs)
		return NULL;

	level = clamp_t(int, ACCESS_ONCE(zstd_level), zstd_min_clevel(),
			zstd_max_clevel());
	zs->params = zstd_get_params(level, PAGE_SIZE);
	size = zstd_cctx_workspace_bound(&zs->params.cParams);
	zs->ws = zstd_ws_alloc(size);
	if (!zs->ws)
		goto err;
	zs->cctx = zstd_init_cctx(zs->ws, size);
	if (!zs->cctx)
		goto err;
	if (zstd_dctx_get())
		goto err;
	return zs;

err:
	vfree(zs->ws);
	kfree(zs);
	return NULL;
}

static void zcomp_zstd_destroy(void *private)
{
	struct zcomp_zstd *zs = private;

	mutex_lock(&zstd_dctx_lock);
	zstd_dctx_put();
	mutex_unlock(&zstd_dctx_lock);
	vfree(zs->ws);
	kfree(zs);
}

static int zcomp_zstd_compress(const unsigned char *src, unsigned char *dst,
		size_t *dst_len, void *private)
{
	struct zcomp_zstd *zs = private;
	size_t len;

	/* zcomp_strm_alloc() gives the destination two pages. */
	len = zstd_compress_cctx(zs->cctx, dst, PAGE_SIZE * 2, src, PAGE_SIZE,
				 &zs->params);
	if (zstd_is_error(len))
		return -EINVAL;
	*dst_len = len;
	return 0;
}

static int zcomp_zstd_decompress(const unsigned char *src, size_t src_len,
		unsigned char *dst)
{
	int cpu = get_cpu();
	size_t len;

	len = zstd_decompress_dctx(per_cpu(zcomp_zstd_dctx, cpu), dst, PAGE_SIZE,
				   src, src_len);
	put_cpu();
	if (zstd_is_error(len) || len != PAGE_SIZE)
		return -EINVAL;
	return 0;
}

struct zcomp_backend zcomp_zstd = {
	.compress = zcomp_zstd_compress,
	.decompress = zcomp_zstd_decompress,
	.create = zcomp_zstd_create,
	.destroy = zcomp_zstd_destroy,
	.name = "zstd",
};
