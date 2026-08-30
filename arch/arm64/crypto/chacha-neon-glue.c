/*
 * ARM64 NEON accelerated ChaCha and XChaCha stream ciphers,
 * including ChaCha20 (RFC7539)
 *
 * Copyright (C) 2016 - 2017 Linaro, Ltd. <ard.biesheuvel@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Based on:
 * ChaCha20 256-bit cipher algorithm, RFC7539, SIMD glue code
 *
 * Copyright (C) 2015 Martin Willi
 *
 * ---------------------------------------------------------------------------
 *
 * Diadaptasi ke kernel 3.10 untuk OPPO A37 (msm8916).
 *
 * Berkas .S diambil apa adanya dari mainline v5.4; seluruh dependensinya
 * (ENTRY/ENDPROC di linux/linkage.h, CPU_LE/CPU_BE di asm/assembler.h,
 * asm/cache.h) sudah ada di 3.10 sehingga tidak perlu diubah.
 *
 * Glue-nya DITULIS ULANG. Versi mainline memakai API skcipher yang belum ada
 * di 3.10; berkas ini memakai blkcipher_walk, mengikuti persis struktur
 * crypto/chacha_generic.c di pohon ini agar alur kendalinya sama dengan kode
 * generik yang sudah terbukti jalan.
 *
 * Alasan keberadaannya: Cortex-A53 pada msm8916 tidak punya ARMv8 Crypto
 * Extensions, sehingga AES berjalan lewat NEON/C sementara Adiantum
 * sepenuhnya C generik. Terukur di perangkat sebelum berkas ini ada:
 *   xts(aes) ber-NEON        30.90 MB/s
 *   adiantum C generik       47.67 MB/s   (1.54x)
 * ChaCha adalah komponen terberat Adiantum, jadi di sinilah NEON paling
 * berpengaruh.
 */

#include <crypto/algapi.h>
#include <crypto/chacha.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <asm/neon.h>
#include <asm/simd.h>

asmlinkage void chacha_block_xor_neon(u32 *state, u8 *dst, const u8 *src,
				      int nrounds);
asmlinkage void chacha_4block_xor_neon(u32 *state, u8 *dst, const u8 *src,
				       int nrounds, int bytes);
asmlinkage void hchacha_block_neon(const u32 *state, u32 *out, int nrounds);

/*
 * Di bawah ambang ini, biaya menyimpan/memulihkan register FP pada
 * kernel_neon_begin() lebih besar daripada keuntungan SIMD-nya.
 */
#define CHACHA_NEON_MIN_BYTES	(CHACHA_BLOCK_SIZE * 2)

static void chacha_doneon(u32 *state, u8 *dst, const u8 *src,
			  int bytes, int nrounds)
{
	while (bytes > 0) {
		int l = min(bytes, CHACHA_BLOCK_SIZE * 5);

		if (l <= CHACHA_BLOCK_SIZE) {
			u8 buf[CHACHA_BLOCK_SIZE];

			memcpy(buf, src, l);
			chacha_block_xor_neon(state, buf, buf, nrounds);
			memcpy(dst, buf, l);
			state[12] += 1;
			break;
		}
		chacha_4block_xor_neon(state, dst, src, nrounds, l);
		bytes -= CHACHA_BLOCK_SIZE * 5;
		src += CHACHA_BLOCK_SIZE * 5;
		dst += CHACHA_BLOCK_SIZE * 5;
		state[12] += 5;
	}
}

static int chacha_neon_stream_xor(struct blkcipher_desc *desc,
				  struct scatterlist *dst,
				  struct scatterlist *src, unsigned int nbytes,
				  struct chacha_ctx *ctx, u8 *iv)
{
	struct blkcipher_walk walk;
	u32 state[16];
	int err;

	blkcipher_walk_init(&walk, dst, src, nbytes);
	err = blkcipher_walk_virt_block(desc, &walk, CHACHA_BLOCK_SIZE);

	crypto_chacha_init(state, ctx, iv);

	while (walk.nbytes >= CHACHA_BLOCK_SIZE) {
		unsigned int chunk = rounddown(walk.nbytes, CHACHA_BLOCK_SIZE);

		kernel_neon_begin();
		chacha_doneon(state, walk.dst.virt.addr, walk.src.virt.addr,
			      chunk, ctx->nrounds);
		kernel_neon_end();

		err = blkcipher_walk_done(desc, &walk,
					  walk.nbytes % CHACHA_BLOCK_SIZE);
	}

	if (walk.nbytes) {
		kernel_neon_begin();
		chacha_doneon(state, walk.dst.virt.addr, walk.src.virt.addr,
			      walk.nbytes, ctx->nrounds);
		kernel_neon_end();

		err = blkcipher_walk_done(desc, &walk, 0);
	}

	return err;
}

static int chacha_neon(struct blkcipher_desc *desc, struct scatterlist *dst,
		       struct scatterlist *src, unsigned int nbytes)
{
	struct chacha_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);

	if (nbytes < CHACHA_NEON_MIN_BYTES || !may_use_simd())
		return crypto_chacha_crypt(desc, dst, src, nbytes);

	return chacha_neon_stream_xor(desc, dst, src, nbytes, ctx, desc->info);
}

static int xchacha_neon(struct blkcipher_desc *desc, struct scatterlist *dst,
			struct scatterlist *src, unsigned int nbytes)
{
	struct chacha_ctx *ctx = crypto_blkcipher_ctx(desc->tfm);
	struct chacha_ctx subctx;
	u32 state[16];
	u8 real_iv[16];

	if (nbytes < CHACHA_NEON_MIN_BYTES || !may_use_simd())
		return crypto_xchacha_crypt(desc, dst, src, nbytes);

	/* Turunkan subkey dari kunci asli dan 128 bit nonce pertama */
	crypto_chacha_init(state, ctx, desc->info);

	kernel_neon_begin();
	hchacha_block_neon(state, subctx.key, ctx->nrounds);
	kernel_neon_end();

	subctx.nrounds = ctx->nrounds;

	/* Susun IV sebenarnya */
	memcpy(&real_iv[0], desc->info + 24, 8);	/* posisi stream */
	memcpy(&real_iv[8], desc->info + 16, 8);	/* 64 bit nonce sisanya */

	return chacha_neon_stream_xor(desc, dst, src, nbytes, &subctx, real_iv);
}

static struct crypto_alg algs[] = {
	{
		.cra_name		= "chacha20",
		.cra_driver_name	= "chacha20-neon",
		.cra_priority		= 300,
		.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
		.cra_blocksize		= 1,
		.cra_type		= &crypto_blkcipher_type,
		.cra_ctxsize		= sizeof(struct chacha_ctx),
		.cra_alignmask		= sizeof(u32) - 1,
		.cra_module		= THIS_MODULE,
		.cra_u			= {
			.blkcipher = {
				.min_keysize	= CHACHA_KEY_SIZE,
				.max_keysize	= CHACHA_KEY_SIZE,
				.ivsize		= CHACHA_IV_SIZE,
				.geniv		= "seqiv",
				.setkey		= crypto_chacha20_setkey,
				.encrypt	= chacha_neon,
				.decrypt	= chacha_neon,
			},
		},
	}, {
		.cra_name		= "xchacha20",
		.cra_driver_name	= "xchacha20-neon",
		.cra_priority		= 300,
		.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
		.cra_blocksize		= 1,
		.cra_type		= &crypto_blkcipher_type,
		.cra_ctxsize		= sizeof(struct chacha_ctx),
		.cra_alignmask		= sizeof(u32) - 1,
		.cra_module		= THIS_MODULE,
		.cra_u			= {
			.blkcipher = {
				.min_keysize	= CHACHA_KEY_SIZE,
				.max_keysize	= CHACHA_KEY_SIZE,
				.ivsize		= XCHACHA_IV_SIZE,
				.geniv		= "seqiv",
				.setkey		= crypto_chacha20_setkey,
				.encrypt	= xchacha_neon,
				.decrypt	= xchacha_neon,
			},
		},
	}, {
		.cra_name		= "xchacha12",
		.cra_driver_name	= "xchacha12-neon",
		.cra_priority		= 300,
		.cra_flags		= CRYPTO_ALG_TYPE_BLKCIPHER,
		.cra_blocksize		= 1,
		.cra_type		= &crypto_blkcipher_type,
		.cra_ctxsize		= sizeof(struct chacha_ctx),
		.cra_alignmask		= sizeof(u32) - 1,
		.cra_module		= THIS_MODULE,
		.cra_u			= {
			.blkcipher = {
				.min_keysize	= CHACHA_KEY_SIZE,
				.max_keysize	= CHACHA_KEY_SIZE,
				.ivsize		= XCHACHA_IV_SIZE,
				.geniv		= "seqiv",
				.setkey		= crypto_chacha12_setkey,
				.encrypt	= xchacha_neon,
				.decrypt	= xchacha_neon,
			},
		},
	}
};

static int __init chacha_simd_mod_init(void)
{
	/*
	 * TIDAK memeriksa elf_hwcap & HWCAP_ASIMD seperti versi mainline.
	 *
	 * arch/arm64/kernel/setup.c pada kernel 3.10 ini hanya menyetel HWCAP
	 * untuk Crypto Extensions yang OPSIONAL -- HWCAP_AES, HWCAP_PMULL,
	 * HWCAP_SHA1, HWCAP_SHA2 -- dan tidak pernah menyetel HWCAP_ASIMD
	 * maupun HWCAP_FP. Pada ARMv8-A keduanya wajib secara arsitektur, jadi
	 * kernel seusia ini tidak repot menandainya; kernel yang lebih baru
	 * barulah menyetelnya eksplisit.
	 *
	 * Akibatnya pemeriksaan itu SELALU gagal di sini dan driver tidak
	 * pernah terdaftar -- terbukti di perangkat: simbolnya ada di
	 * /proc/kallsyms tetapi /proc/crypto hanya memuat varian generik.
	 *
	 * arch/arm64/crypto/aes-glue.c di pohon yang sama juga mendaftar tanpa
	 * memeriksa hwcap, dan itulah yang membuat xts-aes-neon berfungsi.
	 * Ketersediaan NEON sudah dijamin oleh CONFIG_KERNEL_MODE_NEON yang
	 * menjadi syarat Kconfig driver ini.
	 */
	return crypto_register_algs(algs, ARRAY_SIZE(algs));
}

static void __exit chacha_simd_mod_fini(void)
{
	crypto_unregister_algs(algs, ARRAY_SIZE(algs));
}

module_init(chacha_simd_mod_init);
module_exit(chacha_simd_mod_fini);

MODULE_DESCRIPTION("ChaCha and XChaCha stream ciphers (NEON accelerated)");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("chacha20");
MODULE_ALIAS_CRYPTO("chacha20-neon");
MODULE_ALIAS_CRYPTO("xchacha20");
MODULE_ALIAS_CRYPTO("xchacha20-neon");
MODULE_ALIAS_CRYPTO("xchacha12");
MODULE_ALIAS_CRYPTO("xchacha12-neon");
