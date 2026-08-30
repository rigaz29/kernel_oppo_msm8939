/*
 * NHPoly1305 - fungsi hash ε-almost-∆-universal untuk Adiantum
 * (versi berbantuan NEON ARM64)
 *
 * Copyright 2018 Google LLC
 *
 * SPDX-License-Identifier: GPL-2.0
 *
 * ---------------------------------------------------------------------------
 *
 * Diadaptasi ke kernel 3.10 untuk OPPO A37 (msm8916).
 *
 * nh-neon-core.S diambil apa adanya dari mainline torvalds/linux v5.4; ia hanya
 * bergantung pada linux/linkage.h beserta ENTRY/ENDPROC, yang sudah ada di
 * 3.10. Berbeda dengan chacha-neon-core.S, berkas ini TIDAK memakai adr_l
 * maupun frame_push/frame_pop.
 *
 * Tiga penyesuaian pada glue-nya:
 *
 *   1. crypto_simd_usable() -> may_use_simd(). Yang pertama berasal dari
 *      crypto/internal/simd.h yang belum ada di 3.10; may_use_simd() di
 *      asm-generic/simd.h menyediakan makna yang sama.
 *
 *   2. Pemeriksaan cpu_have_named_feature(ASIMD) DIBUANG. Pada kernel ini
 *      arch/arm64/kernel/setup.c hanya mengisi HWCAP untuk Crypto Extensions
 *      yang opsional (AES/PMULL/SHA1/SHA2) dan tidak pernah menyetel
 *      HWCAP_ASIMD, karena pada ARMv8-A ASIMD wajib secara arsitektur.
 *      Mempertahankannya membuat driver tidak pernah terdaftar -- persis yang
 *      terjadi pada percobaan pertama chacha-neon-glue.c. Ketersediaan NEON
 *      dijamin oleh CONFIG_KERNEL_MODE_NEON yang jadi syarat Kconfig.
 *
 *   3. Pembungkus _nh_neon dipertahankan meski alasan aslinya (CFI) tidak
 *      berlaku di sini, karena ia juga menjembatani perbedaan tipe antara
 *      u8 hash[NH_HASH_BYTES] pada assembly dan __le64 hash[NH_NUM_PASSES]
 *      pada typedef nh_t.
 *
 * Alasan keberadaannya: setelah ChaCha memakai NEON, nhpoly1305 menjadi
 * komponen C generik terberat yang tersisa di Adiantum. Terukur sebelum
 * berkas ini ada:
 *   xts(aes) ber-NEON                        30.93 MB/s
 *   adiantum(xchacha12-neon, nhpoly-generic) 80.84 MB/s   (2.61x)
 */

#include <asm/neon.h>
#include <asm/simd.h>
#include <crypto/internal/hash.h>
#include <crypto/nhpoly1305.h>
#include <linux/module.h>

asmlinkage void nh_neon(const u32 *key, const u8 *message, size_t message_len,
			u8 hash[NH_HASH_BYTES]);

static void _nh_neon(const u32 *key, const u8 *message, size_t message_len,
		     __le64 hash[NH_NUM_PASSES])
{
	nh_neon(key, message, message_len, (u8 *)hash);
}

static int nhpoly1305_neon_update(struct shash_desc *desc,
				  const u8 *src, unsigned int srclen)
{
	if (srclen < 64 || !may_use_simd())
		return crypto_nhpoly1305_update(desc, src, srclen);

	do {
		unsigned int n = min_t(unsigned int, srclen, PAGE_SIZE);

		kernel_neon_begin();
		crypto_nhpoly1305_update_helper(desc, src, n, _nh_neon);
		kernel_neon_end();
		src += n;
		srclen -= n;
	} while (srclen);
	return 0;
}

static struct shash_alg nhpoly1305_alg = {
	.base.cra_name		= "nhpoly1305",
	.base.cra_driver_name	= "nhpoly1305-neon",
	.base.cra_priority	= 200,
	.base.cra_ctxsize	= sizeof(struct nhpoly1305_key),
	.base.cra_module	= THIS_MODULE,
	.digestsize		= POLY1305_DIGEST_SIZE,
	.init			= crypto_nhpoly1305_init,
	.update			= nhpoly1305_neon_update,
	.final			= crypto_nhpoly1305_final,
	.setkey			= crypto_nhpoly1305_setkey,
	.descsize		= sizeof(struct nhpoly1305_state),
};

static int __init nhpoly1305_mod_init(void)
{
	/* Lihat catatan (2) di atas: tidak memeriksa HWCAP_ASIMD. */
	return crypto_register_shash(&nhpoly1305_alg);
}

static void __exit nhpoly1305_mod_exit(void)
{
	crypto_unregister_shash(&nhpoly1305_alg);
}

module_init(nhpoly1305_mod_init);
module_exit(nhpoly1305_mod_exit);

MODULE_DESCRIPTION("NHPoly1305 ε-almost-∆-universal hash function (NEON-accelerated)");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
MODULE_ALIAS_CRYPTO("nhpoly1305");
MODULE_ALIAS_CRYPTO("nhpoly1305-neon");
