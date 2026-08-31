/*
 * key management facility for FS encryption support.
 *
 * Copyright (C) 2015, Google, Inc.
 *
 * This contains encryption key functions.
 *
 * Written by Michael Halcrow, Ildar Muslukhov, and Uday Savagaonkar, 2015.
 */

#include <keys/user-type.h>
#include <linux/hashtable.h>
#include <linux/scatterlist.h>
#include <crypto/algapi.h>
#include <linux/ratelimit.h>
#include <crypto/aes.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>
#include "fscrypt_private.h"

static struct crypto_shash *essiv_hash_tfm;

/**
 * derive_key_aes() - Derive a key using AES-128-ECB
 * @deriving_key: Encryption key used for derivation.
 * @source_key:   Source key to which to apply derivation.
 * @derived_raw_key:  Derived raw key.
 *
 * Return: Zero on success; non-zero otherwise.
 */
static int derive_key_aes(u8 deriving_key[FS_AES_128_ECB_KEY_SIZE],
				const struct fscrypt_key *source_key,
				u8 derived_raw_key[FS_MAX_KEY_SIZE])
{
	int res = 0;
	struct ablkcipher_request *req = NULL;
	DECLARE_CRYPTO_WAIT(wait);
	struct scatterlist src_sg, dst_sg;
	struct crypto_ablkcipher *tfm = crypto_alloc_ablkcipher("ecb(aes)", 0, 0);

	if (IS_ERR(tfm)) {
		res = PTR_ERR(tfm);
		tfm = NULL;
		goto out;
	}
	crypto_ablkcipher_set_flags(tfm, CRYPTO_TFM_REQ_WEAK_KEY);
	req = ablkcipher_request_alloc(tfm, GFP_NOFS);
	if (!req) {
		res = -ENOMEM;
		goto out;
	}
	ablkcipher_request_set_callback(req,
			CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
			crypto_req_done, &wait);
	res = crypto_ablkcipher_setkey(tfm, deriving_key,
					FS_AES_128_ECB_KEY_SIZE);
	if (res < 0)
		goto out;

	sg_init_one(&src_sg, source_key->raw, source_key->size);
	sg_init_one(&dst_sg, derived_raw_key, source_key->size);
	ablkcipher_request_set_crypt(req, &src_sg, &dst_sg, source_key->size,
				   NULL);
	res = crypto_wait_req(crypto_ablkcipher_encrypt(req), &wait);
out:
	ablkcipher_request_free(req);
	crypto_free_ablkcipher(tfm);
	return res;
}

static int validate_user_key(struct fscrypt_info *crypt_info,
			struct fscrypt_context *ctx, u8 *raw_key,
			const char *prefix, int min_keysize)
{
	char *description;
	struct key *keyring_key;
	struct fscrypt_key *master_key;
	const struct user_key_payload *ukp;
	int prefix_size = strlen(prefix);
	int full_key_len = prefix_size + (FS_KEY_DESCRIPTOR_SIZE * 2) + 1;
	int res;

	/* FIXME: 3.18 causes kernel panic.
	 description = kasprintf(GFP_NOFS, "%s%*phN", prefix,
				FS_KEY_DESCRIPTOR_SIZE,
				ctx->master_key_descriptor);
	 */
	description = kmalloc(full_key_len, GFP_NOFS);
	if (!description)
		return -ENOMEM;

	memcpy(description, prefix, prefix_size);
	sprintf(description + prefix_size,
			"%*phN", FS_KEY_DESCRIPTOR_SIZE,
			ctx->master_key_descriptor);
	description[full_key_len - 1] = '\0';

	keyring_key = request_key(&key_type_logon, description, NULL);
	kfree(description);
	if (IS_ERR(keyring_key))
		return PTR_ERR(keyring_key);
	down_read(&keyring_key->sem);

	if (keyring_key->type != &key_type_logon) {
		printk_once(KERN_WARNING
				"%s: key type must be logon\n", __func__);
		res = -ENOKEY;
		goto out;
	}
	ukp = user_key_payload(keyring_key);
	if (!ukp) {
		/* key was revoked before we acquired its semaphore */
		res = -EKEYREVOKED;
		goto out;
	}
	if (ukp->datalen != sizeof(struct fscrypt_key)) {
		res = -EINVAL;
		goto out;
	}
	master_key = (struct fscrypt_key *)ukp->data;
	BUILD_BUG_ON(FS_AES_128_ECB_KEY_SIZE != FS_KEY_DERIVATION_NONCE_SIZE);

	if (master_key->size < min_keysize || master_key->size > FS_MAX_KEY_SIZE
	    || master_key->size % AES_BLOCK_SIZE != 0) {
		printk_once(KERN_WARNING
				"%s: key size incorrect: %d\n",
				__func__, master_key->size);
		res = -ENOKEY;
		goto out;
	}
	if (crypt_info->ci_flags & FS_POLICY_FLAG_DIRECT_KEY) {
		/*
		 * DIRECT_KEY: kunci master dipakai apa adanya sebagai kunci
		 * berkas -- tidak ada penurunan AES-128-ECB per berkas. Yang
		 * membedakan antar berkas dipindah ke IV (lihat
		 * fscrypt_generate_iv). Hanya min_keysize byte pertama yang
		 * dipakai; pemeriksaan ukuran di atas sudah menjamin kunci
		 * master tidak lebih pendek dari itu.
		 */
		memcpy(raw_key, master_key->raw, min_keysize);
		res = 0;
	} else {
		res = derive_key_aes(ctx->nonce, master_key, raw_key);
	}
out:
	up_read(&keyring_key->sem);
	key_put(keyring_key);
	return res;
}

static const struct {
	const char *cipher_str;
	int keysize;
	int ivsize;
} available_modes[] = {
	[FS_ENCRYPTION_MODE_AES_256_XTS] = { "xts(aes)",
					     FS_AES_256_XTS_KEY_SIZE, 16 },
	[FS_ENCRYPTION_MODE_AES_256_CTS] = { "cts(cbc(aes))",
					     FS_AES_256_CTS_KEY_SIZE, 16 },
	[FS_ENCRYPTION_MODE_AES_128_CBC] = { "cbc(aes)",
					     FS_AES_128_CBC_KEY_SIZE, 16 },
	[FS_ENCRYPTION_MODE_AES_128_CTS] = { "cts(cbc(aes))",
					     FS_AES_128_CTS_KEY_SIZE, 16 },
	/*
	 * Adiantum: kunci 32 byte, IV 32 byte. Nilai ivsize inilah yang
	 * membedakannya dari seluruh mode AES di atas, dan alasan buffer IV
	 * di crypto.c harus berukuran FS_MAX_IV_SIZE. Angka-angka ini cocok
	 * dengan tabel mode Adiantum di pohon a6010
	 * (fs/ext4/crypto_key.c: keysize 32, ivsize 32).
	 */
	[FS_ENCRYPTION_MODE_ADIANTUM]    = { "adiantum(xchacha12,aes)",
					     32, 32 },
};

static int determine_cipher_type(struct fscrypt_info *ci, struct inode *inode,
				 const char **cipher_str_ret, int *keysize_ret,
				 int *ivsize_ret, u32 *mode_ret)
{
	u32 mode;

	if (!fscrypt_valid_enc_modes(ci->ci_data_mode, ci->ci_filename_mode)) {
		pr_warn_ratelimited("fscrypt: inode %lu uses unsupported encryption modes (contents mode %d, filenames mode %d)\n",
				    inode->i_ino,
				    ci->ci_data_mode, ci->ci_filename_mode);
		return -EINVAL;
	}

	if (S_ISREG(inode->i_mode)) {
		mode = ci->ci_data_mode;
	} else if (S_ISDIR(inode->i_mode) || S_ISLNK(inode->i_mode)) {
		mode = ci->ci_filename_mode;
	} else {
		WARN_ONCE(1, "fscrypt: filesystem tried to load encryption info for inode %lu, which is not encryptable (file type %d)\n",
			  inode->i_ino, (inode->i_mode & S_IFMT));
		return -EINVAL;
	}

	*cipher_str_ret = available_modes[mode].cipher_str;
	*keysize_ret = available_modes[mode].keysize;
	*ivsize_ret = available_modes[mode].ivsize;
	*mode_ret = mode;
	return 0;
}

/*
 * Tabel kunci master untuk kebijakan DIRECT_KEY.
 *
 * Pada DIRECT_KEY seluruh berkas memakai kunci master yang SAMA -- yang
 * membedakan antar berkas dipindah ke IV (lihat fscrypt_generate_iv). Tanpa
 * tabel ini setiap inode mengalokasikan tfm sendiri lalu memanggil setkey
 * sendiri, padahal kuncinya identik. Terukur di perangkat: /proc/crypto
 * menunjukkan refcnt 3067 untuk adiantum(xchacha12,aes) -- sekitar tiga ribu
 * salinan konteks kunci yang isinya sama persis.
 *
 * Biayanya dua arah:
 *   - memori. Tiap instans membawa empat tfm bersarang; yang terbesar kunci NH
 *     1072 byte (nhpoly1305_key). Di perangkat 1,9 GB dengan RAM bebas ~40 MB,
 *     itu terasa.
 *   - waktu. setkey Adiantum menurunkan 1136 byte keystream XChaCha12
 *     (adiantum.c:123, BLOCKCIPHER_KEY_SIZE + HASH_KEY_SIZE) ditambah jadwal
 *     kunci AES dan setkey nhpoly1305 -- diulang tiap inode dibuka.
 *
 * Diadaptasi dari acroreiser/android_kernel_lenovo_a6010, yang memecahkan
 * masalah yang sama di kernel 3.10.108 yang sama (fs/ext4/crypto_key.c:23,95,
 * 256-335). Bedanya hanya letak: mereka di stack enkripsi milik ext4, kita di
 * fs/crypto bersama yang dipakai f2fs. Mainline menyebutnya fscrypt_direct_key
 * di fs/crypto/keysetup_v1.c.
 */
static DEFINE_HASHTABLE(fscrypt_master_keys, 6);	/* 6 bit = 64 bucket */
static DEFINE_SPINLOCK(fscrypt_master_keys_lock);

struct fscrypt_master_key {
	struct hlist_node mk_node;
	atomic_t mk_refcount;
	u32 mk_mode;
	int mk_keysize;
	struct crypto_ablkcipher *mk_ctfm;
	u8 mk_descriptor[FS_KEY_DESCRIPTOR_SIZE];
	u8 mk_raw[FS_MAX_KEY_SIZE];
};

static void free_master_key(struct fscrypt_master_key *mk)
{
	if (mk) {
		crypto_free_ablkcipher(mk->mk_ctfm);
		kzfree(mk);
	}
}

static void put_master_key(struct fscrypt_master_key *mk)
{
	if (!atomic_dec_and_lock(&mk->mk_refcount, &fscrypt_master_keys_lock))
		return;
	hash_del(&mk->mk_node);
	spin_unlock(&fscrypt_master_keys_lock);

	free_master_key(mk);
}

static struct crypto_ablkcipher *allocate_ablkcipher(const char *cipher_str,
						     const u8 *raw_key,
						     int keysize,
						     const struct inode *inode)
{
	struct crypto_ablkcipher *ctfm;
	int err;

	ctfm = crypto_alloc_ablkcipher(cipher_str, 0, 0);
	if (!ctfm || IS_ERR(ctfm)) {
		err = ctfm ? PTR_ERR(ctfm) : -ENOMEM;
		pr_debug("%s: error %d (inode %lu) allocating crypto tfm\n",
			 __func__, err, inode->i_ino);
		return ERR_PTR(err);
	}
	crypto_ablkcipher_clear_flags(ctfm, ~0);
	crypto_ablkcipher_set_flags(ctfm, CRYPTO_TFM_REQ_WEAK_KEY);
	/*
	 * Kalau kunci yang diberikan lebih panjang dari keysize, hanya keysize
	 * byte pertama yang dipakai.
	 */
	err = crypto_ablkcipher_setkey(ctfm, raw_key, keysize);
	if (err) {
		crypto_free_ablkcipher(ctfm);
		return ERR_PTR(err);
	}
	return ctfm;
}

/*
 * Cari atau sisipkan kunci master ke dalam tabel. Kalau ketemu, ia dikembalikan
 * dengan refcount dinaikkan dan 'to_insert' dibebaskan bila bukan NULL. Kalau
 * tidak ketemu, 'to_insert' disisipkan dan dikembalikan; NULL bila to_insert
 * juga NULL.
 */
static struct fscrypt_master_key *
find_or_insert_master_key(struct fscrypt_master_key *to_insert,
			  const u8 *raw_key, u32 mode, int keysize,
			  const struct fscrypt_info *ci)
{
	unsigned long hash_key;
	struct fscrypt_master_key *mk;

	/*
	 * Hati-hati: tabel di-hash berdasarkan DESKRIPTOR, bukan kunci mentah,
	 * dan perbandingan kunci memakai crypto_memneq(). Kalau di-hash dari
	 * kunci mentah, waktu pencariannya bisa membocorkan isi kunci.
	 */
	BUILD_BUG_ON(sizeof(hash_key) > FS_KEY_DESCRIPTOR_SIZE);
	memcpy(&hash_key, ci->ci_master_key, sizeof(hash_key));

	spin_lock(&fscrypt_master_keys_lock);
	hash_for_each_possible(fscrypt_master_keys, mk, mk_node, hash_key) {
		if (memcmp(ci->ci_master_key, mk->mk_descriptor,
			   FS_KEY_DESCRIPTOR_SIZE) != 0)
			continue;
		if (mode != mk->mk_mode || keysize != mk->mk_keysize)
			continue;
		if (crypto_memneq(raw_key, mk->mk_raw, keysize))
			continue;
		/* tfm yang sama untuk (deskriptor, mode, kunci) yang sama */
		atomic_inc(&mk->mk_refcount);
		spin_unlock(&fscrypt_master_keys_lock);
		free_master_key(to_insert);
		return mk;
	}
	if (to_insert)
		hash_add(fscrypt_master_keys, &to_insert->mk_node, hash_key);
	spin_unlock(&fscrypt_master_keys_lock);
	return to_insert;
}

static struct fscrypt_master_key *
get_master_key(const struct fscrypt_info *ci, const char *cipher_str,
	       const u8 *raw_key, u32 mode, int keysize,
	       const struct inode *inode)
{
	struct fscrypt_master_key *mk;
	int err;

	/* Sudah ada tfm untuk kunci ini? */
	mk = find_or_insert_master_key(NULL, raw_key, mode, keysize, ci);
	if (mk)
		return mk;

	/* Belum -- buat satu. */
	mk = kzalloc(sizeof(*mk), GFP_NOFS);
	if (!mk)
		return ERR_PTR(-ENOMEM);
	atomic_set(&mk->mk_refcount, 1);
	mk->mk_mode = mode;
	mk->mk_keysize = keysize;
	mk->mk_ctfm = allocate_ablkcipher(cipher_str, raw_key, keysize, inode);
	if (IS_ERR(mk->mk_ctfm)) {
		err = PTR_ERR(mk->mk_ctfm);
		mk->mk_ctfm = NULL;
		free_master_key(mk);
		return ERR_PTR(err);
	}
	memcpy(mk->mk_descriptor, ci->ci_master_key, FS_KEY_DESCRIPTOR_SIZE);
	memcpy(mk->mk_raw, raw_key, keysize);

	/*
	 * Balapan: thread lain bisa menyisipkan kunci yang sama sementara kita
	 * mengalokasikan. find_or_insert menangani itu -- punya kita dibuang.
	 */
	return find_or_insert_master_key(mk, raw_key, mode, keysize, ci);
}

static void put_crypt_info(struct fscrypt_info *ci)
{
	if (!ci)
		return;

	/*
	 * Pada DIRECT_KEY ci_ctfm dimiliki bersama lewat tabel kunci master;
	 * yang boleh kita lepas hanya rujukannya, bukan tfm-nya.
	 */
	if (ci->ci_mk)
		put_master_key(ci->ci_mk);
	else
		crypto_free_ablkcipher(ci->ci_ctfm);
	crypto_free_cipher(ci->ci_essiv_tfm);
	kmem_cache_free(fscrypt_info_cachep, ci);
}

static int derive_essiv_salt(const u8 *key, int keysize, u8 *salt)
{
	struct crypto_shash *tfm = READ_ONCE(essiv_hash_tfm);

	/* init hash transform on demand */
	if (unlikely(!tfm)) {
		struct crypto_shash *prev_tfm;

		tfm = crypto_alloc_shash("sha256", 0, 0);
		if (IS_ERR(tfm)) {
			pr_warn_ratelimited("fscrypt: error allocating SHA-256 transform: %ld\n",
					    PTR_ERR(tfm));
			return PTR_ERR(tfm);
		}
		prev_tfm = cmpxchg(&essiv_hash_tfm, NULL, tfm);
		if (prev_tfm) {
			crypto_free_shash(tfm);
			tfm = prev_tfm;
		}
	}

	{
		SHASH_DESC_ON_STACK(desc, tfm);
		desc->tfm = tfm;
		desc->flags = 0;

		return crypto_shash_digest(desc, key, keysize, salt);
	}
}

static int init_essiv_generator(struct fscrypt_info *ci, const u8 *raw_key,
				int keysize)
{
	int err;
	struct crypto_cipher *essiv_tfm;
	u8 salt[SHA256_DIGEST_SIZE];

	essiv_tfm = crypto_alloc_cipher("aes", 0, 0);
	if (IS_ERR(essiv_tfm))
		return PTR_ERR(essiv_tfm);

	ci->ci_essiv_tfm = essiv_tfm;

	err = derive_essiv_salt(raw_key, keysize, salt);
	if (err)
		goto out;

	/*
	 * Using SHA256 to derive the salt/key will result in AES-256 being
	 * used for IV generation. File contents encryption will still use the
	 * configured keysize (AES-128) nevertheless.
	 */
	err = crypto_cipher_setkey(essiv_tfm, salt, sizeof(salt));
	if (err)
		goto out;

out:
	memzero_explicit(salt, sizeof(salt));
	return err;
}

void __exit fscrypt_essiv_cleanup(void)
{
	crypto_free_shash(essiv_hash_tfm);
}

int fscrypt_get_encryption_info(struct inode *inode)
{
	struct fscrypt_info *crypt_info;
	struct fscrypt_context ctx;
	struct crypto_ablkcipher *ctfm;
	const char *cipher_str;
	int keysize;
	int ivsize;
	u32 mode;
	u8 *raw_key = NULL;
	int res;

	if (inode->i_crypt_info)
		return 0;

	res = fscrypt_initialize(inode->i_sb->s_cop->flags);
	if (res)
		return res;

	res = inode->i_sb->s_cop->get_context(inode, &ctx, sizeof(ctx));
	if (res < 0) {
		if (!fscrypt_dummy_context_enabled(inode) ||
		    IS_ENCRYPTED(inode))
			return res;
		/* Fake up a context for an unencrypted directory */
		memset(&ctx, 0, sizeof(ctx));
		ctx.format = FS_ENCRYPTION_CONTEXT_FORMAT_V1;
		ctx.contents_encryption_mode = FS_ENCRYPTION_MODE_AES_256_XTS;
		ctx.filenames_encryption_mode = FS_ENCRYPTION_MODE_AES_256_CTS;
		memset(ctx.master_key_descriptor, 0x42, FS_KEY_DESCRIPTOR_SIZE);
	} else if (res != sizeof(ctx)) {
		return -EINVAL;
	}

	if (ctx.format != FS_ENCRYPTION_CONTEXT_FORMAT_V1)
		return -EINVAL;

	if (ctx.flags & ~FS_POLICY_FLAGS_VALID)
		return -EINVAL;

	crypt_info = kmem_cache_alloc(fscrypt_info_cachep, GFP_NOFS);
	if (!crypt_info)
		return -ENOMEM;

	crypt_info->ci_flags = ctx.flags;
	crypt_info->ci_data_mode = ctx.contents_encryption_mode;
	crypt_info->ci_filename_mode = ctx.filenames_encryption_mode;
	crypt_info->ci_ctfm = NULL;
	crypt_info->ci_essiv_tfm = NULL;
	crypt_info->ci_mk = NULL;
	memcpy(crypt_info->ci_master_key, ctx.master_key_descriptor,
				sizeof(crypt_info->ci_master_key));

	res = determine_cipher_type(crypt_info, inode, &cipher_str, &keysize,
				    &ivsize, &mode);
	if (res)
		goto out;
	crypt_info->ci_mode_ivsize = ivsize;
	memcpy(crypt_info->ci_nonce, ctx.nonce, FS_KEY_DERIVATION_NONCE_SIZE);

	/*
	 * Pada DIRECT_KEY nonce per berkas harus muat di dalam IV, kalau tidak
	 * seluruh berkas berbagi kunci DAN IV yang sama. Ini menyaring
	 * kombinasi seperti aes-256-xts+DIRECT_KEY, yang IV-nya cuma 16 byte.
	 */
	if ((ctx.flags & FS_POLICY_FLAG_DIRECT_KEY) &&
	    ivsize < offsetofend(union fscrypt_iv, nonce)) {
		res = -EINVAL;
		goto out;
	}

	/*
	 * This cannot be a stack buffer because it is passed to the scatterlist
	 * crypto API as part of key derivation.
	 */
	res = -ENOMEM;
	raw_key = kmalloc(FS_MAX_KEY_SIZE, GFP_NOFS);
	if (!raw_key)
		goto out;

	res = validate_user_key(crypt_info, &ctx, raw_key, FS_KEY_DESC_PREFIX,
				keysize);
	if (res && inode->i_sb->s_cop->key_prefix) {
		int res2 = validate_user_key(crypt_info, &ctx, raw_key,
					     inode->i_sb->s_cop->key_prefix,
					     keysize);
		if (res2) {
			if (res2 == -ENOKEY)
				res = -ENOKEY;
			goto out;
		}
	} else if (res) {
		goto out;
	}
	if (crypt_info->ci_flags & FS_POLICY_FLAG_DIRECT_KEY) {
		struct fscrypt_master_key *mk;

		mk = get_master_key(crypt_info, cipher_str, raw_key, mode,
				    keysize, inode);
		if (IS_ERR(mk)) {
			res = PTR_ERR(mk);
			goto out;
		}
		crypt_info->ci_mk = mk;
		crypt_info->ci_ctfm = mk->mk_ctfm;
	} else {
		ctfm = allocate_ablkcipher(cipher_str, raw_key, keysize, inode);
		if (IS_ERR(ctfm)) {
			res = PTR_ERR(ctfm);
			goto out;
		}
		crypt_info->ci_ctfm = ctfm;
	}

	if (S_ISREG(inode->i_mode) &&
	    crypt_info->ci_data_mode == FS_ENCRYPTION_MODE_AES_128_CBC) {
		res = init_essiv_generator(crypt_info, raw_key, keysize);
		if (res) {
			pr_debug("%s: error %d (inode %lu) allocating essiv tfm\n",
				 __func__, res, inode->i_ino);
			goto out;
		}
	}
	if (cmpxchg(&inode->i_crypt_info, NULL, crypt_info) == NULL)
		crypt_info = NULL;
out:
	if (res == -ENOKEY)
		res = 0;
	put_crypt_info(crypt_info);
	kzfree(raw_key);
	return res;
}
EXPORT_SYMBOL(fscrypt_get_encryption_info);

void fscrypt_put_encryption_info(struct inode *inode)
{
	put_crypt_info(inode->i_crypt_info);
	inode->i_crypt_info = NULL;
}
EXPORT_SYMBOL(fscrypt_put_encryption_info);
