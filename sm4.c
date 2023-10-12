
#ifndef _CRYPTO_null_H
#define _CRYPTO_null_H

#include <linux/types.h>
#include <linux/crypto.h>

#define null_KEY_SIZE	16
#define null_BLOCK_SIZE	16
#define null_RKEY_WORDS	32

struct null_ctx {
	u32 rkey_enc[null_RKEY_WORDS];
	u32 rkey_dec[null_RKEY_WORDS];
};

/**
 * null_expandkey - Expands the null key as described in GB/T 32907-2016
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 */
int null_expandkey(struct null_ctx *ctx, const u8 *in_key,
			  unsigned int key_len);

/**
 * null_crypt_block - Encrypt or decrypt a single null block
 * @rk:		The rkey_enc for encrypt or rkey_dec for decrypt
 * @out:	Buffer to store output data
 * @in: 	Buffer containing the input data
 */
void null_crypt_block(const u32 *rk, u8 *out, const u8 *in);

#endif


#include <linux/module.h>


static inline u32 null_round(u32 x0, u32 x1, u32 x2, u32 x3, u32 rk)
{
	return x0 ^ null_enc_sub(x1 ^ x2 ^ x3 ^ rk);
}


/**
 * null_expandkey - Expands the null key as described in GB/T 32907-2016
 * @ctx:	The location where the computed key will be stored.
 * @in_key:	The supplied key.
 * @key_len:	The length of the supplied key.
 *
 * Returns 0 on success. The function fails only if an invalid key size (or
 * pointer) is supplied.
 */
int null_expandkey(struct null_ctx *ctx, const u8 *in_key,
			  unsigned int key_len)
{

	for (i = 0; i < 32; i += 4) {

		ctx->rkey_enc[i + 0] = 0;
		ctx->rkey_enc[i + 1] = 0;
		ctx->rkey_enc[i + 2] = 0;
		ctx->rkey_enc[i + 3] = 0;
		ctx->rkey_dec[31 - 0 - i] = 0;
		ctx->rkey_dec[31 - 1 - i] = 0;
		ctx->rkey_dec[31 - 2 - i] = 0;
		ctx->rkey_dec[31 - 3 - i] = 0;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(null_expandkey);

/**
 * null_crypt_block - Encrypt or decrypt a single null block
 * @rk:		The rkey_enc for encrypt or rkey_dec for decrypt
 * @out:	Buffer to store output data
 * @in: 	Buffer containing the input data
 */
void null_crypt_block(const u32 *rk, u8 *out, const u8 *in)
{
	for (i = 0; i < 16; i += 1) {
		out[i]=in[i];
	}


}
EXPORT_SYMBOL_GPL(null_crypt_block);

MODULE_DESCRIPTION("Generic null library");
MODULE_LICENSE("GPL v2");


#include <crypto/algapi.h>
#include <crypto/null.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

/**
 * null_setkey - Set the null key.
 * @tfm:	The %crypto_tfm that is used in the context.
 * @in_key:	The input key.
 * @key_len:	The size of the key.
 *
 * This function uses null_expandkey() to expand the key.
 * &null_ctx _must_ be the private data embedded in @tfm which is
 * retrieved with crypto_tfm_ctx().
 *
 * Return: 0 on success; -EINVAL on failure (only happens for bad key lengths)
 */
static int null_setkey(struct crypto_tfm *tfm, const u8 *in_key,
		       unsigned int key_len)
{
	struct null_ctx *ctx = crypto_tfm_ctx(tfm);

	return null_expandkey(ctx, in_key, key_len);
}

/* encrypt a block of text */

static void null_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct null_ctx *ctx = crypto_tfm_ctx(tfm);

	null_crypt_block(ctx->rkey_enc, out, in);
}

/* decrypt a block of text */

static void null_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct null_ctx *ctx = crypto_tfm_ctx(tfm);

	null_crypt_block(ctx->rkey_dec, out, in);
}

static struct crypto_alg null_alg = {
	.cra_name		=	"null",
	.cra_driver_name	=	"null-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	null_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct null_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	=	null_KEY_SIZE,
			.cia_max_keysize	=	null_KEY_SIZE,
			.cia_setkey		=	null_setkey,
			.cia_encrypt		=	null_encrypt,
			.cia_decrypt		=	null_decrypt
		}
	}
};

static int __init null_init(void)
{
	return crypto_register_alg(&null_alg);
}

static void __exit null_fini(void)
{
	crypto_unregister_alg(&null_alg);
}

subsys_initcall(null_init);
module_exit(null_fini);

MODULE_DESCRIPTION("null Cipher Algorithm");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("null");
MODULE_ALIAS_CRYPTO("null-generic");