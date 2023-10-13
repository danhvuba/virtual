#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>


#include <asm/unaligned.h>
#include <crypto/algapi.h>
#include"kuz.h"


static int kuznyechik_set_key(struct crypto_tfm *tfm, const u8 *in_key,
		unsigned int key_len)
{
	struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned int i;

	if (key_len != KUZNYECHIK_KEY_SIZE)
		return -EINVAL;

	memcpy(ctx->key, in_key, 32);
	subkey(ctx->key + 32, ctx->key, 0);
	subkey(ctx->key + 64, ctx->key + 32, 8);
	subkey(ctx->key + 96, ctx->key + 64, 16);
	subkey(ctx->key + 128, ctx->key + 96, 24);
	for (i = 0; i < 10; i++)
		Linv(ctx->dekey + 16 * i, ctx->key + 16 * i);

	return 0;
}

static void kuznyechik_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	LSX(temp, ctx->key + 16 * 0, in);
	LSX(temp, ctx->key + 16 * 1, temp);
	LSX(temp, ctx->key + 16 * 2, temp);
	LSX(temp, ctx->key + 16 * 3, temp);
	LSX(temp, ctx->key + 16 * 4, temp);
	LSX(temp, ctx->key + 16 * 5, temp);
	LSX(temp, ctx->key + 16 * 6, temp);
	LSX(temp, ctx->key + 16 * 7, temp);
	LSX(temp, ctx->key + 16 * 8, temp);
	crypto_xor_cpy(out, ctx->key + 16 * 9, temp, 16);
}

static void kuznyechik_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct crypto_kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
	u8 temp[KUZNYECHIK_BLOCK_SIZE];

	S(temp, in);
	XLiSi(temp, temp, ctx->dekey + 16 * 9);
	XLiSi(temp, temp, ctx->dekey + 16 * 8);
	XLiSi(temp, temp, ctx->dekey + 16 * 7);
	XLiSi(temp, temp, ctx->dekey + 16 * 6);
	XLiSi(temp, temp, ctx->dekey + 16 * 5);
	XLiSi(temp, temp, ctx->dekey + 16 * 4);
	XLiSi(temp, temp, ctx->dekey + 16 * 3);
	XLiSi(temp, temp, ctx->dekey + 16 * 2);
	XLiSi(temp, temp, ctx->dekey + 16 * 1);
	Sinv(out, temp);
	crypto_xor(out, ctx->key + 16 * 0, 16);
}

static struct crypto_alg kuznyechik_alg = {
	.cra_name		=	"kuznyechik",
	.cra_driver_name	=	"kuznyechik-generic",
	.cra_priority		=	100,
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	KUZNYECHIK_BLOCK_SIZE,
	.cra_ctxsize		=	sizeof(struct crypto_kuznyechik_ctx),
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{
		.cipher = {
			.cia_min_keysize	= KUZNYECHIK_KEY_SIZE,
			.cia_max_keysize	= KUZNYECHIK_KEY_SIZE,
			.cia_setkey		= kuznyechik_set_key,
			.cia_encrypt		= kuznyechik_encrypt,
			.cia_decrypt		= kuznyechik_decrypt
		}
	}
};

static int __init kuznyechik_init(void)
{
	return crypto_register_alg(&kuznyechik_alg);
}

static void __exit kuznyechik_fini(void)
{
	crypto_unregister_alg(&kuznyechik_alg);
}

module_init(kuznyechik_init);
module_exit(kuznyechik_fini);

MODULE_DESCRIPTION("GOST R 34.12-2015 (Kuznyechik) algorithm");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("kuznyechik");
MODULE_ALIAS_CRYPTO("kuznyechik-generic");

