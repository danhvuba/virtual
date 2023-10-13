#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>

#define newCipher_KEY_SIZE 16
#define newCipher_BLOCK_SIZE 16

struct newCipher_ctx
{
	u8 key[newCipher_KEY_SIZE];
};

static int newCipher_setkey(struct crypto_tfm *tfm, const u8 *key,
							 unsigned int len)
{
	struct newCipher_ctx *ctx = crypto_tfm_ctx(tfm);
	u32 *flags = &tfm->crt_flags;

	if (len != newCipher_KEY_SIZE)
	{
		*flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
		return -EINVAL;
	}

	memmove(ctx->key, key, newCipher_KEY_SIZE);
	return 0;
}

static void newCipher_crypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	memmove(out, in, newCipher_BLOCK_SIZE);
}


static struct crypto_alg newCipher = {
	.cra_name = "newCipher",
	.cra_driver_name = "newCipher-generic",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = newCipher_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct newCipher_ctx),
	.cra_module = THIS_MODULE,
	.cra_u = {
		.cipher = {
			.cia_min_keysize = newCipher_KEY_SIZE,
			.cia_max_keysize = newCipher_KEY_SIZE,
			.cia_setkey = newCipher_setkey,
			.cia_encrypt = newCipher_crypt,
			.cia_decrypt = newCipher_crypt}}};


static int __init newCipher_init(void)
{
	return crypto_register_alg(&newCipher);
}

static void __exit newCipher_exit(void)
{
	crypto_unregister_alg(&newCipher);
}

module_init(newCipher_init);
module_exit(newCipher_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("No one");
MODULE_DESCRIPTION("newCipher module");
