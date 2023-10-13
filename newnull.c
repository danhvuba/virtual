// SPDX-License-Identifier: GPL-2.0

/*
 * newnull Cipher Algorithm.
 *
 * Copyright (C) 2018 ARM Limited or its affiliates.
 * All rights reserved.
 */

#include <crypto/algapi.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/byteorder.h>
#include <asm/unaligned.h>

#include <linux/types.h>
#include <linux/crypto.h>

#define newnull_KEY_SIZE 16
#define newnull_BLOCK_SIZE 16
#define newnull_RKEY_WORDS 32

struct newnull_ctx
{
	u32 rkey_enc[newnull_RKEY_WORDS];
	u32 rkey_dec[newnull_RKEY_WORDS];
};

static int newnull_setkey(struct crypto_tfm *tfm, const u8 *in_key,
						  unsigned int key_len)
{
	struct newnull_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;
	for (i = 0; i < 32; i += 4)
	{
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

/* encrypt a block of text */

static void newnull_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct newnull_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;
	for (i = 0; i < 16; i += 1)
	{
		out[i] = in[i];
	}
}

/* decrypt a block of text */

static void newnull_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	const struct newnull_ctx *ctx = crypto_tfm_ctx(tfm);
	int i;
	for (i = 0; i < 16; i += 1)
	{
		out[i] = in[i];
	}
}

static struct crypto_alg newnull_alg = {
	.cra_name = "newnull",
	.cra_driver_name = "newnull-generic",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = newnull_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct newnull_ctx),
	.cra_module = THIS_MODULE,
	.cra_u = {
		.cipher = {
			.cia_min_keysize = newnull_KEY_SIZE,
			.cia_max_keysize = newnull_KEY_SIZE,
			.cia_setkey = newnull_setkey,
			.cia_encrypt = newnull_encrypt,
			.cia_decrypt = newnull_decrypt}}};

static int __init newnull_init(void)
{
	return crypto_register_alg(&newnull_alg);
}

static void __exit newnull_fini(void)
{
	crypto_unregister_alg(&newnull_alg);
}

subsys_initcall(newnull_init);
module_exit(newnull_fini);

MODULE_DESCRIPTION("newnull Cipher Algorithm");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("newnull");
MODULE_ALIAS_CRYPTO("newnull-generic");