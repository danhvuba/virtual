// #ifndef _CRYPTO_KUZNYECHIK_H
// #define _CRYPTO_KUZNYECHIK_H

#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/module.h>
#include "kuztable.h"


#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16
#define KUZNYECHIK_SUBKEYS_SIZE (16 * 10)

struct kuznyechik_ctx
{
	u8 key[KUZNYECHIK_SUBKEYS_SIZE];
	u8 decrypt_key[KUZNYECHIK_SUBKEYS_SIZE];
};


static void S(u8 *a, const u8 *b);

static void Sinv(u8 *a, const u8 *b);

static void Linv(u8 *a, const u8 *b);

static void LSX(u8 *a, const u8 *b, const u8 *c);

static void XLiSi(u8 *a, const u8 *b, const u8 *c);

static void subkey(u8 *out, const u8 *key, unsigned int i);

// /**
//  * kuznyechik_expandkey - Expands the kuznyechik key as described in GB/T 32907-2016
//  * @ctx:	The location where the computed key will be stored.
//  * @in_key:	The supplied key.
//  * @key_len:	The length of the supplied key.
//  *
//  * Returns 0 on success. The function fails only if an invalid key size (or
//  * pointer) is supplied.
//  */
// int kuznyechik_set_key(struct kuznyechik_ctx *ctx, const u8 *in_key,
// 						 unsigned int key_len);

// /**
//  * kuznyechik_crypt_block - Encrypt or decrypt a single kuznyechik block
//  * @rk:		The rkey_enc for encrypt or rkey_dec for crypt
//  * @out:	Buffer to store output data
//  * @in: 	Buffer containing the input data
//  */
// void kuznyechik_encrypt_block(const u32 *rk, u8 *out, const u8 *in);

// /**
//  * kuznyechik_crypt_block - Encrypt or decrypt a single kuznyechik block
//  * @rk:		The rkey_enc for encrypt or rkey_dec for decrypt
//  * @out:	Buffer to store output data
//  * @in: 	Buffer containing the input data
//  */
// void kuznyechik_decrypt_block(const u32 *rk, u8 *out, const u8 *in);

// #endif