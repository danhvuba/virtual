#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>

#define fx 0b111000011
#define bit(a, i) ((a >> i) & 1)
#define Shift_left(a, n, fx) (((a ^ (((a >> (n - 1)) & 1) << (n - 1))) << 1) ^ (fx * ((a >> (n - 1)) & 1)))

u8 Mul_fx(u8 ax, u8 bx)
{
    u8 result = 0;
    int i;
    for (i = 0; i < 8; i++)
    {
        if (bit(bx, i))
        {
            result = result ^ ax;
        }
        ax = Shift_left(ax, 8, fx);
    }
    return result;
}

static const u8 pi[256] =
    {
        0xfc,
        0xee,
        0xdd,
        0x11,
        0xcf,
        0x6e,
        0x31,
        0x16,
        0xfb,
        0xc4,
        0xfa,
        0xda,
        0x23,
        0xc5,
        0x04,
        0x4d,
        0xe9,
        0x77,
        0xf0,
        0xdb,
        0x93,
        0x2e,
        0x99,
        0xba,
        0x17,
        0x36,
        0xf1,
        0xbb,
        0x14,
        0xcd,
        0x5f,
        0xc1,
        0xf9,
        0x18,
        0x65,
        0x5a,
        0xe2,
        0x5c,
        0xef,
        0x21,
        0x81,
        0x1c,
        0x3c,
        0x42,
        0x8b,
        0x01,
        0x8e,
        0x4f,
        0x05,
        0x84,
        0x02,
        0xae,
        0xe3,
        0x6a,
        0x8f,
        0xa0,
        0x06,
        0x0b,
        0xed,
        0x98,
        0x7f,
        0xd4,
        0xd3,
        0x1f,
        0xeb,
        0x34,
        0x2c,
        0x51,
        0xea,
        0xc8,
        0x48,
        0xab,
        0xf2,
        0x2a,
        0x68,
        0xa2,
        0xfd,
        0x3a,
        0xce,
        0xcc,
        0xb5,
        0x70,
        0x0e,
        0x56,
        0x08,
        0x0c,
        0x76,
        0x12,
        0xbf,
        0x72,
        0x13,
        0x47,
        0x9c,
        0xb7,
        0x5d,
        0x87,
        0x15,
        0xa1,
        0x96,
        0x29,
        0x10,
        0x7b,
        0x9a,
        0xc7,
        0xf3,
        0x91,
        0x78,
        0x6f,
        0x9d,
        0x9e,
        0xb2,
        0xb1,
        0x32,
        0x75,
        0x19,
        0x3d,
        0xff,
        0x35,
        0x8a,
        0x7e,
        0x6d,
        0x54,
        0xc6,
        0x80,
        0xc3,
        0xbd,
        0x0d,
        0x57,
        0xdf,
        0xf5,
        0x24,
        0xa9,
        0x3e,
        0xa8,
        0x43,
        0xc9,
        0xd7,
        0x79,
        0xd6,
        0xf6,
        0x7c,
        0x22,
        0xb9,
        0x03,
        0xe0,
        0x0f,
        0xec,
        0xde,
        0x7a,
        0x94,
        0xb0,
        0xbc,
        0xdc,
        0xe8,
        0x28,
        0x50,
        0x4e,
        0x33,
        0x0a,
        0x4a,
        0xa7,
        0x97,
        0x60,
        0x73,
        0x1e,
        0x00,
        0x62,
        0x44,
        0x1a,
        0xb8,
        0x38,
        0x82,
        0x64,
        0x9f,
        0x26,
        0x41,
        0xad,
        0x45,
        0x46,
        0x92,
        0x27,
        0x5e,
        0x55,
        0x2f,
        0x8c,
        0xa3,
        0xa5,
        0x7d,
        0x69,
        0xd5,
        0x95,
        0x3b,
        0x07,
        0x58,
        0xb3,
        0x40,
        0x86,
        0xac,
        0x1d,
        0xf7,
        0x30,
        0x37,
        0x6b,
        0xe4,
        0x88,
        0xd9,
        0xe7,
        0x89,
        0xe1,
        0x1b,
        0x83,
        0x49,
        0x4c,
        0x3f,
        0xf8,
        0xfe,
        0x8d,
        0x53,
        0xaa,
        0x90,
        0xca,
        0xd8,
        0x85,
        0x61,
        0x20,
        0x71,
        0x67,
        0xa4,
        0x2d,
        0x2b,
        0x09,
        0x5b,
        0xcb,
        0x9b,
        0x25,
        0xd0,
        0xbe,
        0xe5,
        0x6c,
        0x52,
        0x59,
        0xa6,
        0x74,
        0xd2,
        0xe6,
        0xf4,
        0xb4,
        0xc0,
        0xd1,
        0x66,
        0xaf,
        0xc2,
        0x39,
        0x4b,
        0x63,
        0xb6,
};

static const u8 pi_1[256] =
    {
        0xa5,
        0x2d,
        0x32,
        0x8f,
        0x0e,
        0x30,
        0x38,
        0xc0,
        0x54,
        0xe6,
        0x9e,
        0x39,
        0x55,
        0x7e,
        0x52,
        0x91,
        0x64,
        0x03,
        0x57,
        0x5a,
        0x1c,
        0x60,
        0x07,
        0x18,
        0x21,
        0x72,
        0xa8,
        0xd1,
        0x29,
        0xc6,
        0xa4,
        0x3f,
        0xe0,
        0x27,
        0x8d,
        0x0c,
        0x82,
        0xea,
        0xae,
        0xb4,
        0x9a,
        0x63,
        0x49,
        0xe5,
        0x42,
        0xe4,
        0x15,
        0xb7,
        0xc8,
        0x06,
        0x70,
        0x9d,
        0x41,
        0x75,
        0x19,
        0xc9,
        0xaa,
        0xfc,
        0x4d,
        0xbf,
        0x2a,
        0x73,
        0x84,
        0xd5,
        0xc3,
        0xaf,
        0x2b,
        0x86,
        0xa7,
        0xb1,
        0xb2,
        0x5b,
        0x46,
        0xd3,
        0x9f,
        0xfd,
        0xd4,
        0x0f,
        0x9c,
        0x2f,
        0x9b,
        0x43,
        0xef,
        0xd9,
        0x79,
        0xb6,
        0x53,
        0x7f,
        0xc1,
        0xf0,
        0x23,
        0xe7,
        0x25,
        0x5e,
        0xb5,
        0x1e,
        0xa2,
        0xdf,
        0xa6,
        0xfe,
        0xac,
        0x22,
        0xf9,
        0xe2,
        0x4a,
        0xbc,
        0x35,
        0xca,
        0xee,
        0x78,
        0x05,
        0x6b,
        0x51,
        0xe1,
        0x59,
        0xa3,
        0xf2,
        0x71,
        0x56,
        0x11,
        0x6a,
        0x89,
        0x94,
        0x65,
        0x8c,
        0xbb,
        0x77,
        0x3c,
        0x7b,
        0x28,
        0xab,
        0xd2,
        0x31,
        0xde,
        0xc4,
        0x5f,
        0xcc,
        0xcf,
        0x76,
        0x2c,
        0xb8,
        0xd8,
        0x2e,
        0x36,
        0xdb,
        0x69,
        0xb3,
        0x14,
        0x95,
        0xbe,
        0x62,
        0xa1,
        0x3b,
        0x16,
        0x66,
        0xe9,
        0x5c,
        0x6c,
        0x6d,
        0xad,
        0x37,
        0x61,
        0x4b,
        0xb9,
        0xe3,
        0xba,
        0xf1,
        0xa0,
        0x85,
        0x83,
        0xda,
        0x47,
        0xc5,
        0xb0,
        0x33,
        0xfa,
        0x96,
        0x6f,
        0x6e,
        0xc2,
        0xf6,
        0x50,
        0xff,
        0x5d,
        0xa9,
        0x8e,
        0x17,
        0x1b,
        0x97,
        0x7d,
        0xec,
        0x58,
        0xf7,
        0x1f,
        0xfb,
        0x7c,
        0x09,
        0x0d,
        0x7a,
        0x67,
        0x45,
        0x87,
        0xdc,
        0xe8,
        0x4f,
        0x1d,
        0x4e,
        0x04,
        0xeb,
        0xf8,
        0xf3,
        0x3e,
        0x3d,
        0xbd,
        0x8a,
        0x88,
        0xdd,
        0xcd,
        0x0b,
        0x13,
        0x98,
        0x02,
        0x93,
        0x80,
        0x90,
        0xd0,
        0x24,
        0x34,
        0xcb,
        0xed,
        0xf4,
        0xce,
        0x99,
        0x10,
        0x44,
        0x40,
        0x92,
        0x3a,
        0x01,
        0x26,
        0x12,
        0x1a,
        0x48,
        0x68,
        0xf5,
        0x81,
        0x8b,
        0xc7,
        0xd6,
        0x20,
        0x0a,
        0x08,
        0x00,
        0x4c,
        0xd7,
        0x74,
};

// 128 = 16 u8
#define l(a) (Mul_fx(148, a[15]) ^ Mul_fx(32, a[14]) ^  \
              Mul_fx(133, a[13]) ^ Mul_fx(16, a[12]) ^  \
              Mul_fx(194, a[11]) ^ Mul_fx(192, a[10]) ^ \
              Mul_fx(1, a[9]) ^ Mul_fx(251, a[8]) ^     \
              Mul_fx(1, a[7]) ^ Mul_fx(192, a[6]) ^     \
              Mul_fx(194, a[5]) ^ Mul_fx(16, a[4]) ^    \
              Mul_fx(133, a[3]) ^ Mul_fx(32, a[2]) ^    \
              Mul_fx(148, a[1]) ^ Mul_fx(1, a[0]))

// 128 = 16 u8, result in 'a'
void X(u8 *a, const u8 *k)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        a[i] ^= k[i];
    }
}

// 128 = 16 u8, result in 'a'
void S(u8 *a)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        a[i] = pi[a[i]];
    }
}

// 128 = 16 u8, result in 'a'
void S_1(u8 *a)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        a[i] = pi_1[a[i]];
    }
}

// 128 = 16 u8, result in 'a'
void R(u8 *a)
{
    u8 tmp = l(a);
    int i;
    for (i = 0; i < 15; i++)
    {
        a[i] = a[i + 1];
    }
    a[15] = tmp;
}

// 128 = 16 u8, result in 'a'
void R_1(u8 *a)
{
    u8 tmp = a[15];
    int i;
    for (i = 15; i > 0; i--)
    {
        a[i] = a[i - 1];
    }
    a[0] = tmp;
    a[0] = l(a);
}

// 128-128-128 = (16 u8)*x3, result in 'a1, a0'
void F(u8 *a1, u8 *a0, u8 *k)
{
    // tmp* = a1*
    u8 tmp[16];
    int i;
    for (i = 0; i < 16; i++)
    {
        tmp[i] = a1[i];
    }

    // LSX[k](a1) <=> X - S - L

    X(a1, k);
    S(a1);
    // L = R^16
    for (i = 0; i < 16; i++)
    {
        R(a1);
    }

    // (a1'^a0, a1)
    for (i = 0; i < 16; i++)
    {
        a1[i] ^= a0[i];
        a0[i] = tmp[i];
    }
}

// assign 128=16u8 from *source to *res
void Assign(u8 *source, u8 *res)
{
    int i;
    for (i = 0; i < 16; i++)
    {
        res[i] = source[i];
    }
}

// res = 10*128= array 10*16 u8
// k 256 = 2*128=  32 u8
void Deployment_key(u8 *res, u8 *k)
{
    // C= 32*128= matrix 32*16 u8
    u8 C[32 * 16];
    // C[i]= L( vec_128(i+1))
    int i;
    int j;
    int t;
    for (i = 0; i < 32; i++)
    {
        // C[i]= vec_128(i+1)

        for (j = 0; j < 16; j++)
        {
            C[i * 16 + j] = 0;
        }
        C[i * 16 + 0] = i + 1;

        // L = R^16

        for (t = 0; t < 16; t++)
        {
            R(C + 16 * i);
        }
    }

    memmove(res, k, 32);
    for (i = 1; i <= 4; i++)
    {
        memcpy(res + 16 * 2 * i, res + 16 * (2 * i - 2), 32);
        for (j = 0; j < 8; j++)
        {
            F(res + 16 * 2 * i, res + 16 * (2 * i + 1), C + 16 * (8 * (i - 1) + j));
        }
    }
}

void Encrypt(u8 *a, u8 *K)
{
    int i;
    int t;
    for (i = 0; i < 9; i++)
    {
        // LSX(K[i])  X->S->L
        X(a, K + 16 * i);
        S(a);
        // L = R^16

        for (t = 0; t < 16; t++)
        {
            R(a);
        }
    }
    X(a, K + 16 * 9);
}

void Decrypt(u8 *a, u8 *K)
{
    X(a, K + 16 * 9);
    int i;
    int t;
    for (i = 8; i >= 0; i--)
    {
        // X(K[i])S_1L_1    L_1->S_1->X
        // L_1 = R_1^16

        for (t = 0; t < 16; t++)
        {
            R_1(a);
        }
        S_1(a);
        X(a, K + 16 * i);
    }
}

#define KUZNYECHIK_KEY_SIZE 32
#define KUZNYECHIK_BLOCK_SIZE 16

struct kuznyechik_ctx
{
    u8 key[10 * 16];
};

static int kuznyechik_setkey(struct crypto_tfm *tfm, const u8 *key,
                             unsigned int len)
{
    struct kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
    u32 *flags = &tfm->crt_flags;

    if (len != KUZNYECHIK_KEY_SIZE)
    {
        *flags |= CRYPTO_TFM_RES_BAD_KEY_LEN;
        return -EINVAL;
    }
    Deployment_key(ctx->key, key);
    return 0;
}

static void kuznyechik_encrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
    const struct kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
    memmove(out, in, KUZNYECHIK_BLOCK_SIZE);
    Encrypt(out, ctx->key);
}

static void kuznyechik_decrypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
    const struct kuznyechik_ctx *ctx = crypto_tfm_ctx(tfm);
    memmove(out, in, KUZNYECHIK_BLOCK_SIZE);
    Decrypt(out, ctx->key);
}

static struct crypto_alg kuznyechik = {
    .cra_name = "kuznyechik",
    .cra_driver_name = "kuznyechik-generic",
    .cra_priority = 100,
    .cra_flags = CRYPTO_ALG_TYPE_CIPHER,
    .cra_blocksize = KUZNYECHIK_BLOCK_SIZE,
    .cra_ctxsize = sizeof(struct kuznyechik_ctx),
    .cra_module = THIS_MODULE,
    .cra_u = {
        .cipher = {
            .cia_min_keysize = KUZNYECHIK_KEY_SIZE,
            .cia_max_keysize = KUZNYECHIK_KEY_SIZE,
            .cia_setkey = kuznyechik_setkey,
            .cia_encrypt = kuznyechik_encrypt,
            .cia_decrypt = kuznyechik_decrypt}}};

static int __init kuznyechik_init(void)
{
    return crypto_register_alg(&kuznyechik);
}

static void __exit kuznyechik_exit(void)
{
    crypto_unregister_alg(&kuznyechik);
}

module_init(kuznyechik_init);
module_exit(kuznyechik_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("No one");
MODULE_DESCRIPTION("kuznyechik module");
