#include "kuz.h"

static void S(u8 *a, const u8 *b)
{
	a[0] = pi[b[0]];
	a[1] = pi[b[1]];
	a[2] = pi[b[2]];
	a[3] = pi[b[3]];
	a[4] = pi[b[4]];
	a[5] = pi[b[5]];
	a[6] = pi[b[6]];
	a[7] = pi[b[7]];
	a[8] = pi[b[8]];
	a[9] = pi[b[9]];
	a[10] = pi[b[10]];
	a[11] = pi[b[11]];
	a[12] = pi[b[12]];
	a[13] = pi[b[13]];
	a[14] = pi[b[14]];
	a[15] = pi[b[15]];
}

static void Sinv(u8 *a, const u8 *b)
{
	a[0] = pi_inv[b[0]];
	a[1] = pi_inv[b[1]];
	a[2] = pi_inv[b[2]];
	a[3] = pi_inv[b[3]];
	a[4] = pi_inv[b[4]];
	a[5] = pi_inv[b[5]];
	a[6] = pi_inv[b[6]];
	a[7] = pi_inv[b[7]];
	a[8] = pi_inv[b[8]];
	a[9] = pi_inv[b[9]];
	a[10] = pi_inv[b[10]];
	a[11] = pi_inv[b[11]];
	a[12] = pi_inv[b[12]];
	a[13] = pi_inv[b[13]];
	a[14] = pi_inv[b[14]];
	a[15] = pi_inv[b[15]];
}

static void Linv(u8 *a, const u8 *b)
{
	memcpy(a, &kuz_table_inv[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(a, &kuz_table_inv[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void LSX(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table[0][(b[0] ^ c[0]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[1][(b[1] ^ c[1]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[2][(b[2] ^ c[2]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[3][(b[3] ^ c[3]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[4][(b[4] ^ c[4]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[5][(b[5] ^ c[5]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[6][(b[6] ^ c[6]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[7][(b[7] ^ c[7]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[8][(b[8] ^ c[8]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[9][(b[9] ^ c[9]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[10][(b[10] ^ c[10]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[11][(b[11] ^ c[11]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[12][(b[12] ^ c[12]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[13][(b[13] ^ c[13]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table[14][(b[14] ^ c[14]) * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, &kuz_table[15][(b[15] ^ c[15]) * 16], KUZNYECHIK_BLOCK_SIZE);
}

static void XLiSi(u8 *a, const u8 *b, const u8 *c)
{
	u8 t[16];

	memcpy(t, &kuz_table_inv_LS[0][b[0] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[1][b[1] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[2][b[2] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[3][b[3] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[4][b[4] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[5][b[5] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[6][b[6] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[7][b[7] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[8][b[8] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[9][b[9] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[10][b[10] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[11][b[11] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[12][b[12] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[13][b[13] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[14][b[14] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor(t, &kuz_table_inv_LS[15][b[15] * 16], KUZNYECHIK_BLOCK_SIZE);
	crypto_xor_cpy(a, t, c, 16);
}

static void subkey(u8 *out, const u8 *key, unsigned int i)
{
	u8 test[16];

	LSX(test, key+0, kuz_key_table[i + 0]);
	crypto_xor_cpy(out+16, test, key + 16, 16);
	LSX(test, out+16, kuz_key_table[i + 1]);
	crypto_xor_cpy(out+0, test, key + 0, 16);
	LSX(test, out+0, kuz_key_table[i + 2]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 3]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 4]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 5]);
	crypto_xor(out+0, test, 16);
	LSX(test, out+0, kuz_key_table[i + 6]);
	crypto_xor(out+16, test, 16);
	LSX(test, out+16, kuz_key_table[i + 7]);
	crypto_xor(out+0, test, 16);
}
