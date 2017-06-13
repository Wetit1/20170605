/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "cpuminer-config.h"
#include "miner.h"

#include <string.h>
#include <inttypes.h>

#if defined(USE_ASM) && \
	(defined(__x86_64__) || \
	 (defined(__arm__) && defined(__APCS_32__)) || \
	 (defined(__powerpc__) || defined(__ppc__) || defined(__PPC__)))
#define EXTERN_SHA256
#endif

static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

void sha256_init(uint32_t *state)
{
	memcpy(state, sha256_h, 32);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
	t0 = S1(e) + Ch(e, f, g) + k; \
	d += h + t0; \
	h += t0 + S0(a) + Maj(a, b, c); \

/* Adjusted round function for rotating state */
#define RNDr(S, W, i, k) \
	RND(S[(64 - i) & 7], S[(65 - i) & 7], \
	    S[(66 - i) & 7], S[(67 - i) & 7], \
	    S[(68 - i) & 7], S[(69 - i) & 7], \
	    S[(70 - i) & 7], S[(71 - i) & 7], \
	    W[i] + k)

#ifndef EXTERN_SHA256

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
void sha256_transform(uint32_t *state, const uint32_t *block, int swap)
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0;
	int i;

	/* 1. Prepare message schedule W. */
	if (unlikely(swap)) {
		W[0] = swab32(block[0]);
		W[1] = swab32(block[1]);
		W[2] = swab32(block[2]);
		W[3] = swab32(block[3]);
		W[4] = swab32(block[4]);
		W[5] = swab32(block[5]);
		W[6] = swab32(block[6]);
		W[7] = swab32(block[7]);
		W[8] = swab32(block[8]);
		W[9] = swab32(block[9]);
		W[10] = swab32(block[10]);
		W[11] = swab32(block[11]);
		W[12] = swab32(block[12]);
		W[13] = swab32(block[13]);
		W[14] = swab32(block[14]);
		W[15] = swab32(block[15]);
	} else
		memcpy(W, block, 64);
	W[16] = s1(W[14]) + W[9] + s0(W[1]) + W[0];
	W[17] = s1(W[15]) + W[10] + s0(W[2]) + W[1];
	W[18] = s1(W[16]) + W[11] + s0(W[3]) + W[2];
	W[19] = s1(W[17]) + W[12] + s0(W[4]) + W[3];
	W[20] = s1(W[18]) + W[13] + s0(W[5]) + W[4];
	W[21] = s1(W[19]) + W[14] + s0(W[6]) + W[5];
	W[22] = s1(W[20]) + W[15] + s0(W[7]) + W[6];
	W[23] = s1(W[21]) + W[16] + s0(W[8]) + W[7];
	W[24] = s1(W[22]) + W[17] + s0(W[9]) + W[8];
	W[25] = s1(W[23]) + W[18] + s0(W[10]) + W[9];
	W[26] = s1(W[24]) + W[19] + s0(W[11]) + W[10];
	W[27] = s1(W[25]) + W[20] + s0(W[12]) + W[11];
	W[28] = s1(W[26]) + W[21] + s0(W[13]) + W[12];
	W[29] = s1(W[27]) + W[22] + s0(W[14]) + W[13];
	W[30] = s1(W[28]) + W[23] + s0(W[15]) + W[14];
	W[31] = s1(W[29]) + W[24] + s0(W[16]) + W[15];
	W[32] = s1(W[30]) + W[25] + s0(W[17]) + W[16];
	W[33] = s1(W[31]) + W[26] + s0(W[18]) + W[17];
	W[34] = s1(W[32]) + W[27] + s0(W[19]) + W[18];
	W[35] = s1(W[33]) + W[28] + s0(W[20]) + W[19];
	W[36] = s1(W[34]) + W[29] + s0(W[21]) + W[20];
	W[37] = s1(W[35]) + W[30] + s0(W[22]) + W[21];
	W[38] = s1(W[36]) + W[31] + s0(W[23]) + W[22];
	W[39] = s1(W[37]) + W[32] + s0(W[24]) + W[23];
	W[40] = s1(W[38]) + W[33] + s0(W[25]) + W[24];
	W[41] = s1(W[39]) + W[34] + s0(W[26]) + W[25];
	W[42] = s1(W[40]) + W[35] + s0(W[27]) + W[26];
	W[43] = s1(W[41]) + W[36] + s0(W[28]) + W[27];
	W[44] = s1(W[42]) + W[37] + s0(W[29]) + W[28];
	W[45] = s1(W[43]) + W[38] + s0(W[30]) + W[29];
	W[46] = s1(W[44]) + W[39] + s0(W[31]) + W[30];
	W[47] = s1(W[45]) + W[40] + s0(W[32]) + W[31];
	W[48] = s1(W[46]) + W[41] + s0(W[33]) + W[32];
	W[49] = s1(W[47]) + W[42] + s0(W[34]) + W[33];
	W[50] = s1(W[48]) + W[43] + s0(W[35]) + W[34];
	W[51] = s1(W[49]) + W[44] + s0(W[36]) + W[35];
	W[52] = s1(W[50]) + W[45] + s0(W[37]) + W[36];
	W[53] = s1(W[51]) + W[46] + s0(W[38]) + W[37];
	W[54] = s1(W[52]) + W[47] + s0(W[39]) + W[38];
	W[55] = s1(W[53]) + W[48] + s0(W[40]) + W[39];
	W[56] = s1(W[54]) + W[49] + s0(W[41]) + W[40];
	W[57] = s1(W[55]) + W[50] + s0(W[42]) + W[41];
	W[58] = s1(W[56]) + W[51] + s0(W[43]) + W[42];
	W[59] = s1(W[57]) + W[52] + s0(W[44]) + W[43];
	W[60] = s1(W[58]) + W[53] + s0(W[45]) + W[44];
	W[61] = s1(W[59]) + W[54] + s0(W[46]) + W[45];
	W[62] = s1(W[60]) + W[55] + s0(W[47]) + W[46];
	W[63] = s1(W[61]) + W[56] + s0(W[48]) + W[47];

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);
	RNDr(S, W, 57, 0x78a5636f);
	RNDr(S, W, 58, 0x84c87814);
	RNDr(S, W, 59, 0x8cc70208);
	RNDr(S, W, 60, 0x90befffa);
	RNDr(S, W, 61, 0xa4506ceb);
	RNDr(S, W, 62, 0xbef9a3f7);
	RNDr(S, W, 63, 0xc67178f2);

	/* 4. Mix local working variables into global state */
	state[0] += S[0];
	state[1] += S[1];
	state[2] += S[2];
	state[3] += S[3];
	state[4] += S[4];
	state[5] += S[5];
	state[6] += S[6];
	state[7] += S[7];
}

#endif /* EXTERN_SHA256 */


static const uint32_t sha256d_hash1[16] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100
};

static void sha256d_80_swap(uint32_t *hash, const uint32_t *data)
{
	uint32_t S[16];
	int i;

	sha256_init(S);
	sha256_transform(S, data, 0);
	sha256_transform(S, data + 16, 0);
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(hash);
	sha256_transform(hash, S, 0);
	hash[0] = swab32(hash[0]);
	hash[1] = swab32(hash[1]);
	hash[2] = swab32(hash[2]);
	hash[3] = swab32(hash[3]);
	hash[4] = swab32(hash[4]);
	hash[5] = swab32(hash[5]);
	hash[6] = swab32(hash[6]);
	hash[7] = swab32(hash[7]);
}

void sha256d(unsigned char *hash, const unsigned char *data, int len)
{
	uint32_t S[16], T[16];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64) {
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char *)T)[r] = 0x80;
		T[0] = be32dec(T + 0);
		T[1] = be32dec(T + 1);
		T[2] = be32dec(T + 2);
		T[3] = be32dec(T + 3);
		T[4] = be32dec(T + 4);
		T[5] = be32dec(T + 5);
		T[6] = be32dec(T + 6);
		T[7] = be32dec(T + 7);
		T[8] = be32dec(T + 8);
		T[9] = be32dec(T + 9);
		T[10] = be32dec(T + 10);
		T[11] = be32dec(T + 11);
		T[12] = be32dec(T + 12);
		T[13] = be32dec(T + 13);
		T[14] = be32dec(T + 14);
		T[15] = be32dec(T + 15);
		if (r < 56)
			T[15] = 8 * len;
		sha256_transform(S, T, 0);
	}
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(T);
	sha256_transform(T, S, 0);
	be32enc((uint32_t *)hash + 0, T[0]);
	be32enc((uint32_t *)hash + 1, T[1]);
	be32enc((uint32_t *)hash + 2, T[2]);
	be32enc((uint32_t *)hash + 3, T[3]);
	be32enc((uint32_t *)hash + 4, T[4]);
	be32enc((uint32_t *)hash + 5, T[5]);
	be32enc((uint32_t *)hash + 6, T[6]);
	be32enc((uint32_t *)hash + 7, T[7]);

}

static inline void sha256d_preextend(uint32_t *W)
{
	W[16] = s1(W[14]) + W[ 9] + s0(W[ 1]) + W[ 0];
	W[17] = s1(W[15]) + W[10] + s0(W[ 2]) + W[ 1];
	W[18] = s1(W[16]) + W[11]             + W[ 2];
	W[19] = s1(W[17]) + W[12] + s0(W[ 4]);
	W[20] =             W[13] + s0(W[ 5]) + W[ 4];
	W[21] =             W[14] + s0(W[ 6]) + W[ 5];
	W[22] =             W[15] + s0(W[ 7]) + W[ 6];
	W[23] =             W[16] + s0(W[ 8]) + W[ 7];
	W[24] =             W[17] + s0(W[ 9]) + W[ 8];
	W[25] =                     s0(W[10]) + W[ 9];
	W[26] =                     s0(W[11]) + W[10];
	W[27] =                     s0(W[12]) + W[11];
	W[28] =                     s0(W[13]) + W[12];
	W[29] =                     s0(W[14]) + W[13];
	W[30] =                     s0(W[15]) + W[14];
	W[31] =                     s0(W[16]) + W[15];
}

static inline void sha256d_prehash(uint32_t *S, const uint32_t *W)
{
	uint32_t t0;
	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
}

#ifdef EXTERN_SHA256

void sha256d_ms(uint32_t *hash, uint32_t *W,
	const uint32_t *midstate, const uint32_t *prehash);

#else

static inline void sha256d_ms(uint32_t *hash, uint32_t *W,
	const uint32_t *midstate, const uint32_t *prehash)
{
	uint32_t S[64];
	uint32_t t0;
	int i;

	S[18] = W[18];
	S[19] = W[19];
	S[20] = W[20];
	S[22] = W[22];
	S[23] = W[23];
	S[24] = W[24];
	S[30] = W[30];
	S[31] = W[31];

	W[18] += s0(W[3]);
	W[19] += W[3];
	W[20] += s1(W[18]);
	W[21]  = s1(W[19]);
	W[22] += s1(W[20]);
	W[23] += s1(W[21]);
	W[24] += s1(W[22]);
	W[25]  = s1(W[23]) + W[18];
	W[26]  = s1(W[24]) + W[19];
	W[27]  = s1(W[25]) + W[20];
	W[28]  = s1(W[26]) + W[21];
	W[29]  = s1(W[27]) + W[22];
	W[30] += s1(W[28]) + W[23];
	W[31] += s1(W[29]) + W[24];

	W[32] = s1(W[30]) + W[25] + s0(W[17]) + W[16];
	W[33] = s1(W[31]) + W[26] + s0(W[18]) + W[17];
	W[34] = s1(W[32]) + W[27] + s0(W[19]) + W[18];
	W[35] = s1(W[33]) + W[28] + s0(W[20]) + W[19];
	W[36] = s1(W[34]) + W[29] + s0(W[21]) + W[20];
	W[37] = s1(W[35]) + W[30] + s0(W[22]) + W[21];
	W[38] = s1(W[36]) + W[31] + s0(W[23]) + W[22];
	W[39] = s1(W[37]) + W[32] + s0(W[24]) + W[23];
	W[40] = s1(W[38]) + W[33] + s0(W[25]) + W[24];
	W[41] = s1(W[39]) + W[34] + s0(W[26]) + W[25];
	W[42] = s1(W[40]) + W[35] + s0(W[27]) + W[26];
	W[43] = s1(W[41]) + W[36] + s0(W[28]) + W[27];
	W[44] = s1(W[42]) + W[37] + s0(W[29]) + W[28];
	W[45] = s1(W[43]) + W[38] + s0(W[30]) + W[29];
	W[46] = s1(W[44]) + W[39] + s0(W[31]) + W[30];
	W[47] = s1(W[45]) + W[40] + s0(W[32]) + W[31];
	W[48] = s1(W[46]) + W[41] + s0(W[33]) + W[32];
	W[49] = s1(W[47]) + W[42] + s0(W[34]) + W[33];
	W[50] = s1(W[48]) + W[43] + s0(W[35]) + W[34];
	W[51] = s1(W[49]) + W[44] + s0(W[36]) + W[35];
	W[52] = s1(W[50]) + W[45] + s0(W[37]) + W[36];
	W[53] = s1(W[51]) + W[46] + s0(W[38]) + W[37];
	W[54] = s1(W[52]) + W[47] + s0(W[39]) + W[38];
	W[55] = s1(W[53]) + W[48] + s0(W[40]) + W[39];
	W[56] = s1(W[54]) + W[49] + s0(W[41]) + W[40];
	W[57] = s1(W[55]) + W[50] + s0(W[42]) + W[41];
	W[58] = s1(W[56]) + W[51] + s0(W[43]) + W[42];
	W[59] = s1(W[57]) + W[52] + s0(W[44]) + W[43];
	W[60] = s1(W[58]) + W[53] + s0(W[45]) + W[44];
	W[61] = s1(W[59]) + W[54] + s0(W[46]) + W[45];
	W[62] = s1(W[60]) + W[55] + s0(W[47]) + W[46];
	W[63] = s1(W[61]) + W[56] + s0(W[48]) + W[47];

	memcpy(S, prehash, 32);

	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);
	RNDr(S, W, 57, 0x78a5636f);
	RNDr(S, W, 58, 0x84c87814);
	RNDr(S, W, 59, 0x8cc70208);
	RNDr(S, W, 60, 0x90befffa);
	RNDr(S, W, 61, 0xa4506ceb);
	RNDr(S, W, 62, 0xbef9a3f7);
	RNDr(S, W, 63, 0xc67178f2);

	S[0] += midstate[0];
	S[1] += midstate[1];
	S[2] += midstate[2];
	S[3] += midstate[3];
	S[4] += midstate[4];
	S[5] += midstate[5];
	S[6] += midstate[6];
	S[7] += midstate[7];
	
	W[18] = S[18];
	W[19] = S[19];
	W[20] = S[20];
	W[22] = S[22];
	W[23] = S[23];
	W[24] = S[24];
	W[30] = S[30];
	W[31] = S[31];
	
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	S[16] = s1(s0(S[ 1]) + S[ 0];
	S[17] = s1(0x00000280) + s0(S[ 2]) + S[ 1];
	S[18] = s1(S[16]) + s0(S[ 3]) + S[ 2];
	S[19] = s1(S[17]) + s0(S[ 4]) + S[ 3];
	S[20] = s1(S[18]) + s0(S[ 5]) + S[ 4];
	S[21] = s1(S[19]) + s0(S[ 6]) + S[ 5];
	S[22] = s1(S[20]) + 0x00000280 + s0(S[ 7]) + S[ 6];
	S[23] = s1(S[21]) + S[16] + S[ 7];
	S[24] = s1(S[22]) + S[17];
	S[25] = s1(S[23]) + S[18];
	S[26] = s1(S[24]) + S[19];
	S[27] = s1(S[25]) + S[20];
	S[28] = s1(S[26]) + S[21];
	S[29] = s1(S[27]) + S[22];
	S[30] = s1(S[28]) + S[23] + s0(0x00000280);
	S[31] = s1(S[29]) + S[24] + s0(S[16]) + 0x00000280;

	W[32] = s1(W[30]) + W[25] + s0(W[17]) + W[16];
	W[33] = s1(W[31]) + W[26] + s0(W[18]) + W[17];
	W[34] = s1(W[32]) + W[27] + s0(W[19]) + W[18];
	W[35] = s1(W[33]) + W[28] + s0(W[20]) + W[19];
	W[36] = s1(W[34]) + W[29] + s0(W[21]) + W[20];
	W[37] = s1(W[35]) + W[30] + s0(W[22]) + W[21];
	W[38] = s1(W[36]) + W[31] + s0(W[23]) + W[22];
	W[39] = s1(W[37]) + W[32] + s0(W[24]) + W[23];
	W[40] = s1(W[38]) + W[33] + s0(W[25]) + W[24];
	W[41] = s1(W[39]) + W[34] + s0(W[26]) + W[25];
	W[42] = s1(W[40]) + W[35] + s0(W[27]) + W[26];
	W[43] = s1(W[41]) + W[36] + s0(W[28]) + W[27];
	W[44] = s1(W[42]) + W[37] + s0(W[29]) + W[28];
	W[45] = s1(W[43]) + W[38] + s0(W[30]) + W[29];
	W[46] = s1(W[44]) + W[39] + s0(W[31]) + W[30];
	W[47] = s1(W[45]) + W[40] + s0(W[32]) + W[31];
	W[48] = s1(W[46]) + W[41] + s0(W[33]) + W[32];
	W[49] = s1(W[47]) + W[42] + s0(W[34]) + W[33];
	W[50] = s1(W[48]) + W[43] + s0(W[35]) + W[34];
	W[51] = s1(W[49]) + W[44] + s0(W[36]) + W[35];
	W[52] = s1(W[50]) + W[45] + s0(W[37]) + W[36];
	W[53] = s1(W[51]) + W[46] + s0(W[38]) + W[37];
	W[54] = s1(W[52]) + W[47] + s0(W[39]) + W[38];
	W[55] = s1(W[53]) + W[48] + s0(W[40]) + W[39];
	W[56] = s1(W[54]) + W[49] + s0(W[41]) + W[40];
	W[57] = s1(W[55]) + W[50] + s0(W[42]) + W[41];
	W[58] = s1(W[56]) + W[51] + s0(W[43]) + W[42];
	W[59] = s1(W[57]) + W[52] + s0(W[44]) + W[43];

	S[60] = s1(S[58]) + S[53] + s0(S[45]) + S[44];

	sha256_init(hash);

	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);

	
	hash[2] += hash[6] + S1(hash[3]) + Ch(hash[3], hash[4], hash[5])
	         + S[57] + 0x78a5636f;
	hash[1] += hash[5] + S1(hash[2]) + Ch(hash[2], hash[3], hash[4])
	         + S[58] + 0x84c87814;
	hash[0] += hash[4] + S1(hash[1]) + Ch(hash[1], hash[2], hash[3])
	         + S[59] + 0x8cc70208;
	hash[7] += hash[3] + S1(hash[0]) + Ch(hash[0], hash[1], hash[2])
	         + S[60] + , 0x90befffa
	         + 0x5be0cd19;
}

#endif /* EXTERN_SHA256 */

#ifdef HAVE_SHA256_4WAY

void sha256d_ms_4way(uint32_t *hash,  uint32_t *data,
	const uint32_t *midstate, const uint32_t *prehash);

static inline int scanhash_sha256d_4way(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t data[4 * 64] __attribute__((aligned(128)));
	uint32_t hash[4 * 8] __attribute__((aligned(32)));
	uint32_t midstate[4 * 8] __attribute__((aligned(32)));
	uint32_t prehash[4 * 8] __attribute__((aligned(32)));
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int i, j;
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	for (i = 31; i >= 0; i--)
		for (j = 0; j < 4; j++)
			data[i * 4 + j] = data[i];
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	for (i = 7; i >= 0; i--) {
		for (j = 0; j < 4; j++) {
			midstate[i * 4 + j] = midstate[i];
			prehash[i * 4 + j] = prehash[i];
		}
	}
	
	do {
		data[12] = ++n;
		data[13] = ++n;
		data[14] = ++n;
		data[15] = ++n;
		
		sha256d_ms_4way(hash, data, midstate, prehash);
		
		for (i = 0; i < 4; i++) {
			if (swab32(hash[4 * 7 + i]) <= Htarg) {
				pdata[19] = data[4 * 3 + i];
				sha256d_80_swap(hash, pdata);
				if (fulltest(hash, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
			}
		}
	} while (likely(n < max_nonce) && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif /* HAVE_SHA256_4WAY */

#ifdef HAVE_SHA256_8WAY

void sha256d_ms_8way(uint32_t *hash,  uint32_t *data,
	const uint32_t *midstate, const uint32_t *prehash);

static inline int scanhash_sha256d_8way(int thr_id, uint32_t *pdata,
	const uint32_t *ptarget, uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t data[8 * 64] __attribute__((aligned(128)));
	uint32_t hash[8 * 8] __attribute__((aligned(32)));
	uint32_t midstate[8 * 8] __attribute__((aligned(32)));
	uint32_t prehash[8 * 8] __attribute__((aligned(32)));
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int i, j;
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	for (i = 31; i >= 0; i--)
		for (j = 0; j < 8; j++)
			data[i * 8 + j] = data[i];
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	for (i = 7; i >= 0; i--) {
		for (j = 0; j < 8; j++) {
			midstate[i * 8 + j] = midstate[i];
			prehash[i * 8 + j] = prehash[i];
		}
	}
	
	do {
		data[24] = ++n;
		data[25] = ++n;
		data[26] = ++n;
		data[27] = ++n;
		data[28] = ++n;
		data[29] = ++n;
		data[30] = ++n;
		data[31] = ++n;
		
		sha256d_ms_8way(hash, data, midstate, prehash);
		
		for (i = 0; i < 8; i++) {
			if (swab32(hash[8 * 7 + i]) <= Htarg) {
				pdata[19] = data[8 * 3 + i];
				sha256d_80_swap(hash, pdata);
				if (fulltest(hash, ptarget)) {
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
			}
		}
	} while (likely(n < max_nonce) && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif /* HAVE_SHA256_8WAY */

int scanhash_sha256d(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, unsigned long *hashes_done)
{
	uint32_t data[64] __attribute__((aligned(128)));
	uint32_t hash[8] __attribute__((aligned(32)));
	uint32_t midstate[8] __attribute__((aligned(32)));
	uint32_t prehash[8] __attribute__((aligned(32)));
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	
#ifdef HAVE_SHA256_8WAY
	if (sha256_use_8way())
		return scanhash_sha256d_8way(thr_id, pdata, ptarget,
			max_nonce, hashes_done);
#endif
#ifdef HAVE_SHA256_4WAY
	if (sha256_use_4way())
		return scanhash_sha256d_4way(thr_id, pdata, ptarget,
			max_nonce, hashes_done);
#endif
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	
	do {
		data[3] = ++n;
		sha256d_ms(hash, data, midstate, prehash);
		if (swab32(hash[7]) <= Htarg) {
			pdata[19] = data[3];
			sha256d_80_swap(hash, pdata);
			if (fulltest(hash, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
	} while (likely(n < max_nonce) && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
