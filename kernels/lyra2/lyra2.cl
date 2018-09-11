/*
* Lyra2 kernel implementation.
*
* ==========================(LICENSE BEGIN)============================
* Copyright (c) 2014 djm34
* 
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* ===========================(LICENSE END)=============================
*
* @author   djm34
*/

#if __ENDIAN_LITTLE__
#define SPH_LITTLE_ENDIAN 1
#else
#define SPH_BIG_ENDIAN 1
#endif

#define SPH_UPTR sph_u64

typedef unsigned int sph_u32;
typedef int sph_s32;
#ifndef __OPENCL_VERSION__
typedef unsigned long long sph_u64;
typedef long long sph_s64;
#else
typedef unsigned long sph_u64;
typedef long sph_s64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x)    ((sph_u32)(x ## U))
#define SPH_T32(x)    ((x) & SPH_C32(0xFFFFFFFF))

#define SPH_C64(x)    ((sph_u64)(x ## UL))
#define SPH_T64(x)    ((x) & SPH_C64(0xFFFFFFFFFFFFFFFF))

#define SPH_ROTL32(x,n) rotate(x,(uint)n)     //faster with driver 14.6
#define SPH_ROTR32(x,n) rotate(x,(uint)(32-n))
#define SPH_ROTL64(x,n) rotate(x,(ulong)n)

static inline sph_u64 ror64(sph_u64 vw, unsigned a) {
	uint2 result;
	uint2 v = as_uint2(vw);
	unsigned n = (unsigned)(64 - a);
	if (n == 32) { return as_ulong((uint2)(v.y, v.x)); }
	if (n < 32) {
		result.y = ((v.y << (n)) | (v.x >> (32 - n)));
		result.x = ((v.x << (n)) | (v.y >> (32 - n)));
	}	else {
		result.y = ((v.x << (n - 32)) | (v.y >> (64 - n)));
		result.x = ((v.y << (n - 32)) | (v.x >> (64 - n)));
	}
	return as_ulong(result);
}

#define SPH_ROTR64(l,n) ror64(l, n)

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)

#if SPH_BIG_ENDIAN
  #define DEC64E(x) (x)
  #define DEC64BE(x) (*(const __global sph_u64 *) (x));
  #define DEC64LE(x) SWAP8(*(const __global sph_u64 *) (x));
  #define DEC32LE(x) (*(const __global sph_u32 *) (x));
#else
  #define DEC64E(x) SWAP8(x)
  #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
  #define DEC64LE(x) (*(const __global sph_u64 *) (x));
  #define DEC32LE(x) SWAP4(*(const __global sph_u32 *) (x));
#endif

/*Blake2b IV Array*/
__constant static const sph_u64 blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*Blake2b's rotation*/

static inline uint2 ror2(uint2 v, unsigned a) {
	uint2 result;
	unsigned n = 64 - a;
	if (n == 32) { return (uint2)(v.y,v.x); }
	if (n < 32) {
		result.y = ((v.y << (n)) | (v.x >> (32 - n)));
		result.x = ((v.x << (n)) | (v.y >> (32 - n)));
	}
	else {
		result.y = ((v.x << (n - 32)) | (v.y >> (64 - n)));
		result.x = ((v.y << (n - 32)) | (v.x >> (64 - n)));
	}
	return result;
}
static inline uint2 ror2l(uint2 v, unsigned a) {
	uint2 result;
		result.y = ((v.x << (32-a)) | (v.y >> (a)));
		result.x = ((v.y << (32-a)) | (v.x >> (a)));
	return result;
}
static inline uint2 ror2r(uint2 v, unsigned a) {
	uint2 result;
		result.y = ((v.y << (64-a)) | (v.x >> (a-32)));
		result.x = ((v.x << (64-a)) | (v.y >> (a-32)));
	return result;
}
/*
#define G(a,b,c,d) \
  do { \
a = as_uint2(as_ulong(a)+as_ulong(b)); d ^= a; d = d.yx; \
c = as_uint2(as_ulong(c)+as_ulong(d)); b ^= c; b = ror2l(b, 24); \
a = as_uint2(as_ulong(a)+as_ulong(b)); d ^= a; d = ror2l(d, 16); \
c = as_uint2(as_ulong(c)+as_ulong(d)); b ^= c; b = ror2r(b, 63); \
  } while(0)
*/
#define G(a,b,c,d) \
  do { \
a = as_uint2(as_ulong(a)+as_ulong(b)); d ^= a; d = d.yx; \
c = as_uint2(as_ulong(c)+as_ulong(d)); b ^= c; b = as_uint2(as_uchar8(b).s34567012); \
a = as_uint2(as_ulong(a)+as_ulong(b)); d ^= a; d = ror2l(d, 16); \
c = as_uint2(as_ulong(c)+as_ulong(d)); b ^= c; b = ror2r(b, 63); \
  } while(0)

/*One Round of the Blake2b's compression function*/
#define round_lyra(v)  \
 do { \
    G(v[ 0],v[ 4],v[ 8],v[12]); \
    G(v[ 1],v[ 5],v[ 9],v[13]); \
    G(v[ 2],v[ 6],v[10],v[14]); \
    G(v[ 3],v[ 7],v[11],v[15]); \
    G(v[ 0],v[ 5],v[10],v[15]); \
    G(v[ 1],v[ 6],v[11],v[12]); \
    G(v[ 2],v[ 7],v[ 8],v[13]); \
    G(v[ 3],v[ 4],v[ 9],v[14]); \
 } while(0)


#define reduceDuplexRowSetup(rowIn, rowInOut, rowOut) \
   { \
	for (int i = 0; i < 8; i++) \
				{ \
\
		for (int j = 0; j < 12; j++) {state[j] ^= as_uint2(as_ulong(Matrix[12 * i + j][rowIn]) + as_ulong(Matrix[12 * i + j][rowInOut]));} \
		round_lyra(state); \
		for (int j = 0; j < 12; j++) {Matrix[j + 84 - 12 * i][rowOut] = Matrix[12 * i + j][rowIn] ^ state[j];} \
\
		Matrix[0 + 12 * i][rowInOut] ^= state[11]; \
		Matrix[1 + 12 * i][rowInOut] ^= state[0]; \
		Matrix[2 + 12 * i][rowInOut] ^= state[1]; \
		Matrix[3 + 12 * i][rowInOut] ^= state[2]; \
		Matrix[4 + 12 * i][rowInOut] ^= state[3]; \
		Matrix[5 + 12 * i][rowInOut] ^= state[4]; \
		Matrix[6 + 12 * i][rowInOut] ^= state[5]; \
		Matrix[7 + 12 * i][rowInOut] ^= state[6]; \
		Matrix[8 + 12 * i][rowInOut] ^= state[7]; \
		Matrix[9 + 12 * i][rowInOut] ^= state[8]; \
		Matrix[10 + 12 * i][rowInOut] ^= state[9]; \
		Matrix[11 + 12 * i][rowInOut] ^= state[10]; \
				} \
 \
   } 

#define reduceDuplexRow(rowIn, rowInOut, rowOut) \
  { \
	 for (int i = 0; i < 8; i++) \
	 	 	 	 	 { \
		 for (int j = 0; j < 12; j++) \
			 state[j] ^= as_uint2(as_ulong(Matrix[12 * i + j][rowIn]) + as_ulong(Matrix[12 * i + j][rowInOut])); \
 \
		 round_lyra(state); \
		 for (int j = 0; j < 12; j++) {Matrix[j + 12 * i][rowOut] ^= state[j];} \
\
		 Matrix[0 + 12 * i][rowInOut] ^= state[11]; \
		 Matrix[1 + 12 * i][rowInOut] ^= state[0]; \
		 Matrix[2 + 12 * i][rowInOut] ^= state[1]; \
		 Matrix[3 + 12 * i][rowInOut] ^= state[2]; \
		 Matrix[4 + 12 * i][rowInOut] ^= state[3]; \
		 Matrix[5 + 12 * i][rowInOut] ^= state[4]; \
		 Matrix[6 + 12 * i][rowInOut] ^= state[5]; \
		 Matrix[7 + 12 * i][rowInOut] ^= state[6]; \
		 Matrix[8 + 12 * i][rowInOut] ^= state[7]; \
		 Matrix[9 + 12 * i][rowInOut] ^= state[8]; \
		 Matrix[10 + 12 * i][rowInOut] ^= state[9]; \
		 Matrix[11 + 12 * i][rowInOut] ^= state[10]; \
	 	 	 	 	 } \
 \
  } 
#define absorbblock(in)  { \
	state[0] ^= Matrix[0][in]; \
	state[1] ^= Matrix[1][in]; \
	state[2] ^= Matrix[2][in]; \
	state[3] ^= Matrix[3][in]; \
	state[4] ^= Matrix[4][in]; \
	state[5] ^= Matrix[5][in]; \
	state[6] ^= Matrix[6][in]; \
	state[7] ^= Matrix[7][in]; \
	state[8] ^= Matrix[8][in]; \
	state[9] ^= Matrix[9][in]; \
	state[10] ^= Matrix[10][in]; \
	state[11] ^= Matrix[11][in]; \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
	round_lyra(state); \
  } 

/// lyra2 algo 

typedef union {
    uint h[8];
    ulong h2[4];
    uint4 h4[2];
    ulong4 h8;
} hash_t;

__attribute__((reqd_work_group_size(256, 1, 1)))
__kernel void lyra2(__global uint* hashes)
{
  uint gid = get_global_id(0);
  __global hash_t *hash = (__global hash_t *)(hashes + (8* (get_global_id(0))));

  uint2 state[16];

  for (int i = 0; i < 4; i++) { state[i] = as_uint2(hash->h2[i]);} //password
  for (int i = 0; i < 4; i++) { state[i + 4] = state[i]; } //salt 
  for (int i = 0; i < 8; i++) { state[i + 8] = as_uint2(blake2b_IV[i]); }

  //     blake2blyra x2 

  for (int i = 0; i < 24; i++) {round_lyra(state);} //because 12 is not enough

  __private uint2 Matrix[96][8]; // very uncool
  /// reducedSqueezeRow0

  for (int i = 0; i < 8; i++)
  {
	  for (int j = 0; j<12; j++) {Matrix[j + 84 - 12 * i][0] = state[j];}
	  round_lyra(state);
  }

  /// reducedSqueezeRow1

  for (int i = 0; i < 8; i++)
  {
	  for (int j = 0; j < 12; j++) {state[j] ^= Matrix[j + 12 * i][0];}
	  round_lyra(state);
	  for (int j = 0; j < 12; j++) {Matrix[j + 84 - 12 * i][1] = Matrix[j + 12 * i][0] ^ state[j];}
  }
 
  reduceDuplexRowSetup(1, 0, 2);
  reduceDuplexRowSetup(2, 1, 3);
  reduceDuplexRowSetup(3, 0, 4);
  reduceDuplexRowSetup(4, 3, 5);
  reduceDuplexRowSetup(5, 2, 6);
  reduceDuplexRowSetup(6, 1, 7);

  sph_u32 rowa;
  rowa = state[0].x & 7;

  reduceDuplexRow(7, rowa, 0);
  rowa = state[0].x & 7;
  reduceDuplexRow(0, rowa, 3);
  rowa = state[0].x & 7;
  reduceDuplexRow(3, rowa, 6);
  rowa = state[0].x & 7;
  reduceDuplexRow(6, rowa, 1);
  rowa = state[0].x & 7;
  reduceDuplexRow(1, rowa, 4);
  rowa = state[0].x & 7;
  reduceDuplexRow(4, rowa, 7);
  rowa = state[0].x & 7;
  reduceDuplexRow(7, rowa, 2);
  rowa = state[0].x & 7;
  reduceDuplexRow(2, rowa, 5);

  absorbblock(rowa);

  for (int i = 0; i < 4; i++) {hash->h2[i] = as_ulong(state[i]);}
barrier(CLK_LOCAL_MEM_FENCE);

}