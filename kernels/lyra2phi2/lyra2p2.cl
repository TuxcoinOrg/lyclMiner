/*
 * Lyra2RE kernel implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 * Copyright (c) 2014 djm34
 * Copyright (c) 2014 James Lovejoy
 * Copyright (c) 2017 MaxDZ8
 * Copyright (c) 2018 fancyIX
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
 * @author   fancyIX 2018
 */
/*
 * This file is mostly the same as lyra2rev2.cl: differences:
 * - Cubehash implementation is now shared across search2 and search5
 * - Cubehash is reformulated, this reduces ISA size to almost 1/3
 *   leaving rooms for other algorithms.
 * - Lyra is reformulated in 4 stages: arithmetically intensive
 *   head and tail, one coherent matrix expansion, one incoherent mess.
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
#else
  typedef unsigned long sph_u64;
#endif

#define SPH_64 1
#define SPH_64_TRUE 1

#define SPH_C32(x) ((sph_u32)(x ## U))
#define SPH_T32(x) (as_uint(x))
#define SPH_ROTL32(x, n) rotate(as_uint(x), as_uint(n))
#define SPH_ROTR32(x, n) SPH_ROTL32(x, (32 - (n)))

#define SPH_C64(x) ((sph_u64)(x ## UL))
#define SPH_T64(x) (as_ulong(x))
#define SPH_ROTL64(x, n) rotate(as_ulong(x), (n) & 0xFFFFFFFFFFFFFFFFUL)
#define SPH_ROTR64(x, n) SPH_ROTL64(x, (64 - (n)))

#define SPH_ECHO_64 1
#define SPH_JH_64 1

#define SWAP4(x) as_uint(as_uchar4(x).wzyx)
#define SWAP8(x) as_ulong(as_uchar8(x).s76543210)
#define SWAP32(x) as_ulong(as_uint2(x).s10)

#if SPH_BIG_ENDIAN
  #define DEC64BE(x) (*(const __global sph_u64 *) (x));
  #define DEC64LE(x) SWAP8(*(const __global sph_u64 *) (x));
#else
  #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
  #define DEC64LE(x) (*(const __global sph_u64 *) (x));
#endif

#define SHL(x, n) ((x) << (n))
#define SHR(x, n) ((x) >> (n))

#define SWAP8_INPUT(x)   x
#define SWAP8_USELESS(x) x


#if SPH_BIG_ENDIAN
  #define DEC64E(x) (x)
  #define DEC64BE(x) (*(const __global sph_u64 *) (x));
  #define DEC32LE(x) SWAP4(*(const __global sph_u32 *) (x));
#else
  #define DEC64E(x) SWAP8(x)
  #define DEC64BE(x) SWAP8(*(const __global sph_u64 *) (x));
  #define DEC32LE(x) (*(const __global sph_u32 *) (x));
#endif

#define rotr64(x, n) ((n) < 32 ? (amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n)) | ((ulong)amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n)) << 32)) : (amd_bitalign((uint)(x), (uint)((x) >> 32), (uint)(n) - 32) | ((ulong)amd_bitalign((uint)((x) >> 32), (uint)(x), (uint)(n) - 32) << 32)))

#define Gfunc(a,b,c,d) \
{ \
    a += b;  \
    d ^= a; \
    ttr = rotr64(d, 32); \
    d = ttr; \
 \
    c += d;  \
    b ^= c; \
    ttr = rotr64(b, 24); \
    b = ttr; \
 \
    a += b;  \
    d ^= a; \
    ttr = rotr64(d, 16); \
    d = ttr; \
 \
    c += d; \
    b ^= c; \
    ttr = rotr64(b, 63); \
    b = ttr; \
}

#define roundLyra(state) \
{ \
     Gfunc(state[0].x, state[2].x, state[4].x, state[6].x); \
     Gfunc(state[0].y, state[2].y, state[4].y, state[6].y); \
     Gfunc(state[1].x, state[3].x, state[5].x, state[7].x); \
     Gfunc(state[1].y, state[3].y, state[5].y, state[7].y); \
 \
     Gfunc(state[0].x, state[2].y, state[5].x, state[7].y); \
     Gfunc(state[0].y, state[3].x, state[5].y, state[6].x); \
     Gfunc(state[1].x, state[3].y, state[4].x, state[6].y); \
     Gfunc(state[1].y, state[2].x, state[4].y, state[7].x); \
}


#pragma OPENCL EXTENSION cl_amd_media_ops : enable
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable

ulong ROTR64(const ulong x2, const uint y)
{
	uint2 x = as_uint2(x2);
	if(y < 32) return(as_ulong(amd_bitalign(x.s10, x, y)));
	else return(as_ulong(amd_bitalign(x, x.s10, (y - 32))));
}


/// lyra2 algo  ///////////////////////////////////////////////////////////
#define HASH_SIZE (256 / 8) // size in bytes of an hash in/out
#define SLOT (get_global_id(1) - get_global_offset(1))
#define LOCAL_LINEAR (get_local_id(1) * get_local_size(0) + get_local_id(0))
#define REG_ROW_COUNT (4 * get_local_size(1)) // ideally all happen at the same clock
#define STATE_BLOCK_COUNT (3 * REG_ROW_COUNT)  // very close instructions
#define LYRA_ROUNDS 8
#define HYPERMATRIX_COUNT (LYRA_ROUNDS * STATE_BLOCK_COUNT)

// Usually just #define G(a,b,c,d)...; I have no time to read the Lyra paper
// but that looks like some kind of block cipher I guess.
void cipher_G(ulong *s) {
	s[0] += s[1]; s[3] ^= s[0]; s[3] = SWAP32(s[3]);
	s[2] += s[3]; s[1] ^= s[2]; s[1] = ROTR64(s[1], 24);
	s[0] += s[1]; s[3] ^= s[0]; s[3] = ROTR64(s[3], 16);
	s[2] += s[3]; s[1] ^= s[2]; s[1] = ROTR64(s[1], 63);
}

// pad counts 4 entries each hash team of 4
void round_lyra_4way(ulong *state, __local ulong *pad) {
	// The first half of the round is super nice to us 4-way kernels because we mangle
	// our own column so it's just as in the legacy kernel, except we are parallel.
	cipher_G(state);
	// Now we mangle diagonals ~ shift rows
	// That's a problem for us in CL because we don't have SIMD lane shuffle yet (AMD you dumb fuck)
	// Not a problem for private miners: there's an op for that.
	// But maybe only for GCN>3? IDK.
	// Anyway, each element of my state besides 0 should go somewhere!
	for(int shuffle = 1; shuffle < 4; shuffle++) {
		pad[get_local_id(0)] = state[shuffle];
		barrier(CLK_LOCAL_MEM_FENCE); // nop, we're lockstep
		state[shuffle] = pad[(get_local_id(0) + shuffle) % 4]; // maybe also precompute those offsets
	}	
	cipher_G(state);
	// And we also have to put everything back in place :-(
	for(int shuffle = 1; shuffle < 4; shuffle++) {
		pad[get_local_id(0)] = state[shuffle];
		barrier(CLK_LOCAL_MEM_FENCE); // nop, we're lockstep
		int offset = shuffle % 2? 2 : 0;
		offset += shuffle;
		state[shuffle] = pad[(get_local_id(0) + offset) % 4]; // maybe also precompute those offsets
	}
}


/** Legacy kernel: "reduce duplex f". What it really does:
init hypermatrix[1] from [0], starting at bigMat, already offset per hash
inverting cols. We init hyper index 1 and we have only 1 to mangle. */
void make_hyper_one(ulong *state, __local ulong *xchange, __local ulong *bigMat) {
	ulong si[3];
	uint src = 0;
	uint dst = HYPERMATRIX_COUNT * 2 - STATE_BLOCK_COUNT;
	for (int loop = 0; loop < LYRA_ROUNDS; loop++)
	{
		for (int row = 0; row < 3; row++) {
			si[row] = bigMat[src];
			state[row] ^= si[row];
			src += REG_ROW_COUNT; // read sequentially huge chunks of memory!
		}
		round_lyra_4way(state, xchange);
		for (int row = 0; row < 3; row++) {
			si[row] ^= state[row];
			bigMat[dst + row * REG_ROW_COUNT] = si[row]; // zigzag. Less nice.
		} // legacy kernel interleave xyzw for each row of matrix so
		// going ahead or back is no difference for them but it is for us
		// (me and my chip) because we keep the columns packed.
		dst -= STATE_BLOCK_COUNT;
	}
}

/** Consider your s'' as a sequence of ulongs instead of a matrix. Rotate it back
and xor with true state. */
void xorrot_one(ulong *modify, __local ulong *groupPad, ulong *src) {
	
	ushort dst = LOCAL_LINEAR; // my slot
	short off = get_local_id(0) < 3? 1 : (20 - 3);
	groupPad[dst + off] = src[0];
	dst += 20;
	groupPad[dst + off] = src[1];
	dst += 20;
	off = get_local_id(0) < 3? 1 : (-40 - 3);
	groupPad[dst + off] = src[2];
	for(uint cp = 0; cp < 3; cp++) modify[cp] ^= groupPad[LOCAL_LINEAR + cp * 20];
}


/** Legacy kernel: reduce duplex row (from) setup.
I rather think of their rows as my hyper matrix.
There are two we can use now. The first we read.
The last we modify (and we created it only a few ticks before!
So maybe LDS here as well? To be benchmarked). */
void make_next_hyper(uint matin, uint matrw, uint matout,
                     ulong *state, __local ulong *groupPad, __local ulong *bigMat) {
	ulong si[3], sII[3];
	uint hyc = HYPERMATRIX_COUNT * matin; // hyper constant
	uint hymod = HYPERMATRIX_COUNT * matrw; // hyper modify
	uint hydst = HYPERMATRIX_COUNT * matout + HYPERMATRIX_COUNT - STATE_BLOCK_COUNT;
	for (int i = 0; i < LYRA_ROUNDS; i++)
	{
		for (int row = 0; row < 3; row++)  {
			si[row] = bigMat[hyc + row * REG_ROW_COUNT];
			sII[row] = bigMat[hymod + row * REG_ROW_COUNT];
			state[row] ^= si[row] + sII[row];
		}
		round_lyra_4way(state, groupPad + get_local_id(1) * 4);
		for (int row = 0; row < 3; row++) {
			si[row] ^= state[row];
			bigMat[hydst + row * REG_ROW_COUNT] = si[row];
		}
		// A nice surprise there! Before continuing, xor your mini-matrix'' by state.
		// But there's a quirk! Your s''[i] is to be xorred with s[i-1].
		// Or with s[i+11] in modulo arithmetic.
		// Private miners again shuffle those with the ISA instruction which provides
		// far more performance (1 op instead of 4, and shuffle masks are constants
		// whereas LDS isn't). So, we send forward 1 our state, rows interleaved.
		xorrot_one(sII, groupPad, state);
		for(uint cp = 0; cp < 3; cp++) bigMat[hymod + cp * REG_ROW_COUNT] = sII[cp];
		hyc += STATE_BLOCK_COUNT;
		hymod += STATE_BLOCK_COUNT;
		hydst -= STATE_BLOCK_COUNT;
	}
}


/** Legacy: reduce duplex row function? IDK.
What it does: XOR huge chunks of memory (now fully parallel and packed)!
The difference wrt building hyper matrices is
- We don't invert rows anymore so we start and walk similarly for all matrix.
- When the two matrices being modified are the same we just assign. */
void hyper_xor(uint matin, uint matrw, uint matout,
               ulong *state, __local ulong *groupPad, __local ulong *bigMat) {
	ulong si[3], sII[3];
	uint3 hyoff = (uint3)(matin* HYPERMATRIX_COUNT, matrw* HYPERMATRIX_COUNT, matout* HYPERMATRIX_COUNT);
	uint hyc = HYPERMATRIX_COUNT * matin;
	uint hymod = HYPERMATRIX_COUNT * matrw;
	uint hydst = HYPERMATRIX_COUNT * matout;
	for (int i = 0; i < LYRA_ROUNDS; i++)
	{
		for (int row = 0; row < 3; row++)  {
			si[row] = bigMat[hyc + row * REG_ROW_COUNT];
			sII[row] = bigMat[hymod + row * REG_ROW_COUNT];
		}
		for (int row = 0; row < 3; row++)  {
			si[row] += sII[row];
			state[row] ^= si[row];
		}
		round_lyra_4way(state, groupPad + get_local_id(1) * 4);
		xorrot_one(sII, groupPad, state);
		// Oh noes! An 'if' inside a loop!
		// That's particularly bad: it's a 'dynamic' (or 'varying') branch
		// which means it's potentially divergent and it's basically random.
		// Every hash goes this or that way and if we could have 4-element
		// SIMD lanes we would have little problem but we have this.
		// Don't worry; we're going at memory speed anyway.
		// BTW this has both different sources and different destinations so
		// no other way to do it but just diverge.
		if (matrw != matout) {
			for (int row = 0; row < 3; row++) {
				bigMat[hymod + row * REG_ROW_COUNT] = sII[row];
				bigMat[hydst + row * REG_ROW_COUNT] ^= state[row];
			}
		}
		else {
			for (int row = 0; row < 3; row++) {
				sII[row] ^= state[row];
			    bigMat[hymod + row * REG_ROW_COUNT] = sII[row];
			}
		}
		hyc += STATE_BLOCK_COUNT;
		hymod += STATE_BLOCK_COUNT;
		hydst += STATE_BLOCK_COUNT;
	}
}



static constant ulong initial_lyra2[2][4] = {
	{ 0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL },
	{ 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL }
};

static constant ulong mid_mix[2][4] = {
	{ 0x20,0x20,0x20,0x01 },
	{ 0x04,0x04,0x80,0x0100000000000000 }
};

typedef union {
    uint h4[32];
    ulong h8[16];
    uint4 h16[8];
    ulong2 hl16[8];
    ulong4 h32[4];
} lyraState_t;

__attribute__((reqd_work_group_size(64, 1, 1)))
__kernel void lyra441p2(__global uint* lyraStates)
{
  uint gid = get_global_id(1);
  __global lyraState_t *lyraState = (__global lyraState_t *)(lyraStates + (32 * (gid-get_global_offset(1))));

  __local ulong roundPad[12 * 5];
  __local ulong *xchange = roundPad + get_local_id(1) * 4;

  //__global ulong *notepad = buffer + get_local_id(0) + 4 * SLOT;
  __local ulong notepadLDS[192 * 4 * 5];
  __local ulong *notepad = notepadLDS + LOCAL_LINEAR;
  const uint player = (uint)get_local_id(0);

  ulong state[4];

	//-------------------------------------
	// Load Lyra state
	state[0] = (ulong)(lyraState->h8[player]);
	state[1] = (ulong)(lyraState->h8[player+4]);
	state[2] = (ulong)(lyraState->h8[player+8]);
	state[3] = (ulong)(lyraState->h8[player+12]);
  
  __local ulong *dst = notepad + HYPERMATRIX_COUNT;
  for (int loop = 0; loop < LYRA_ROUNDS; loop++) { // write columns and rows 'in order'
    dst -= STATE_BLOCK_COUNT; // but blocks backwards
    for(int cp = 0; cp < 3; cp++) dst[cp * REG_ROW_COUNT] = state[cp];
    round_lyra_4way(state, xchange);
  }
  make_hyper_one(state, xchange, notepad);
  make_next_hyper(1, 0, 2, state, roundPad, notepad);
  make_next_hyper(2, 1, 3, state, roundPad, notepad);
  make_next_hyper(3, 0, 4, state, roundPad, notepad);
  make_next_hyper(4, 3, 5, state, roundPad, notepad);
  make_next_hyper(5, 2, 6, state, roundPad, notepad);
  make_next_hyper(6, 1, 7, state, roundPad, notepad);

  uint modify;
  uint prev = 7;
  uint iterator = 0;

    for (uint i = 0; i<LYRA_ROUNDS; i++) {
      local uint *shorter = (local uint*)roundPad;
      if(get_local_id(0) == 0) {
          shorter[get_local_id(1)] = (uint)(state[0] % 8);
      }
      barrier(CLK_LOCAL_MEM_FENCE); // nop
      modify = shorter[get_local_id(1)];
      hyper_xor(prev, modify, iterator, state, roundPad, notepad);
      prev = iterator;
      iterator = (iterator - 1) & 7;
    }

  notepad += HYPERMATRIX_COUNT * modify;
  for(int loop = 0; loop < 3; loop++) state[loop] ^= notepad[loop * REG_ROW_COUNT];

  //-------------------------------------
  // save lyra state    
  lyraState->h8[player] = state[0];
  lyraState->h8[player+4] = state[1];
  lyraState->h8[player+8] = state[2];
  lyraState->h8[player+12] = state[3];

  barrier(CLK_GLOBAL_MEM_FENCE);
}
