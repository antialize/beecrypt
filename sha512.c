/*
 * Copyright (c) 2004 Beeyond Software Holding BV
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/*!\file sha512.c
 * \brief SHA-512 hash function, as specified by NIST FIPS 180-2.
 * \author Bob Deblier <bob.deblier@telenet.be>
 * \ingroup HASH_m HASH_sha512_m
 */
 
#define BEECRYPT_DLL_EXPORT

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/sha512.h"
#include "beecrypt/endianness.h"

/*!\addtogroup HASH_sha512_m
 * \{
 */

static const uint64_t k[80] = {
	0x428a2f98d728ae22U, 0x7137449123ef65cdU,
	0xb5c0fbcfec4d3b2fU, 0xe9b5dba58189dbbcU,
	0x3956c25bf348b538U, 0x59f111f1b605d019U,
	0x923f82a4af194f9bU, 0xab1c5ed5da6d8118U,
	0xd807aa98a3030242U, 0x12835b0145706fbeU,
	0x243185be4ee4b28cU, 0x550c7dc3d5ffb4e2U,
	0x72be5d74f27b896fU, 0x80deb1fe3b1696b1U,
	0x9bdc06a725c71235U, 0xc19bf174cf692694U,
	0xe49b69c19ef14ad2U, 0xefbe4786384f25e3U,
	0x0fc19dc68b8cd5b5U, 0x240ca1cc77ac9c65U,
	0x2de92c6f592b0275U, 0x4a7484aa6ea6e483U,
	0x5cb0a9dcbd41fbd4U, 0x76f988da831153b5U,
	0x983e5152ee66dfabU, 0xa831c66d2db43210U,
	0xb00327c898fb213fU, 0xbf597fc7beef0ee4U,
	0xc6e00bf33da88fc2U, 0xd5a79147930aa725U,
	0x06ca6351e003826fU, 0x142929670a0e6e70U,
	0x27b70a8546d22ffcU, 0x2e1b21385c26c926U,
	0x4d2c6dfc5ac42aedU, 0x53380d139d95b3dfU,
	0x650a73548baf63deU, 0x766a0abb3c77b2a8U,
	0x81c2c92e47edaee6U, 0x92722c851482353bU,
	0xa2bfe8a14cf10364U, 0xa81a664bbc423001U,
	0xc24b8b70d0f89791U, 0xc76c51a30654be30U,
	0xd192e819d6ef5218U, 0xd69906245565a910U,
	0xf40e35855771202aU, 0x106aa07032bbd1b8U,
	0x19a4c116b8d2d0c8U, 0x1e376c085141ab53U,
	0x2748774cdf8eeb99U, 0x34b0bcb5e19b48a8U,
	0x391c0cb3c5c95a63U, 0x4ed8aa4ae3418acbU,
	0x5b9cca4f7763e373U, 0x682e6ff3d6b2b8a3U,
	0x748f82ee5defb2fcU, 0x78a5636f43172f60U,
	0x84c87814a1f0ab72U, 0x8cc702081a6439ecU,
	0x90befffa23631e28U, 0xa4506cebde82bde9U,
	0xbef9a3f7b2c67915U, 0xc67178f2e372532bU,
	0xca273eceea26619cU, 0xd186b8c721c0c207U,
	0xeada7dd6cde0eb1eU, 0xf57d4f7fee6ed178U,
	0x06f067aa72176fbaU, 0x0a637dc5a2c898a6U,
	0x113f9804bef90daeU, 0x1b710b35131c471bU,
	0x28db77f523047d84U, 0x32caab7b40c72493U,
	0x3c9ebe0a15c9bebcU, 0x431d67c49c100d4cU,
	0x4cc5d4becb3e42b6U, 0x597f299cfc657e2aU,
	0x5fcb6fab3ad6faecU, 0x6c44198c4a475817U
};

static const uint64_t hinit[8] = {
	0x6a09e667f3bcc908U,
	0xbb67ae8584caa73bU,
	0x3c6ef372fe94f82bU,
	0xa54ff53a5f1d36f1U,
	0x510e527fade682d1U,
	0x9b05688c2b3e6c1fU,
	0x1f83d9abfb41bd6bU,
	0x5be0cd19137e2179U
};

const hashFunction sha512 = { "SHA-512", sizeof(sha512Param), 128, 64, (hashFunctionReset) sha512Reset, (hashFunctionUpdate) sha512Update, (hashFunctionDigest) sha512Digest };

int sha512Reset(register sha512Param* sp)
{
	memcpy(sp->h, hinit, 8 * sizeof(uint64_t));
	memset(sp->data, 0, 80 * sizeof(uint64_t));
	#if (MP_WBITS == 64)
	mpzero(2, sp->length);
	#elif (MP_WBITS == 32)
	mpzero(4, sp->length);
	#else
	# error
	#endif
	sp->offset = 0;
	return 0;
}

#define R(x,s)  ((x) >> (s))
#define S(x,s) ROTR64(x, s)

#define CH(x,y,z) ((x&(y^z))^z)
#define MAJ(x,y,z) (((x|y)&z)|(x&y))
#define SIG0(x)	(S(x,28) ^ S(x,34) ^ S(x,39))
#define SIG1(x)	(S(x,14) ^ S(x,18) ^ S(x,41))
#define sig0(x) (S(x,1) ^ S(x,8) ^ R(x,7))
#define sig1(x) (S(x,19) ^ S(x,61) ^ R(x,6))

#define ROUND(a,b,c,d,e,f,g,h,w,k)	\
	temp = h + SIG1(e) + CH(e,f,g) + k + w;	\
	h = temp + SIG0(a) + MAJ(a,b,c);	\
	d += temp

#ifndef ASM_SHA512PROCESS
void sha512Process(register sha512Param* sp)
{
	register uint64_t a, b, c, d, e, f, g, h, temp;
	register uint64_t *w;
	register byte t;

	#if WORDS_BIGENDIAN
	w = sp->data + 16;
	#else
	w = sp->data;
	t = 16;
	while (t--)
	{
		temp = swapu64(*w);
		*(w++) = temp;
	}
	#endif

	t = 64;
	while (t--)
	{
		temp = sig1(w[-2]) + w[-7] + sig0(w[-15]) + w[-16];
		*(w++) = temp;
	}

	w = sp->data;

	a = sp->h[0]; b = sp->h[1]; c = sp->h[2]; d = sp->h[3];
	e = sp->h[4]; f = sp->h[5]; g = sp->h[6]; h = sp->h[7];

	ROUND(a,b,c,d,e,f,g,h,w[ 0],k[ 0]);
	ROUND(h,a,b,c,d,e,f,g,w[ 1],k[ 1]);
	ROUND(g,h,a,b,c,d,e,f,w[ 2],k[ 2]);
	ROUND(f,g,h,a,b,c,d,e,w[ 3],k[ 3]);
	ROUND(e,f,g,h,a,b,c,d,w[ 4],k[ 4]);
	ROUND(d,e,f,g,h,a,b,c,w[ 5],k[ 5]);
	ROUND(c,d,e,f,g,h,a,b,w[ 6],k[ 6]);
	ROUND(b,c,d,e,f,g,h,a,w[ 7],k[ 7]);
	ROUND(a,b,c,d,e,f,g,h,w[ 8],k[ 8]);
	ROUND(h,a,b,c,d,e,f,g,w[ 9],k[ 9]);
	ROUND(g,h,a,b,c,d,e,f,w[10],k[10]);
	ROUND(f,g,h,a,b,c,d,e,w[11],k[11]);
	ROUND(e,f,g,h,a,b,c,d,w[12],k[12]);
	ROUND(d,e,f,g,h,a,b,c,w[13],k[13]);
	ROUND(c,d,e,f,g,h,a,b,w[14],k[14]);
	ROUND(b,c,d,e,f,g,h,a,w[15],k[15]);
	ROUND(a,b,c,d,e,f,g,h,w[16],k[16]);
	ROUND(h,a,b,c,d,e,f,g,w[17],k[17]);
	ROUND(g,h,a,b,c,d,e,f,w[18],k[18]);
	ROUND(f,g,h,a,b,c,d,e,w[19],k[19]);
	ROUND(e,f,g,h,a,b,c,d,w[20],k[20]);
	ROUND(d,e,f,g,h,a,b,c,w[21],k[21]);
	ROUND(c,d,e,f,g,h,a,b,w[22],k[22]);
	ROUND(b,c,d,e,f,g,h,a,w[23],k[23]);
	ROUND(a,b,c,d,e,f,g,h,w[24],k[24]);
	ROUND(h,a,b,c,d,e,f,g,w[25],k[25]);
	ROUND(g,h,a,b,c,d,e,f,w[26],k[26]);
	ROUND(f,g,h,a,b,c,d,e,w[27],k[27]);
	ROUND(e,f,g,h,a,b,c,d,w[28],k[28]);
	ROUND(d,e,f,g,h,a,b,c,w[29],k[29]);
	ROUND(c,d,e,f,g,h,a,b,w[30],k[30]);
	ROUND(b,c,d,e,f,g,h,a,w[31],k[31]);
	ROUND(a,b,c,d,e,f,g,h,w[32],k[32]);
	ROUND(h,a,b,c,d,e,f,g,w[33],k[33]);
	ROUND(g,h,a,b,c,d,e,f,w[34],k[34]);
	ROUND(f,g,h,a,b,c,d,e,w[35],k[35]);
	ROUND(e,f,g,h,a,b,c,d,w[36],k[36]);
	ROUND(d,e,f,g,h,a,b,c,w[37],k[37]);
	ROUND(c,d,e,f,g,h,a,b,w[38],k[38]);
	ROUND(b,c,d,e,f,g,h,a,w[39],k[39]);
	ROUND(a,b,c,d,e,f,g,h,w[40],k[40]);
	ROUND(h,a,b,c,d,e,f,g,w[41],k[41]);
	ROUND(g,h,a,b,c,d,e,f,w[42],k[42]);
	ROUND(f,g,h,a,b,c,d,e,w[43],k[43]);
	ROUND(e,f,g,h,a,b,c,d,w[44],k[44]);
	ROUND(d,e,f,g,h,a,b,c,w[45],k[45]);
	ROUND(c,d,e,f,g,h,a,b,w[46],k[46]);
	ROUND(b,c,d,e,f,g,h,a,w[47],k[47]);
	ROUND(a,b,c,d,e,f,g,h,w[48],k[48]);
	ROUND(h,a,b,c,d,e,f,g,w[49],k[49]);
	ROUND(g,h,a,b,c,d,e,f,w[50],k[50]);
	ROUND(f,g,h,a,b,c,d,e,w[51],k[51]);
	ROUND(e,f,g,h,a,b,c,d,w[52],k[52]);
	ROUND(d,e,f,g,h,a,b,c,w[53],k[53]);
	ROUND(c,d,e,f,g,h,a,b,w[54],k[54]);
	ROUND(b,c,d,e,f,g,h,a,w[55],k[55]);
	ROUND(a,b,c,d,e,f,g,h,w[56],k[56]);
	ROUND(h,a,b,c,d,e,f,g,w[57],k[57]);
	ROUND(g,h,a,b,c,d,e,f,w[58],k[58]);
	ROUND(f,g,h,a,b,c,d,e,w[59],k[59]);
	ROUND(e,f,g,h,a,b,c,d,w[60],k[60]);
	ROUND(d,e,f,g,h,a,b,c,w[61],k[61]);
	ROUND(c,d,e,f,g,h,a,b,w[62],k[62]);
	ROUND(b,c,d,e,f,g,h,a,w[63],k[63]);
	ROUND(a,b,c,d,e,f,g,h,w[64],k[64]);
	ROUND(h,a,b,c,d,e,f,g,w[65],k[65]);
	ROUND(g,h,a,b,c,d,e,f,w[66],k[66]);
	ROUND(f,g,h,a,b,c,d,e,w[67],k[67]);
	ROUND(e,f,g,h,a,b,c,d,w[68],k[68]);
	ROUND(d,e,f,g,h,a,b,c,w[69],k[69]);
	ROUND(c,d,e,f,g,h,a,b,w[70],k[70]);
	ROUND(b,c,d,e,f,g,h,a,w[71],k[71]);
	ROUND(a,b,c,d,e,f,g,h,w[72],k[72]);
	ROUND(h,a,b,c,d,e,f,g,w[73],k[73]);
	ROUND(g,h,a,b,c,d,e,f,w[74],k[74]);
	ROUND(f,g,h,a,b,c,d,e,w[75],k[75]);
	ROUND(e,f,g,h,a,b,c,d,w[76],k[76]);
	ROUND(d,e,f,g,h,a,b,c,w[77],k[77]);
	ROUND(c,d,e,f,g,h,a,b,w[78],k[78]);
	ROUND(b,c,d,e,f,g,h,a,w[79],k[79]);

	sp->h[0] += a;
	sp->h[1] += b;
	sp->h[2] += c;
	sp->h[3] += d;
	sp->h[4] += e;
	sp->h[5] += f;
	sp->h[6] += g;
	sp->h[7] += h;
}
#endif

int sha512Update(register sha512Param* sp, const byte* data, size_t size)
{
	register uint64_t proclength;

	#if (MP_WBITS == 64)
	mpw add[2];
	mpsetw(2, add, size);
	mplshift(2, add, 3);
	mpadd(2, sp->length, add);
	#elif (MP_WBITS == 32)
	mpw add[4];
	mpsetw(4, add, size);
	mplshift(4, add, 3);
	mpadd(4, sp->length, add);
	#else
	# error
	#endif

	while (size > 0)
	{
		proclength = ((sp->offset + size) > 128U) ? (128U - sp->offset) : size;
		memcpy(((byte *) sp->data) + sp->offset, data, proclength);
		size -= proclength;
		data += proclength;
		sp->offset += proclength;

		if (sp->offset == 128U)
		{
			sha512Process(sp);
			sp->offset = 0;
		}
	}
	return 0;
}

static void sha512Finish(register sha512Param* sp)
{
	register byte *ptr = ((byte *) sp->data) + sp->offset++;

	*(ptr++) = 0x80;

	if (sp->offset > 112)
	{
		while (sp->offset++ < 128)
			*(ptr++) = 0;

		sha512Process(sp);
		sp->offset = 0;
	}

	ptr = ((byte *) sp->data) + sp->offset;
	while (sp->offset++ < 112)
		*(ptr++) = 0;

	#if (MP_WBITS == 64)
	ptr[ 0] = (byte)(sp->length[0] >> 56);
	ptr[ 1] = (byte)(sp->length[0] >> 48);
	ptr[ 2] = (byte)(sp->length[0] >> 40);
	ptr[ 3] = (byte)(sp->length[0] >> 32);
	ptr[ 4] = (byte)(sp->length[0] >> 24);
	ptr[ 5] = (byte)(sp->length[0] >> 16);
	ptr[ 6] = (byte)(sp->length[0] >>  8);
	ptr[ 7] = (byte)(sp->length[0]      );
	ptr[ 8] = (byte)(sp->length[1] >> 56);
	ptr[ 9] = (byte)(sp->length[1] >> 48);
	ptr[10] = (byte)(sp->length[1] >> 40);
	ptr[11] = (byte)(sp->length[1] >> 32);
	ptr[12] = (byte)(sp->length[1] >> 24);
	ptr[13] = (byte)(sp->length[1] >> 16);
	ptr[14] = (byte)(sp->length[1] >>  8);
	ptr[15] = (byte)(sp->length[1]      );
	#elif (MP_WBITS == 32)
	ptr[ 0] = (byte)(sp->length[0] >> 24);
	ptr[ 1] = (byte)(sp->length[0] >> 16);
	ptr[ 2] = (byte)(sp->length[0] >>  8);
	ptr[ 3] = (byte)(sp->length[0]      );
	ptr[ 4] = (byte)(sp->length[1] >> 24);
	ptr[ 5] = (byte)(sp->length[1] >> 16);
	ptr[ 6] = (byte)(sp->length[1] >>  8);
	ptr[ 7] = (byte)(sp->length[1]      );
	ptr[ 8] = (byte)(sp->length[2] >> 24);
	ptr[ 9] = (byte)(sp->length[2] >> 16);
	ptr[10] = (byte)(sp->length[2] >>  8);
	ptr[11] = (byte)(sp->length[2]      );
	ptr[12] = (byte)(sp->length[3] >> 24);
	ptr[13] = (byte)(sp->length[3] >> 16);
	ptr[14] = (byte)(sp->length[3] >>  8);
	ptr[15] = (byte)(sp->length[3]      );
	#else
	# error
	#endif

	sha512Process(sp);
	sp->offset = 0;
}

int sha512Digest(register sha512Param* sp, byte* data)
{
	sha512Finish(sp);

	/* encode 8 integers big-endian style */
	data[ 0] = (byte)(sp->h[0] >> 56);
	data[ 1] = (byte)(sp->h[0] >> 48);
	data[ 2] = (byte)(sp->h[0] >> 40);
	data[ 3] = (byte)(sp->h[0] >> 32);
	data[ 4] = (byte)(sp->h[0] >> 24);
	data[ 5] = (byte)(sp->h[0] >> 16);
	data[ 6] = (byte)(sp->h[0] >>  8);
	data[ 7] = (byte)(sp->h[0] >>  0);

	data[ 8] = (byte)(sp->h[1] >> 56);
	data[ 9] = (byte)(sp->h[1] >> 48);
	data[10] = (byte)(sp->h[1] >> 40);
	data[11] = (byte)(sp->h[1] >> 32);
	data[12] = (byte)(sp->h[1] >> 24);
	data[13] = (byte)(sp->h[1] >> 16);
	data[14] = (byte)(sp->h[1] >>  8);
	data[15] = (byte)(sp->h[1] >>  0);

	data[16] = (byte)(sp->h[2] >> 56);
	data[17] = (byte)(sp->h[2] >> 48);
	data[18] = (byte)(sp->h[2] >> 40);
	data[19] = (byte)(sp->h[2] >> 32);
	data[20] = (byte)(sp->h[2] >> 24);
	data[21] = (byte)(sp->h[2] >> 16);
	data[22] = (byte)(sp->h[2] >>  8);
	data[23] = (byte)(sp->h[2] >>  0);

	data[24] = (byte)(sp->h[3] >> 56);
	data[25] = (byte)(sp->h[3] >> 48);
	data[26] = (byte)(sp->h[3] >> 40);
	data[27] = (byte)(sp->h[3] >> 32);
	data[28] = (byte)(sp->h[3] >> 24);
	data[29] = (byte)(sp->h[3] >> 16);
	data[30] = (byte)(sp->h[3] >>  8);
	data[31] = (byte)(sp->h[3] >>  0);

	data[32] = (byte)(sp->h[4] >> 56);
	data[33] = (byte)(sp->h[4] >> 48);
	data[34] = (byte)(sp->h[4] >> 40);
	data[35] = (byte)(sp->h[4] >> 32);
	data[36] = (byte)(sp->h[4] >> 24);
	data[37] = (byte)(sp->h[4] >> 16);
	data[38] = (byte)(sp->h[4] >>  8);
	data[39] = (byte)(sp->h[4] >>  0);

	data[40] = (byte)(sp->h[5] >> 56);
	data[41] = (byte)(sp->h[5] >> 48);
	data[42] = (byte)(sp->h[5] >> 40);
	data[43] = (byte)(sp->h[5] >> 32);
	data[44] = (byte)(sp->h[5] >> 24);
	data[45] = (byte)(sp->h[5] >> 16);
	data[46] = (byte)(sp->h[5] >>  8);
	data[47] = (byte)(sp->h[5] >>  0);

	data[48] = (byte)(sp->h[6] >> 56);
	data[49] = (byte)(sp->h[6] >> 48);
	data[50] = (byte)(sp->h[6] >> 40);
	data[51] = (byte)(sp->h[6] >> 32);
	data[52] = (byte)(sp->h[6] >> 24);
	data[53] = (byte)(sp->h[6] >> 16);
	data[54] = (byte)(sp->h[6] >>  8);
	data[55] = (byte)(sp->h[6] >>  0);

	data[56] = (byte)(sp->h[7] >> 56);
	data[57] = (byte)(sp->h[7] >> 48);
	data[58] = (byte)(sp->h[7] >> 40);
	data[59] = (byte)(sp->h[7] >> 32);
	data[60] = (byte)(sp->h[7] >> 24);
	data[61] = (byte)(sp->h[7] >> 16);
	data[62] = (byte)(sp->h[7] >>  8);
	data[63] = (byte)(sp->h[7] >>  0);

	sha512Reset(sp);
	return 0;
}

/*!\}
 */
