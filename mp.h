/*
 * Copyright (c) 2002, 2003 Bob Deblier
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

/*!\file mp.h
 * \brief Multi-precision integer routines, headers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup MP_m
 */

#ifndef _MP_H
#define _MP_H

#include "beecrypt.api.h"
#include "mpopt.h"

#if HAVE_STRING_H
# include <string.h>
#endif

#define MP_HWBITS	(MP_WBITS >> 1)
#define MP_WBYTES	(MP_WBITS >> 3)
#define MP_WNIBBLES	(MP_WBITS >> 2)

#if (MP_WBITS == 64)
# define MP_WORDS_TO_BITS(x)	((x) << 6)
# define MP_WORDS_TO_NIBBLES(x)	((x) << 4)
# define MP_WORDS_TO_BYTES(x)	((x) << 3)
# define MP_BITS_TO_WORDS(x)	((x) >> 6)
# define MP_NIBBLES_TO_WORDS(x)	((x) >> 4)
# define MP_BYTES_TO_WORDS(x)	((x) >> 3)
#elif (MP_WBITS == 32)
# define MP_WORDS_TO_BITS(x)	((x) << 5)
# define MP_WORDS_TO_NIBBLES(x)	((x) << 3)
# define MP_WORDS_TO_BYTES(x)	((x) << 2)
# define MP_BITS_TO_WORDS(x)	((x) >> 5) 
# define MP_NIBBLES_TO_WORDS(x)	((x) >> 3)
# define MP_BYTES_TO_WORDS(x)	((x) >> 2)
#else
# error
#endif

#if (MP_WBITS == 64)
typedef uint64_t mpw;
typedef uint32_t mphw;
#elif (MP_WBITS == 32)
# if HAVE_UINT64_T
#  define HAVE_MPDW 1
typedef uint64_t mpdw;
# endif
typedef uint32_t mpw;
typedef uint16_t mphw;
#else
# error
#endif

#define MP_MSBMASK	(((mpw) 0x1) << (MP_WBITS-1))
#define MP_LSBMASK	 ((mpw) 0x1)
#define MP_ALLMASK	~((mpw) 0x0)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ASM_MPCOPY
# define mpcopy(size, dst, src) memcpy(dst, src, MP_WORDS_TO_BYTES(size))
#else
BEECRYPTAPI
void mpcopy(size_t, mpw*, const mpw*);
#endif

#ifndef ASM_MPMOVE
# define mpmove(size, dst, src) memmove(dst, src, MP_WORDS_TO_BYTES(size))
#else
BEECRYPTAPI
void mpmove(size_t, mpw*, const mpw*);
#endif

BEECRYPTAPI
void mpzero(size_t, mpw*);
BEECRYPTAPI
void mpfill(size_t, mpw*, mpw);

BEECRYPTAPI
int mpodd (size_t, const mpw*);
BEECRYPTAPI
int mpeven(size_t, const mpw*);

BEECRYPTAPI
int mpz  (size_t, const mpw*);
BEECRYPTAPI
int mpnz (size_t, const mpw*);
BEECRYPTAPI
int mpeq (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mpne (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mpgt (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mplt (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mpge (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mple (size_t, const mpw*, const mpw*);
BEECRYPTAPI
int mpeqx(size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
int mpnex(size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
int mpgtx(size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
int mpltx(size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
int mpgex(size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
int mplex(size_t, const mpw*, size_t, const mpw*);

BEECRYPTAPI
int mpisone(size_t, const mpw*);
BEECRYPTAPI
int mpistwo(size_t, const mpw*);
BEECRYPTAPI
int mpleone(size_t, const mpw*);
BEECRYPTAPI
int mpeqmone(size_t, const mpw*, const mpw*);

BEECRYPTAPI
int mpmsbset(size_t, const mpw*);
BEECRYPTAPI
int mplsbset(size_t, const mpw*);

BEECRYPTAPI
void mpsetmsb(size_t, mpw*);
BEECRYPTAPI
void mpsetlsb(size_t, mpw*);
BEECRYPTAPI
void mpclrmsb(size_t, mpw*);
BEECRYPTAPI
void mpclrlsb(size_t, mpw*);

BEECRYPTAPI
void mpxor(size_t, mpw*, const mpw*);
BEECRYPTAPI
void mpnot(size_t, mpw*);

BEECRYPTAPI
void mpsetw(size_t, mpw*, mpw);
BEECRYPTAPI
void mpsetx(size_t, mpw*, size_t, const mpw*);

BEECRYPTAPI
int mpaddw(size_t, mpw*, mpw);
BEECRYPTAPI
int mpadd (size_t, mpw*, const mpw*);
BEECRYPTAPI
int mpaddx(size_t, mpw*, size_t, const mpw*);

BEECRYPTAPI
int mpsubw(size_t, mpw*, mpw);
BEECRYPTAPI
int mpsub (size_t, mpw*, const mpw*);
BEECRYPTAPI
int mpsubx(size_t, mpw*, size_t, const mpw*);

BEECRYPTAPI
int mpmultwo(size_t, mpw*);

BEECRYPTAPI
void mpneg(size_t, mpw*);

BEECRYPTAPI
size_t mpsize(size_t, const mpw*);
BEECRYPTAPI
size_t mpbits(size_t, const mpw*);

BEECRYPTAPI
size_t mpmszcnt(size_t, const mpw*);
BEECRYPTAPI
size_t mplszcnt(size_t, const mpw*);

BEECRYPTAPI
void mplshift(size_t, mpw*, size_t);
BEECRYPTAPI
void mprshift(size_t, mpw*, size_t);

BEECRYPTAPI
size_t mprshiftlsz(size_t, mpw*);

BEECRYPTAPI
size_t mpnorm(size_t, mpw*);

BEECRYPTAPI
void mpdivtwo (size_t, mpw*);
BEECRYPTAPI
void mpsdivtwo(size_t, mpw*);

BEECRYPTAPI
mpw mpsetmul   (size_t, mpw*, const mpw*, mpw);
BEECRYPTAPI
mpw mpaddmul   (size_t, mpw*, const mpw*, mpw);
BEECRYPTAPI
mpw mpaddsqrtrc(size_t, mpw*, const mpw*);

BEECRYPTAPI
void mpmul(mpw*, size_t, const mpw*, size_t, const mpw*);
BEECRYPTAPI
void mpsqr(mpw*, size_t, const mpw*);

BEECRYPTAPI
void mpgcd_w(size_t, const mpw*, const mpw*, mpw*, mpw*);

BEECRYPTAPI
mpw mppndiv(mpw, mpw, mpw);

BEECRYPTAPI
mpw mpnmodw(mpw*, size_t, const mpw*, mpw, mpw*);

BEECRYPTAPI
void mpnmod(mpw*, size_t, const mpw*, size_t, const mpw*, mpw*);
BEECRYPTAPI
void mpndivmod(mpw*, size_t, const mpw*, size_t, const mpw*, mpw*);

/*
 * Output Routines
 */

BEECRYPTAPI
void mpprint(size_t, const mpw*);
BEECRYPTAPI
void mpprintln(size_t, const mpw*);

/*
 * Conversion Routines
 */

BEECRYPTAPI
int os2ip(mpw*, size_t, const byte*, size_t);
BEECRYPTAPI
int i2osp(byte*, size_t, const mpw*, size_t);

BEECRYPTAPI
int hs2ip(mpw*, size_t, const char*, size_t);

#ifdef __cplusplus
}
#endif

#endif
