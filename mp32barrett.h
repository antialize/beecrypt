/*
 * mp32barrett.h
 *
 * Barrett modular reduction, header
 *
 * Copyright (c) 1997, 1998, 1999, 2000, 2001 Virtual Unlimited B.V.
 *
 * Author: Bob Deblier <bob@virtualunlimited.com>
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

#ifndef _MP32BARRETT_H
#define _MP32BARRETT_H

#include "beecrypt.h"
#include "mp32number.h"

typedef struct
{
	uint32	size;
	uint32* modl;	/* (size) words */
	uint32* mu;		/* (size+1) words */
} mp32barrett;

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
void mp32bzero(mp32barrett*);
BEECRYPTAPI
void mp32binit(mp32barrett*, uint32);
BEECRYPTAPI
void mp32bfree(mp32barrett*);
BEECRYPTAPI
void mp32bcopy(mp32barrett*, const mp32barrett*);

BEECRYPTAPI
void mp32bset(mp32barrett*, uint32, const uint32*);
BEECRYPTAPI
void mp32bsethex(mp32barrett*, const char*);

BEECRYPTAPI
void mp32bsubone(const mp32barrett*, uint32*);

BEECRYPTAPI
void mp32bmu_w(mp32barrett*, uint32*);

BEECRYPTAPI
void mp32brnd_w   (const mp32barrett*, randomGeneratorContext*, uint32*, uint32*);
BEECRYPTAPI
void mp32brndodd_w(const mp32barrett*, randomGeneratorContext*, uint32*, uint32*);
BEECRYPTAPI
void mp32brndinv_w(const mp32barrett*, randomGeneratorContext*, uint32*, uint32*, uint32*);

BEECRYPTAPI
void mp32bneg_w(const mp32barrett*, const uint32*, uint32*);
BEECRYPTAPI
void mp32bmod_w(const mp32barrett*, const uint32*, uint32*, uint32*);

BEECRYPTAPI
void mp32baddmod_w(const mp32barrett*, uint32, const uint32*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32bsubmod_w(const mp32barrett*, uint32, const uint32*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32bmulmod_w(const mp32barrett*, uint32, const uint32*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32bsqrmod_w(const mp32barrett*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32bpowmod_w(const mp32barrett*, uint32, const uint32*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32bpowmodsld_w(const mp32barrett*, const uint32*, uint32, const uint32*, uint32*, uint32*);
BEECRYPTAPI
void mp32btwopowmod_w(const mp32barrett*, uint32, const uint32*, uint32*, uint32*);

BEECRYPTAPI
int  mp32binv_w(const mp32barrett*, uint32, const uint32*, uint32*, uint32*);


/* To be added:
 * simultaneous multiple exponentiation, for use in dsa and elgamal signature verification
 */
BEECRYPTAPI
void mp32bsm2powmod(const mp32barrett*, const uint32*, const uint32*, const uint32*, const uint32*);
BEECRYPTAPI
void mp32bsm3powmod(const mp32barrett*, const uint32*, const uint32*, const uint32*, const uint32*, const uint32*, const uint32*);


BEECRYPTAPI
int  mp32bpprime_w(const mp32barrett*, randomGeneratorContext*, int, uint32*);

/* the next routines take mp32numbers as parameters */

BEECRYPTAPI
void mp32bnrnd(const mp32barrett*, randomGeneratorContext*, mp32number*);

BEECRYPTAPI
void mp32bnmulmod(const mp32barrett*, const mp32number*, const mp32number*, mp32number*);
BEECRYPTAPI
void mp32bnsqrmod(const mp32barrett*, const mp32number*, mp32number*);

BEECRYPTAPI
void mp32bnpowmod   (const mp32barrett*, const mp32number*, const mp32number*, mp32number*);
BEECRYPTAPI
void mp32bnpowmodsld(const mp32barrett*, const uint32*, const mp32number*, mp32number*);

#ifdef __cplusplus
}
#endif

#endif
