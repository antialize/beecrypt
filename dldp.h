/*
 * dldp.h
 *
 * Discrete Logarithm Domain Parameters, header
 *
 * <conformance statement for IEEE P1363 needed here>
 *
 * Copyright (c) 2000, 2001 Virtual Unlimited B.V.
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

#ifndef _DLDP_H
#define _DLDP_H

#include "beecrypt.h"
#include "mp32barrett.h"

/*
 * Discrete Logarithm Domain Parameters - Prime
 *
 * Standard definition where p = qr+1; in case where p=2q+1, r=2
 *
 * In IEEE P1363 naming is p = rk+1
 *
 * Hence, IEEE prime r = q and cofactor k = r
 *
 * Make sure q is large enough to foil Pohlig-Hellman attacks
 *  See: "Handbook of Applied Cryptography", Chapter 3.6.4
 *
 * g is either a generator of a subgroup of order q, or a generator of order
 *  n = (p-1)
 */

typedef struct
{
	mp32barrett p;
	mp32barrett q;
	mp32number  r;
	mp32number  g;
	mp32barrett n;
} dldp_p;

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Functions for setting up and copying
 */

BEECRYPTAPI
int dldp_pInit(dldp_p*);
BEECRYPTAPI
int dldp_pFree(dldp_p*);
BEECRYPTAPI
int dldp_pCopy(dldp_p*, const dldp_p*);

/*
 * Functions for generating keys
 */

BEECRYPTAPI
int dldp_pPrivate(const dldp_p*, randomGeneratorContext*, mp32number*);
BEECRYPTAPI
int dldp_pPublic (const dldp_p*, const mp32number*, mp32number*);
BEECRYPTAPI
int dldp_pPair   (const dldp_p*, randomGeneratorContext*, mp32number*, mp32number*);

/*
 * Function for comparing domain parameters
 */

BEECRYPTAPI
int  dldp_pEqual  (const dldp_p*, const dldp_p*);

/*
 * Functions for generating and validating dldp_pgoq variant domain parameters
 */

BEECRYPTAPI
int dldp_pgoqMake     (dldp_p*, randomGeneratorContext*, uint32, uint32, int);
BEECRYPTAPI
int dldp_pgoqMakeSafe (dldp_p*, randomGeneratorContext*, uint32);
BEECRYPTAPI
int dldp_pgoqGenerator(dldp_p*, randomGeneratorContext*);
BEECRYPTAPI
int  dldp_pgoqValidate (const dldp_p*, randomGeneratorContext*, int);

/*
 * Functions for generating and validating dldp_pgon variant domain parameters
 */

BEECRYPTAPI
int dldp_pgonMake     (dldp_p*, randomGeneratorContext*, uint32, uint32);
BEECRYPTAPI
int dldp_pgonMakeSafe (dldp_p*, randomGeneratorContext*, uint32);
BEECRYPTAPI
int dldp_pgonGenerator(dldp_p*, randomGeneratorContext*);
BEECRYPTAPI
int  dldp_pgonValidate (const dldp_p*, randomGeneratorContext*);

#ifdef __cplusplus
}
#endif

#endif
