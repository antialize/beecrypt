/*
 * Copyright (c) 1999, 2000, 2002 Virtual Unlimited B.V.
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

/*!\file hmac.h
 * \brief HMAC algorithm, headers.
 * \todo Up to now the algorithm only works for hashes that have a block size
 *       of 64 bytes. It would be good to change this so that the initializer
 *       uses the block size from the hash function's descriptor.
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup HMAC_m
 */

#ifndef _HMAC_H
#define _HMAC_H

#include "beecrypt.h"

/*!\ingroup HMAC_m
 */
typedef struct
{
	byte kxi[64];
	byte kxo[64];
} hmacParam;

#ifdef __cplusplus
extern "C" {
#endif

/* not used directly as keyed hash function, but instead used as generic methods */

BEECRYPTAPI
int hmacSetup (hmacParam*, const hashFunction*, hashFunctionParam*, const uint32*, int);
BEECRYPTAPI
int hmacReset (hmacParam*, const hashFunction*, hashFunctionParam*);
BEECRYPTAPI
int hmacUpdate(hmacParam*, const hashFunction*, hashFunctionParam*, const byte*, int);
BEECRYPTAPI
int hmacDigest(hmacParam*, const hashFunction*, hashFunctionParam*, uint32*);

#ifdef __cplusplus
}
#endif

#endif
