/*
 * hmacsha256.h
 *
 * HMAC-SHA-256 message authentication code, header
 *
 * Copyright (c) 2000, 2001, 2002 Virtual Unlimited B.V.
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

#ifndef _HMACSHA256_H
#define _HMACSHA256_H

#include "hmac.h"
#include "sha256.h"

typedef struct
{
	hmacParam hparam;
	sha256Param sparam;
} hmacsha256Param;

#ifdef __cplusplus
extern "C" {
#endif

extern BEECRYPTAPI const keyedHashFunction hmacsha256;

BEECRYPTAPI
int hmacsha256Setup (hmacsha256Param*, const uint32*, int);
BEECRYPTAPI
int hmacsha256Reset (hmacsha256Param*);
BEECRYPTAPI
int hmacsha256Update(hmacsha256Param*, const byte*, int);
BEECRYPTAPI
int hmacsha256Digest(hmacsha256Param*, uint32*);

#ifdef __cplusplus
}
#endif

#endif
