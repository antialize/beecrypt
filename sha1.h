/*
 * Copyright (c) 1997, 1998, 1999, 2000, 2002 Virtual Unlimited B.V.
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

/*!\file sha1.h
 * \brief SHA-1 hash function, headers.
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup HASH_m HASH_sha1_m
 */

#ifndef _SHA1_H
#define _SHA1_H

#include "beecrypt.h"
#include "sha1opt.h"

/*!\ingroup HASH_sha1_m
 */
typedef struct
{
	uint32 h[5];
	uint32 data[80];
	uint64 length;
	uint8  offset;
} sha1Param;

#ifdef __cplusplus
extern "C" {
#endif

extern BEECRYPTAPI const hashFunction sha1;

BEECRYPTAPI
void sha1Process(sha1Param*);
BEECRYPTAPI
int  sha1Reset  (sha1Param*);
BEECRYPTAPI
int  sha1Update (sha1Param*, const byte*, int);
BEECRYPTAPI
int  sha1Digest (sha1Param*, uint32*);

#ifdef __cplusplus
}
#endif

#endif
