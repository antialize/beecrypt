/*
 * sha256hmac.c
 *
 * SHA-256/HMAC message authentication code, code
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

#define BEECRYPT_DLL_EXPORT

#include "sha256hmac.h"

const keyedHashFunction sha256hmac = { "SHA-256/HMAC", sizeof(sha256hmacParam), 64, 8 * sizeof(uint32), 64, 512, 32, (const keyedHashFunctionSetup) sha256hmacSetup, (const keyedHashFunctionReset) sha256hmacReset, (const keyedHashFunctionUpdate) sha256hmacUpdate, (const keyedHashFunctionDigest) sha256hmacDigest };

int sha256hmacSetup (sha256hmacParam* sp, const uint32* key, int keybits)
{
	return hmacSetup((hmacParam*) sp, &sha256, &sp->param, key, keybits);
}

int sha256hmacReset (sha256hmacParam* sp)
{
	return hmacReset((hmacParam*) sp, &sha256, &sp->param);
}

int sha256hmacUpdate(sha256hmacParam* sp, const byte* data, int size)
{
	return hmacUpdate((hmacParam*) sp, &sha256, &sp->param, data, size);
}

int sha256hmacDigest(sha256hmacParam* sp, uint32* data)
{
	return hmacDigest((hmacParam*) sp, &sha256, &sp->param, data);
}
