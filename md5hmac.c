/*
 * md5hmac.c
 *
 * MD5/HMAC message authentication code, code
 *
 * Copyright (c) 2000 Virtual Unlimited B.V.
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

#include "md5hmac.h"

const keyedHashFunction md5hmac = { "MD5/HMAC", sizeof(md5hmacParam), 64, 4 * sizeof(uint32), 64, 512, 32, (const keyedHashFunctionSetup) md5hmacSetup, (const keyedHashFunctionReset) md5hmacReset, (const keyedHashFunctionUpdate) md5hmacUpdate, (const keyedHashFunctionDigest) md5hmacDigest };

int md5hmacSetup (md5hmacParam* sp, const uint32* key, int keybits)
{
	return hmacSetup((hmacParam*) sp, &md5, &sp->param, key, keybits);
}

int md5hmacReset (md5hmacParam* sp)
{
	return hmacReset((hmacParam*) sp, &md5, &sp->param);
}

int md5hmacUpdate(md5hmacParam* sp, const byte* data, int size)
{
	return hmacUpdate((hmacParam*) sp, &md5, &sp->param, data, size);
}

int md5hmacDigest(md5hmacParam* sp, uint32* data)
{
	return hmacDigest((hmacParam*) sp, &md5, &sp->param, data);
}
