/*
 * hmac.c
 *
 * HMAC message authentication code, code
 *
 * Copyright (c) 1999, 2000, 2002 Virtual Unlimited B.V.
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

#include "hmac.h"
#include "mp32.h"
#include "endianness.h"

#define HMAC_IPAD	0x36363636
#define HMAC_OPAD	0x5c5c5c5c

int hmacSetup(hmacParam* hp, const hashFunction* hash, hashFunctionParam* param, const uint32* key, int keybits)
{
	register int i, rc;

	int keywords = (keybits + 31) >> 5; /* rounded up */
	int keybytes = (keybits     ) >> 3;

	/* if the key is too large, hash it first */
	if (keybytes > 64)
	{
		uint32 keydigest[16];
		byte* tmp;

		/* if the hash digest is too large, this doesn't help */
		if (hash->digestsize > 64)
			return -1;

		if (hash->reset(param))
			return -1;

		tmp = (byte*) malloc(keybytes);

		if (tmp == (byte*) 0)
			return -1;

		/* before we can hash the key, we need to encode it! */
		encodeIntsPartial(key, tmp, keybytes);

		rc = hash->update(param, tmp, keybytes);
		free(tmp);

		if (rc)
			return -1;

		if (hash->digest(param, keydigest))
			return -1;

		keywords = hash->digestsize >> 2;
		keybytes = hash->digestsize;

		encodeInts(keydigest, (byte*) hp->kxi, keybytes);
		encodeInts(keydigest, (byte*) hp->kxo, keybytes);
	}
	else if (keybytes > 0)
	{
		encodeIntsPartialPad(key, (byte*) hp->kxi, keybytes, 0);
		encodeIntsPartialPad(key, (byte*) hp->kxo, keybytes, 0);
	}
	else
		return -1;

	for (i = 0; i < keywords; i++)
	{
		hp->kxi[i] ^= HMAC_IPAD;
		hp->kxo[i] ^= HMAC_OPAD;
	}

	for (i = keywords; i < 16; i++)
	{
		hp->kxi[i] = HMAC_IPAD;
		hp->kxo[i] = HMAC_OPAD;
	}

	return hmacReset(hp, hash, param);
}

int hmacReset(hmacParam* hp, const hashFunction* hash, hashFunctionParam* param)
{
	if (hash->reset(param))
		return -1;

	if (hash->update(param, (const byte*) hp->kxi, 64))
		return -1;

	return 0;
}

int hmacUpdate(hmacParam* hp, const hashFunction* hash, hashFunctionParam* param, const byte* data, int size)
{
	return hash->update(param, data, size);
}

int hmacDigest(hmacParam* hp, const hashFunction* hash, hashFunctionParam* param, uint32* data)
{
	if (hash->digest(param, data))
		return -1;

	if (hash->update(param, (const byte*) hp->kxo, 64))
		return -1;

	/* digestsize is in bytes; divide by 4 to get the number of words */
	encodeInts((const javaint*) data, (byte*) data, hash->digestsize >> 2);

	if (hash->update(param, (const byte*) data, hash->digestsize))
		return -1;

	if (hash->digest(param, data))
		return -1;

	return 0;
}
