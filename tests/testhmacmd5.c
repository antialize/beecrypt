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

/*!\file testhmacmd5.c
 * \brief Unit test program for HMAC-MD5; it tests all vectors specified
 *        by RFC 2202.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup UNIT_m
 */

#include <stdio.h>

#include "hmacmd5.h"

struct key_input_expect
{
	unsigned char* key;
	unsigned char* input;
	uint32 expect[4];
};

struct key_input_expect table[7] = 
{
	{ "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", "Hi There",
		{ 0x9294727aU, 0x3638bb1cU, 0x13f48ef8U, 0x158bfc9dU } },
	{ "Jefe", "what do ya want for nothing?",
		{ 0x750c783eU, 0x6ab0b503U, 0xeaa86e31U, 0x0a5db738U } },
	{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
		{ 0x56be3452U, 0x1d144c88U, 0xdbb8c733U, 0xf0e8b3f6U } },
	{ "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",  "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
		{ 0x697eaf0aU, 0xca3a3aeaU, 0x3a751647U, 0x46ffaa79U } },
	{ "\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c", "Test With Truncation",
		{ 0x56461ef2U, 0x342edc00U, 0xf9bab995U, 0x690efd4cU } },
	{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "Test Using Larger Than Block-Size Key - Hash Key First",
		{ 0x6b1ab7feU, 0x4bd7bf8fU, 0x0b62e6ceU, 0x61b9d0cdU } },
	{ "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
		{ 0x6f630fadU, 0x67cda0eeU, 0x1fb1f562U, 0xdb3aa53eU} }
};

int main()
{
	int i, failures = 0;
	hmacmd5Param param;
	uint32 digest[4];
	uint32 key[64];

	for (i = 0; i < 7; i++)
	{
		/* set the key up properly, removing endian-ness */
		decodeIntsPartial(key, table[i].key, strlen(table[i].key));

		if (hmacmd5Setup(&param, key, strlen(table[i].key) << 3))
			return -1;

		if (hmacmd5Update(&param, table[i].input, strlen(table[i].input)))
			return -1;
		if (hmacmd5Digest(&param, digest))
			return -1;

		if (mp32ne(4, digest, table[i].expect))
		{
			printf("failed\n");
			failures++;
		}
		else
			printf("ok\n");
	}

	return failures;
}
