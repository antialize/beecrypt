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

/*!\file testmd5.c
 * \brief Unit test program for the MD5 algorithm; it tests all vectors
 *        specified by RFC 1321.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup UNIT_m
 */

#include <stdio.h>

#include "md5.h"

struct input_expect
{
	unsigned char* input;
	uint32 expect[4];
};


struct input_expect table[7] = {
	{ "",
		{ 0xd41d8cd9U, 0x8f00b204U, 0xe9800998U, 0xecf8427eU } },
	{ "a",
		{ 0x0cc175b9U, 0xc0f1b6a8U, 0x31c399e2U, 0x69772661U } },
	{ "abc",
		{ 0x90015098U, 0x3cd24fb0U, 0xd6963f7dU, 0x28e17f72U } },
	{ "message digest",
		{ 0xf96b697dU, 0x7cb7938dU, 0x525a2f31U, 0xaaf161d0U } },
	{ "abcdefghijklmnopqrstuvwxyz",
		{ 0xc3fcd3d7U, 0x6192e400U, 0x7dfb496cU, 0xca67e13bU } },
	{ "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
		{ 0xd174ab98U, 0xd277d9f5U, 0xa5611c2cU, 0x9f419d9fU } },
	{ "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
		{ 0x57edf4a2U, 0x2be3c955U, 0xac49da2eU, 0x2107b67aU } }
};

int main()
{
	int i, failures = 0;
        md5Param param;
	uint32 digest[4];

	for (i = 0; i < 7; i++)
	{
		if (md5Reset(&param))
			return -1;
		if (md5Update(&param, table[i].input, strlen(table[i].input)))
			return -1;
		if (md5Digest(&param, digest))
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
