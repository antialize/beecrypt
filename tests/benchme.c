/*
 * Copyright (c) 2003 Bob Deblier
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

/*!\file benchme.c
 * \brief Benchmark program for Modular Exponentiation.
 * \author Bob Deblier <bob.deblier@pandora.be>
 */

#include <stdio.h>

#include "beecrypt.h"
#include "dldp.h"
#include "timestamp.h"

#define SECONDS	10

static const char* hp = "afe160d7ec48d97e7e47c70847a650835a8c33fd228f780bcff36b3753fa3e12d5517a4548f805a890d41c9dff493b0f195973b72269b63b977bb86f6187e5cb3588635d6ed49c15d40993c35c55732e5632099a1fe752b15ff6273ddbe8ce411d2b9ee1722e7ec8fc348a8446c56a2cb099130b6b1cfa97bb3494ebb32893fb";
static const char* hq = "ee4e9b43898b5a48c23f25ff8d2db0c5c32f527b";
static const char* hg = "2c63b6a74c065bf1cb23c37d890055a1a18569c0e55f1bcd0a438d115b6634370d34085866fc9f03fafadb417dc5356bf0f8ae3468aefe59356b118ab0b5a5528714ee649f7100a2aea3d9bdf8e40d7b97998a2e6e4e4ac98fbe0f16662a528318a9da36f52dca7d5008ff42eb304c174089ab691aabb43d3375bb276104d41a";

int main()
{
	dldp_p params;
	mp32number gq;
	javalong start, now;
	int iterations = 0;

	dldp_pInit(&params);

	mp32bsethex(&params.p, hp);
	mp32bsethex(&params.q, hq);
	mp32nsethex(&params.g, hg);

	mp32nzero(&gq);

	/* get starting time */
	start = timestamp();
	do
	{
		mp32bnpowmod(&params.p, &params.g, (mp32number*) &params.q, &gq);
		now = timestamp();
		iterations++;
	} while (now < (start + (SECONDS * ONE_SECOND)));

	mp32nfree(&gq);

	printf("(%d bits) ^ (%d bits) mod (%d bits): %d times in %d seconds\n", params.g.size << 5, params.q.size << 5, params.p.size << 5, iterations, SECONDS);

	dldp_pFree(&params);

	return 0;
}
