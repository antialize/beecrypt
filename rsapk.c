/*
 * rsapk.c
 *
 * RSA Public Key, code
 *
 * <conformance statement for IEEE P1363 needed here>
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

#include "rsapk.h"

void rsapkInit(rsapk* pk)
{
	memset(pk, 0, sizeof(rsapk));
	/* or
	mp32bzero(&pk->n);
	mp32nzero(&pk->e);
	*/
}

void rsapkFree(rsapk* pk)
{
	mp32bfree(&pk->n);
	mp32nfree(&pk->e);
}

void rsapkCopy(rsapk* dst, const rsapk* src)
{
	mp32bcopy(&dst->n, &src->n);
	mp32ncopy(&dst->e, &src->e);
}
