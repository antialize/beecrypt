/*
 * dlkp.c
 *
 * Discrete Logarithm Keypair, code
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

#include "dlkp.h"

void dlkp_pPair(dlkp_p* kp, randomGeneratorContext* rc, const dldp_p* param)
{
	/* copy the parameters */
	dldp_pCopy(&kp->param, param);

	dldp_pPair(param, rc, &kp->x, &kp->y);
}

void dlkp_pInit(dlkp_p* kp)
{
	dldp_pInit(&kp->param);
	mp32nzero(&kp->y);
	mp32nzero(&kp->x);
}

void dlkp_pFree(dlkp_p* kp)
{
	dldp_pFree(&kp->param);

	mp32nfree(&kp->y);
	mp32nfree(&kp->x);
}

void dlkp_pCopy(dlkp_p* dst, const dlkp_p* src)
{
	dldp_pCopy(&dst->param, &src->param);

	mp32ncopy(&dst->y, &src->y);
	mp32ncopy(&dst->x, &src->x);
}
