/*
 * Copyright (c) 2000, 2002 Virtual Unlimited B.V.
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

/*!\file rsakp.c
 * \brief RSA keypair.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup IF_m IF_rsa_m
 */

#define BEECRYPT_DLL_EXPORT

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "rsakp.h"
#include "mpprime.h"

/*!\addtogroup IF_rsa_m
 * \{
 */

int rsakpMake(rsakp* kp, randomGeneratorContext* rgc, size_t bits)
{
	/* 
	 * Generates an RSA Keypair for use with the Chinese Remainder Theorem
	 */

	size_t pbits = (bits+1) >> 1;
	size_t qbits = (bits - pbits);
	size_t nsize = MP_BITS_TO_WORDS(bits+MP_WBITS-1);
	size_t psize = MP_BITS_TO_WORDS(pbits+MP_WBITS-1);
	size_t qsize = MP_BITS_TO_WORDS(qbits+MP_WBITS-1);
	size_t pqsize = psize+qsize;
	mpw* temp = (mpw*) malloc((16*pqsize+6)*sizeof(mpw));

	if (temp)
	{
		mpbarrett psubone, qsubone;
		mpnumber phi, min;
		mpw* divmod = temp;
		mpw* dividend = divmod+nsize+1;
		mpw* workspace = dividend+nsize+1;
		int shift;

		/* set e */
		mpnsetw(&kp->e, 65537);

		/* generate a random prime p */
		mpprnd_w(&kp->p, rgc, pbits, mpptrials(pbits), &kp->e, temp);

		/* find out how big q should be */
		shift = MP_WORDS_TO_BITS(nsize) - bits;
		mpzero(nsize, dividend);
		dividend[0] |= MP_MSBMASK;
		dividend[nsize-1] |= MP_LSBMASK;
		mpndivmod(divmod, nsize+1, dividend, psize, kp->p.modl, workspace);
		mprshift(nsize+1, divmod, shift);

		mpnzero(&min);
		mpnset(&min, nsize+1-psize, divmod);

		/* generate a random prime q, with min/max constraints */
		if (mpprndr_w(&kp->q, rgc, qbits, mpptrials(qbits), &min, (mpnumber*) 0, &kp->e, temp))
		{
			/* shouldn't happen */
			mpnfree(&min);
			free(temp);
			return -1;
		}

		mpnfree(&min);

		mpbzero(&psubone);
		mpbzero(&qsubone);
		mpnzero(&phi);

		/* set n = p*q, with appropriate size (pqsize may be > nsize) */
		mpmul(temp, psize, kp->p.modl, qsize, kp->q.modl);
		mpbset(&kp->n, nsize, temp+pqsize-nsize);

		/* compute p-1 */
		mpbsubone(&kp->p, temp);
		mpbset(&psubone, psize, temp);

		/* compute q-1 */
		mpbsubone(&kp->q, temp);
		mpbset(&qsubone, qsize, temp);

		/* compute phi = (p-1)*(q-1) */
		mpmul(temp, psize, psubone.modl, qsize, qsubone.modl);
		mpnset(&phi, nsize, temp);

		/* compute d = inv(e) mod phi */
		mpninv(&kp->d, &kp->e, &phi);

		/* compute d1 = d mod (p-1) */
		mpnsize(&kp->d1, psize);
		mpbmod_w(&psubone, kp->d.data, kp->d1.data, temp);

		/* compute d2 = d mod (q-1) */
		mpnsize(&kp->d2, qsize);
		mpbmod_w(&qsubone, kp->d.data, kp->d2.data, temp);

		/* compute c = inv(q) mod p */
		mpninv(&kp->c, (mpnumber*) &kp->q, (mpnumber*) &kp->p);

		free(temp);

		return 0;
	}
	return -1;
}

int rsakpInit(rsakp* kp)
{
	memset(kp, 0, sizeof(rsakp));
	/* or
	mpbzero(&kp->n);
	mpnzero(&kp->e);
	mpnzero(&kp->d);
	mpbzero(&kp->p);
	mpbzero(&kp->q);
	mpnzero(&kp->d1);
	mpnzero(&kp->d2);
	mpnzero(&kp->c);
	*/

	return 0;
}

int rsakpFree(rsakp* kp)
{
	/* wipe all secret key components */
	mpbfree(&kp->n);
	mpnfree(&kp->e);
	mpnwipe(&kp->d);
	mpnfree(&kp->d);
	mpbwipe(&kp->p);
	mpbfree(&kp->p);
	mpbwipe(&kp->q);
	mpbfree(&kp->q);
	mpnwipe(&kp->d1);
	mpnfree(&kp->d1);
	mpnwipe(&kp->d2);
	mpnfree(&kp->d2);
	mpnwipe(&kp->c);
	mpnfree(&kp->c);

	return 0;
}

int rsakpCopy(rsakp* dst, const rsakp* src)
{
	mpbcopy(&dst->n, &src->n);
	mpncopy(&dst->e, &src->e);
	mpncopy(&dst->d, &src->d);
	mpbcopy(&dst->p, &src->p);
	mpbcopy(&dst->q, &src->q);
	mpncopy(&dst->d1, &src->d1);
	mpncopy(&dst->d2, &src->d2);
	mpncopy(&dst->c, &src->c);

	return 0;
}

/*!\}
 */
