/*
 * Copyright (c) 2001, 2002 Virtual Unlimited B.V.
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

/*!\file dsa.c
 * \brief Digital Signature Algorithm, as specified by NIST FIPS 186.
 *
 * FIPS 186 specifies the DSA algorithm as having a large prime \f$p\f$,
 * a cofactor \f$q\f$ and a generator \f$g\f$ of a subgroup of
 * \f$\mathds{Z}^{*}_p\f$ with order \f$q\f$. The private and public key
 * values are \f$x\f$ and \f$y\f$ respectively.
 *
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup DL_m DL_dsa_m
 */
 
#define BEECRYPT_DLL_EXPORT

#include "dsa.h"
#include "dldp.h"
#include "mp32.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

/*!\addtogroup DL_dsa_m
 * \{
 */

/*!\fn int dsasign(const mp32barrett* p, const mp32barrett* q, const mp32number* g, randomGeneratorContext* rgc, const mp32number* hm, const mp32number* x, mp32number* r, mp32number* s)
 * \brief The raw DSA signing function.
 *
 * Signing equations:
 *
 * \li \f$r=(g^{k}\ \textrm{mod}\ p)\ \textrm{mod}\ q\f$
 * \li \f$s=k^{-1}(h(m)+xr)\ \textrm{mod}\ q\f$
 *
 * \param p The prime.
 * \param q The cofactor.
 * \param g The generator.
 * \param rgc The pseudo-random generator context.
 * \param hm The hash to be signed.
 * \param x The private key value.
 * \param r The signature's \e r value.
 * \param s The signature's \e r value.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int dsasign(const mp32barrett* p, const mp32barrett* q, const mp32number* g, randomGeneratorContext* rgc, const mp32number* hm, const mp32number* x, mp32number* r, mp32number* s)
{
	register uint32  psize = p->size;
	register uint32  qsize = q->size;

	register uint32* ptemp;
	register uint32* qtemp;

	register uint32* pwksp;
	register uint32* qwksp;

	register int rc = -1;

	ptemp = (uint32*) malloc((5*psize+2)*sizeof(uint32));
	if (ptemp == (uint32*) 0)
		return rc;

	qtemp = (uint32*) malloc((9*qsize+6)*sizeof(uint32));
	if (qtemp == (uint32*) 0)
	{
		free(ptemp);
		return rc;
	}

	pwksp = ptemp+psize;
	qwksp = qtemp+3*qsize;

	/* allocate r */
	mp32nfree(r);
	mp32nsize(r, qsize);

	/* get a random k, invertible modulo q */
	mp32brndinv_w(q, rgc, qtemp, qtemp+qsize, qwksp);

	/* g^k mod p */
	mp32bpowmod_w(p, g->size, g->data, qsize, qtemp, ptemp, pwksp);

	/* (g^k mod p) mod q - simple modulo */
	mp32nmod(qtemp+2*qsize, psize, ptemp, qsize, q->modl, pwksp);
	mp32copy(qsize, r->data, qtemp+psize+qsize);

	/* allocate s */
	mp32nfree(s);
	mp32nsize(s, qsize);

	/* x*r mod q */
	mp32bmulmod_w(q, x->size, x->data, r->size, r->data, qtemp, qwksp);

	/* add h(m) mod q */
	mp32baddmod_w(q, qsize, qtemp, hm->size, hm->data, qtemp+2*qsize, qwksp);

	/* multiply inv(k) mod q */
	mp32bmulmod_w(q, qsize, qtemp+qsize, qsize, qtemp+2*qsize, s->data, qwksp);

	rc = 0;

	free(qtemp);
	free(ptemp);

	return rc;
}

/*!\fn int dsavrfy(const mp32barrett* p, const mp32barrett* q, const mp32number* g, const mp32number* hm, const mp32number* y, const mp32number* r, const mp32number* s)
 * \brief The raw DSA verification function.
 *
 * Verifying equations:
 * \li Check \f$0<r<q\f$ and \f$0<s<q\f$
 * \li \f$w=s^{-1}\ \textrm{mod}\ q\f$
 * \li \f$u_1=w \cdot h(m)\ \textrm{mod}\ q\f$
 * \li \f$u_2=rw\ \textrm{mod}\ q\f$
 * \li \f$v=(g^{u_1}y^{u_2}\ \textrm{mod}\ p)\ \textrm{mod}\ q\f$
 * \li Check \f$v=r\f$
 *
 * \param p The prime.
 * \param q The cofactor.
 * \param g The generator.
 * \param hm The digest to be verified.
 * \param y The public key value.
 * \param r The signature's r value.
 * \param s The signature's r value.
 *
 * \warning The return type of this function should be a boolean, but since
 *          that type isn't as portable, an int is used.
 *
 * \retval 0 on failure.
 * \retval 1 on success.
 */
int dsavrfy(const mp32barrett* p, const mp32barrett* q, const mp32number* g, const mp32number* hm, const mp32number* y, const mp32number* r, const mp32number* s)
{
	register uint32  psize = p->size;
	register uint32  qsize = q->size;

	register uint32* ptemp;
	register uint32* qtemp;

	register uint32* pwksp;
	register uint32* qwksp;

	register int rc = 0;

	if (mp32z(r->size, r->data))
		return rc;

	if (mp32gex(r->size, r->data, qsize, q->modl))
		return rc;

	if (mp32z(s->size, s->data))
		return rc;

	if (mp32gex(s->size, s->data, qsize, q->modl))
		return rc;

	ptemp = (uint32*) malloc((6*psize+2)*sizeof(uint32));
	if (ptemp == (uint32*) 0)
		return rc;

	qtemp = (uint32*) malloc((8*qsize+6)*sizeof(uint32));
	if (qtemp == (uint32*) 0)
	{
		free(ptemp);
		return rc;
	}

	pwksp = ptemp+2*psize;
	qwksp = qtemp+2*qsize;

	/* compute w = inv(s) mod q */
	if (mp32binv_w(q, s->size, s->data, qtemp, qwksp))
	{
		/* compute u1 = h(m)*w mod q */
		mp32bmulmod_w(q, hm->size, hm->data, qsize, qtemp, qtemp+qsize, qwksp);

		/* compute u2 = r*w mod q */
		mp32bmulmod_w(q, r->size, r->data, qsize, qtemp, qtemp, qwksp);

		/* compute g^u1 mod p */
		mp32bpowmod_w(p, g->size, g->data, qsize, qtemp+qsize, ptemp, pwksp);

		/* compute y^u2 mod p */
		mp32bpowmod_w(p, y->size, y->data, qsize, qtemp, ptemp+psize, pwksp);

		/* multiply mod p */
		mp32bmulmod_w(p, psize, ptemp, psize, ptemp+psize, ptemp, pwksp);

		/* modulo q */
		mp32nmod(ptemp+psize, psize, ptemp, qsize, q->modl, pwksp);

		rc = mp32eqx(r->size, r->data, psize, ptemp+psize);
	}

	free(qtemp);
	free(ptemp);

	return rc;
}
