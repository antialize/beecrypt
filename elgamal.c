/*
 * Copyright (c) 1999, 2000, 2001, 2002 Virtual Unlimited B.V.
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
 
/*!\file elgamal.c
 * \brief ElGamal algorithm.
 *
 * For more information on this algorithm, see:
 *  "Handbook of Applied Cryptography",
 *  11.5.2: "The ElGamal signature scheme", p. 454-459
 *
 * Two of the signature variants in Note 11.70 are described.
 *
 * \todo Explore the possibility of using simultaneous multiple exponentiation,
 *       as described in HAC, 14.87 (iii).
 *
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup DL_m DL_elgamal_m
 */

#define BEECRYPT_DLL_EXPORT

#include "elgamal.h"
#include "dldp.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

/*!\addtogroup DL_elgamal_m
 * \{
 */

/*!\fn int elgv1sign(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, randomGeneratorContext* rgc, const mpnumber* hm, const mpnumber* x, mpnumber* r, mpnumber* s)
 * \brief The raw ElGamal signing funcion, variant 1.
 *
 * Signing equations:
 *
 * \li \f$r=g^{k}\ \textrm{mod}\ p\f$
 * \li \f$s=k^{-1}(h(m)-xr)\ \textrm{mod}\ (p-1)\f$
 *
 * \param p The prime.
 * \param n The reducer mod (p-1).
 * \param g The generator.
 * \param rgc The pseudo-random generat
 * \param hm The hash to be signed.
 * \param x The private key value.
 * \param r The signature's \e r value.
 * \param s The signature's \e r value.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int elgv1sign(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, randomGeneratorContext* rgc, const mpnumber* hm, const mpnumber* x, mpnumber* r, mpnumber* s)
{
	register size_t size = p->size;
	register mpw* temp = (mpw*) malloc((8*size+6)*sizeof(mpw));

	if (temp)
	{
		/* get a random k, invertible modulo (p-1) */
		mpbrndinv_w(n, rgc, temp, temp+size, temp+2*size);

		/* compute r = g^k mod p */
		mpnfree(r);
		mpnsize(r, size);
		mpbpowmod_w(p, g->size, g->data, size, temp, r->data, temp+2*size);

		/* compute x*r mod n */
		mpbmulmod_w(n, x->size, x->data, r->size, r->data, temp, temp+2*size);

		/* compute -(x*r) mod n */
		mpneg(size, temp);
		mpadd(size, temp, n->modl);

		/* compute h(m) - x*r mod n */
		mpbaddmod_w(n, hm->size, hm->data, size, temp, temp, temp+2*size);

		/* compute s = inv(k)*(h(m) - x*r) mod n */
		mpnfree(s);
		mpnsize(s, size);
		mpbmulmod_w(n, size, temp, size, temp+size, s->data, temp+2*size);

		free(temp);

		return 0;
	}
	return -1;
}

/*!\fn int elgv1vrfy(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, const mpnumber* hm, const mpnumber* y, const mpnumber* r, const mpnumber* s)
 * \brief The raw ElGamal verification funcion, variant 1.
 *
 * Verifying equations:
 *
 * \li Check \f$0<r<p\f$ and \f$0<s<(p-1)\f$
 * \li \f$v_1=y^{r}r^{s}\ \textrm{mod}\ p\f$
 * \li \f$v_2=g^{h(m)}\ \textrm{mod}\ p\f$
 * \li Check \f$v_1=v_2\f$
 *
 * \param p The prime.
 * \param n The reducer mod (p-1).
 * \param g The generator.
 * \param hm The hash to be signed.
 * \param y The public key value.
 * \param r The signature's \e r value.
 * \param s The signature's \e r value.
 *
 * \warning The return type of this function should be a boolean, but since
 *          that type isn't as portable, an int is used.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int elgv1vrfy(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, const mpnumber* hm, const mpnumber* y, const mpnumber* r, const mpnumber* s)
{
	register size_t size = p->size;
	register mpw* temp;

	if (mpz(r->size, r->data))
		return 0;

	if (mpgex(r->size, r->data, size, p->modl))
		return 0;

	if (mpz(s->size, s->data))
		return 0;

	if (mpgex(s->size, s->data, n->size, n->modl))
		return 0;

	temp = (mpw*) malloc((6*size+2)*sizeof(mpw));

	if (temp)
	{
		register int rc;

		/* compute u1 = y^r mod p */
		mpbpowmod_w(p, y->size, y->data, r->size, r->data, temp, temp+2*size);

		/* compute u2 = r^s mod p */
		mpbpowmod_w(p, r->size, r->data, s->size, s->data, temp+size, temp+2*size);

		/* compute v1 = u1*u2 mod p */
		mpbmulmod_w(p, size, temp, size, temp+size, temp+size, temp+2*size);

		/* compute v2 = g^h(m) mod p */
		mpbpowmod_w(p, g->size, g->data, hm->size, hm->data, temp, temp+2*size);

		rc = mpeq(size, temp, temp+size);

		free(temp);

		return rc;
	}
	return 0;
}

/*!\fn int elgv3sign(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, randomGeneratorContext* rgc, const mpnumber* hm, const mpnumber* x, mpnumber* r, mpnumber* s)
 * \brief The raw ElGamal signing funcion, variant 3.
 *
 * Signing equations:
 *
 * \li \f$r=g^{k}\ \textrm{mod}\ p\f$
 * \li \f$s=xr+kh(m)\ \textrm{mod}\ (p-1)\f$
 *
 * \param p The prime.
 * \param n The reducer mod (p-1).
 * \param g The generator.
 * \param rgc The pseudo-random generat
 * \param hm The hash to be signed.
 * \param x The private key value.
 * \param r The signature's \e r value.
 * \param s The signature's \e r value.
 *
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int elgv3sign(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, randomGeneratorContext* rgc, const mpnumber* hm, const mpnumber* x, mpnumber* r, mpnumber* s)
{
	register size_t size = p->size;
	register mpw* temp = (mpw*) malloc((6*size+2)*sizeof(mpw));

	if (temp)
	{
		/* get a random k */
		mpbrnd_w(p, rgc, temp, temp+2*size);

		/* compute r = g^k mod p */
		mpnfree(r);
		mpnsize(r, size);
		mpbpowmod_w(p, g->size, g->data, size, temp, r->data, temp+2*size);

		/* compute u1 = x*r mod n */
		mpbmulmod_w(n, x->size, x->data, size, r->data, temp+size, temp+2*size);

		/* compute u2 = k*h(m) mod n */
		mpbmulmod_w(n, size, temp, hm->size, hm->data, temp, temp+2*size);

		/* compute s = u1+u2 mod n */
		mpnfree(s);
		mpnsize(s, n->size);
		mpbaddmod_w(n, size, temp, size, temp+size, s->data, temp+2*size);

		free(temp);

		return 0;
	}
	return -1;
}

/*!\fn int elgv3vrfy(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, const mpnumber* hm, const mpnumber* y, const mpnumber* r, const mpnumber* s)
 * \brief The raw ElGamal verification funcion, variant 3.
 *
 * Verifying equations:
 *
 * \li Check \f$0<r<p\f$ and \f$0<s<(p-1)\f$
 * \li \f$v_1=g^{s}\ \textrm{mod}\ p\f$
 * \li \f$v_2=y^{r}r^{h(m)}\ \textrm{mod}\ p\f$
 * \li Check \f$v_1=v_2\f$
 *
 * \param p The prime.
 * \param n The reducer mod (p-1).
 * \param g The generator.
 * \param hm The hash to be signed.
 * \param y The public key value.
 * \param r The signature's \e r value.
 * \param s The signature's \e r value.
 *
 * \warning The return type of this function should be a boolean, but since
 *          that type isn't as portable, an int is used.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int elgv3vrfy(const mpbarrett* p, const mpbarrett* n, const mpnumber* g, const mpnumber* hm, const mpnumber* y, const mpnumber* r, const mpnumber* s)
{
	register size_t size = p->size;
	register mpw* temp;

	if (mpz(r->size, r->data))
		return 0;

	if (mpgex(r->size, r->data, size, p->modl))
		return 0;

	if (mpz(s->size, s->data))
		return 0;

	if (mpgex(s->size, s->data, n->size, n->modl))
		return 0;

	temp = (mpw*) malloc((6*size+2)*sizeof(mpw));

	if (temp)
	{
		register int rc;

		/* compute u1 = y^r mod p */
		mpbpowmod_w(p, y->size, y->data, r->size, r->data, temp, temp+2*size);

		/* compute u2 = r^h(m) mod p */
		mpbpowmod_w(p, r->size, r->data, hm->size, hm->data, temp+size, temp+2*size);

		/* compute v2 = u1*u2 mod p */
		mpbmulmod_w(p, size, temp, size, temp+size, temp+size, temp+2*size);

		/* compute v1 = g^s mod p */
		mpbpowmod_w(p, g->size, g->data, s->size, s->data, temp, temp+2*size);

		rc = mpeq(size, temp, temp+size);

		free(temp);

		return rc;
	}
	return 0;
}

/*!\}
 */
