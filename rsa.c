/*
 * Copyright (c) 2000, 2001, 2002 Virtual Unlimited B.V.
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

/*!\file rsa.c
 * \brief RSA algorithm.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup IF_m IF_rsa_m
 */

#define BEECRYPT_DLL_EXPORT

#include "rsa.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

/*!\addtogroup IF_rsa_m
 * \{
 */

/*!\fn int rsapub(const rsapk* pk, const mpnumber* m, mpnumber* c)
 * \brief The raw RSA public key operation.
 *
 * This function can be used for encryption and verifying.
 *
 * It performs the following operation:
 * \li \f$c=m^{e}\ \testrm{mod}\ \nf$
 *
 * \param pk The RSA public key.
 * \param m The message.
 * \param c The ciphertext.
 * \retval 0 on success.
 * \retval -1 on failure.
 */ 
int rsapub(const rsapk* pk, const mpnumber* m, mpnumber* c)
{
	register size_t size = pk->n.size;
	register mpw* temp;

	if (mpgex(m->size, m->data, pk->n.size, pk->n.modl))
		return -1;

	temp = (mpw*) malloc((4*size+2)*sizeof(mpw));

	if (temp)
	{
		mpnsize(c, size);

		mpbpowmod_w(&pk->n, m->size, m->data, pk->e.size, pk->e.data, c->data, temp);

		return 0;
	}
	return -1;
}


/*!\fn int rsapri(const rsakp* kp, const mpnumber* c, mpnumber* m)
 * \brief The raw RSA private key operation.
 *
 * This function can be used for decryption and signing.
 *
 * It performs the operation:
 * \li \f$m=c^{d}\ \textrm{mod}\ n\f$
 *
 * \param kp The RSA keypair.
 * \param c The ciphertext.
 * \param m The message.
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int rsapri(const rsakp* kp, const mpnumber* c, mpnumber* m)
{
	register size_t size = kp->n.size;
	register mpw* temp;

	if (mpgex(c->size, c->data, kp->n.size, kp->n.modl))
		return -1;

	temp = (mpw*) malloc((4*size+2)*sizeof(mpw));

	if (temp)
	{
		mpnsize(m, size);
		mpbpowmod_w(&kp->n, c->size, c->data, kp->d.size, kp->d.data, m->data, temp);

		free(temp);

		return 0;
	}
	return -1;
}

/*!\fn int rsapricrt(const rsakp* kp, const mpnumber* c, mpnumber* m)
 * \brief The raw RSA private key operation, with Chinese Remainder Theorem.
 *
 * It performs the operation:
 * \li \f$j_1=c^{d_1}\ \textrm{mod}\ p\f$
 * \li \f$j_2=c^{d_2}\ \textrm{mod}\ q\f$
 * \li \f$h=c \cdot (j_1-j_2)\ \textrm{mod}\ p\f$
 * \li \f$m=j_2+hq\f$
 *
 * \param kp The RSA keypair.
 * \param c The ciphertext.
 * \param m The message.
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int rsapricrt(const rsakp* kp, const mpnumber* c, mpnumber* m)
{
	register size_t nsize = kp->n.size;
	register size_t psize = kp->p.size;
	register size_t qsize = kp->q.size;

	register mpw* ptemp;
	register mpw* qtemp;

	if (mpgex(c->size, c->data, kp->n.size, kp->n.modl))
		return -1;

	ptemp = (mpw*) malloc((6*psize+2)*sizeof(mpw));
	if (ptemp == (mpw*) 0)
		return -1;

	qtemp = (mpw*) malloc((6*qsize+2)*sizeof(mpw));
	if (qtemp == (mpw*) 0)
	{
		free(ptemp);
		return -1;
	}

	/* resize c for powmod p */
	mpsetx(psize*2, ptemp, c->size, c->data);

	/* reduce modulo p before we powmod */
	mpbmod_w(&kp->p, ptemp, ptemp+psize, ptemp+2*psize);

	/* compute j1 = c^d1 mod p, store @ ptemp */
	mpbpowmod_w(&kp->p, psize, ptemp+psize, kp->d1.size, kp->d1.data, ptemp, ptemp+2*psize);

	/* resize c for powmod p */
	mpsetx(qsize*2, qtemp, c->size, c->data);

	/* reduce modulo q before we powmod */
	mpbmod_w(&kp->q, qtemp, qtemp+qsize, qtemp+2*qsize);

	/* compute j2 = c^d2 mod q, store @ qtemp */
	mpbpowmod_w(&kp->q, qsize, qtemp+qsize, kp->d2.size, kp->d2.data, qtemp, qtemp+2*qsize);

	/* compute j1-j2 mod p, store @ ptemp */
	mpbsubmod_w(&kp->p, psize, ptemp, qsize, qtemp, ptemp, ptemp+2*psize);

	/* compute h = c*(j1-j2) mod p, store @ ptemp */
	mpbmulmod_w(&kp->p, psize, ptemp, psize, kp->c.data, ptemp, ptemp+2*psize);

	/* make sure the message gets the proper size */
	mpnsize(m, nsize);

	/* compute m = h*q + j2 */
	mpmul(m->data, psize, ptemp, qsize, kp->q.modl);
	mpaddx(nsize, m->data, qsize, qtemp);

	free(ptemp);
	free(qtemp);

	return 0;
}

/*!\fn int rsavrfy(const rsapk* pk, const mpnumber* m, const mpnumber* c)
 *
 * This function verifies if ciphertext \e c was encrypted from cleartext \e m
 * with the private key matching the given public key \e pk.
 *
 * \param pk The public key.
 * \param m The cleartext message.
 * \param c The ciphertext message.
 *
 * \warning The return type of this function should be a boolean, but since
 *          that type isn't as portable, an int is used.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
int rsavrfy(const rsapk* pk, const mpnumber* m, const mpnumber* c)
{
	int rc;
	register size_t size = pk->n.size;
	register mpw* temp;

	if (mpgex(m->size, m->data, pk->n.size, pk->n.modl))
		return -1;

	if (mpgex(c->size, c->data, pk->n.size, pk->n.modl))
		return 0;

	temp = (mpw*) malloc((5*size+2)*sizeof(mpw));

	if (temp)
	{
		mpbpowmod_w(&pk->n, c->size, c->data, pk->e.size, pk->e.data, temp, temp+size);

		rc = mpeqx(size, temp, m->size, m->data);

		free(temp);

		return rc;
	}
	return 0;
}

/*!\}
 */
