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
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup IF_m IF_rsa_m
 */

#define BEECRYPT_DLL_EXPORT

#include "rsa.h"
#include "mp32.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

/*!\addtogroup IF_rsa_m
 * \{
 */

/*!\fn int rsapri(const rsakp* kp, const mp32number* c, mp32number* m)
 * \brief The raw RSA private key operation.
 *
 * This function can be used for encryption and signing.
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
int rsapri(const rsakp* kp, const mp32number* c, mp32number* m)
{
	register uint32  size = kp->n.size;
	register uint32* temp;

	if (mp32gex(c->size, c->data, kp->n.size, kp->n.modl))
		return -1;

	temp = (uint32*) malloc((4*size+2)*sizeof(uint32));

	if (temp)
	{
		mp32nsize(m, size);
		mp32bpowmod_w(&kp->n, c->size, c->data, kp->d.size, kp->d.data, m->data, temp);

		free(temp);

		return 0;
	}
	return -1;
}

/*!\fn int rsapricrt(const rsakp* kp, const mp32number* c, mp32number* m)
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
int rsapricrt(const rsakp* kp, const mp32number* c, mp32number* m)
{
	register uint32  nsize = kp->n.size;
	register uint32  psize = kp->p.size;
	register uint32  qsize = kp->q.size;

	register uint32* ptemp;
	register uint32* qtemp;

	if (mp32gex(c->size, c->data, kp->n.size, kp->n.modl))
		return -1;

	ptemp = (uint32*) malloc((6*psize+2)*sizeof(uint32));
	if (ptemp == (uint32*) 0)
		return -1;

	qtemp = (uint32*) malloc((6*qsize+2)*sizeof(uint32));
	if (qtemp == (uint32*) 0)
	{
		free(ptemp);
		return -1;
	}

	/* c must be small enough to be exponentiated modulo p and q */
	if (c->size > psize || c->size > qsize)
		return -1;

	/* resize c for powmod p */
	mp32setx(psize, ptemp+psize, c->size, c->data);

	/* compute j1 = c^d1 mod p, store @ ptemp */
	mp32bpowmod_w(&kp->p, psize, ptemp+psize, kp->d1.size, kp->d1.data, ptemp, ptemp+2*psize);

	/* resize c for powmod p */
	mp32setx(qsize, qtemp+psize, c->size, c->data);

	/* compute j2 = c^d2 mod q, store @ qtemp */
	mp32bpowmod_w(&kp->q, qsize, qtemp+psize, kp->d2.size, kp->d2.data, qtemp, qtemp+2*qsize);

	/* compute j1-j2 mod p, store @ ptemp */
	mp32bsubmod_w(&kp->p, psize, ptemp, qsize, qtemp, ptemp, ptemp+2*psize);

	/* compute h = c*(j1-j2) mod p, store @ ptemp */
	mp32bmulmod_w(&kp->p, psize, ptemp, psize, kp->c.data, ptemp, ptemp+2*psize);

	/* make sure the message gets the proper size */
	mp32nsize(m, nsize);

	/* compute m = h*q + j2 */
	mp32mul(m->data, psize, ptemp, qsize, kp->q.modl);
	mp32addx(nsize, m->data, qsize, qtemp);

	free(ptemp);
	free(qtemp);

	return 0;
}

/*!\fn int rsavrfy(const rsapk* pk, const mp32number* m, const mp32number* c)
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
int rsavrfy(const rsapk* pk, const mp32number* m, const mp32number* c)
{
	int rc;
	register uint32  size = pk->n.size;
	register uint32* temp;

	if (mp32gex(c->size, c->data, pk->n.size, pk->n.modl))
		return 0;

	temp = (uint32*) malloc((5*size+2)*sizeof(uint32));

	if (temp)
	{
		mp32bpowmod_w(&pk->n, c->size, c->data, pk->e.size, pk->e.data, temp, temp+size);

		rc = mp32eqx(size, temp, m->size, m->data);

		free(temp);

		return rc;
	}
	return 0;
}

/*!\}
 */
