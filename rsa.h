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

/*!\file rsa.h
 * \brief RSA algorithm, headers.
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup IF_m IF_rsa_m
 */

#ifndef _RSA_H
#define _RSA_H

#include "rsakp.h"

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int rsapub   (const rsapk* pk, const mp32number* m, mp32number* c);
BEECRYPTAPI
int rsapri   (const rsakp* kp, const mp32number* c, mp32number* m);
BEECRYPTAPI
int rsapricrt(const rsakp* kp, const mp32number* c, mp32number* m);

BEECRYPTAPI
int rsavrfy  (const rsapk* pk, const mp32number* m, const mp32number* c);

#ifdef __cplusplus
}
#endif

#endif
