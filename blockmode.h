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

/*!\file blockmode.h
 * \brief Blockcipher operation modes, headers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup BC_m
 */

#ifndef _BLOCKMODE_H
#define _BLOCKMODE_H

#include "beecrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int blockEncryptECB(const blockCipher*, blockCipherParam*, int, uint32_t*, const uint32_t*);
BEECRYPTAPI
int blockDecryptECB(const blockCipher*, blockCipherParam*, int, uint32_t*, const uint32_t*);

BEECRYPTAPI
int blockEncryptCBC(const blockCipher*, blockCipherParam*, int, uint32_t*, const uint32_t*);
BEECRYPTAPI
int blockDecryptCBC(const blockCipher*, blockCipherParam*, int, uint32_t*, const uint32_t*);

#ifdef __cplusplus
}
#endif

#endif
