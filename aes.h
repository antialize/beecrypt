/*
 * Copyright (c) 2002 Bob Deblier
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

/*!\file aes.h
 * \brief AES block cipher, headers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup BC_m BC_aes_m
 */

#ifndef _AES_H
#define _AES_H

#include "beecrypt.h"
#include "aesopt.h"

/*!\brief This struct holds all the parameters necessary for the AES cipher.
 * \ingroup BC_aes_m
 */
typedef struct
{
	/*!\var k
	 * \brief Holds the key expansion.
	 */
	uint32 k[64];
	/*!\var nr
	 * \brief Number of rounds to be used in encryption/decryption.
	 */
	uint32 nr;
	/*!\var fdback
	 * \brief Buffer to be used by block chaining or feedback modes.
	 */
	uint32 fdback[4];
} aesParam;

#ifdef __cplusplus
extern "C" {
#endif

extern const BEECRYPTAPI blockCipher aes;

BEECRYPTAPI
int aesSetup  (aesParam*, const uint32*, int, cipherOperation);
BEECRYPTAPI
int aesSetIV  (aesParam*, const uint32*);
BEECRYPTAPI
int aesEncrypt(aesParam*, uint32*, const uint32*);
BEECRYPTAPI
int aesDecrypt(aesParam*, uint32*, const uint32*);

BEECRYPTAPI
int aesECBEncrypt(aesParam*, int, uint32*, const uint32*);
BEECRYPTAPI
int aesECBDecrypt(aesParam*, int, uint32*, const uint32*);

BEECRYPTAPI
int aesCBCEncrypt(aesParam*, int, uint32*, const uint32*);
BEECRYPTAPI
int aesCBCDecrypt(aesParam*, int, uint32*, const uint32*);

#ifdef __cplusplus
}
#endif

#endif
