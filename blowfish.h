/*
 * Copyright (c) 1999, 2000, 2002 Virtual Unlimited B.V.
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

/*!\file blowfish.h
 * \brief Blowfish block cipher, headers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup BC_m BC_blowfish_m
 */

#ifndef _BLOWFISH_H
#define _BLOWFISH_H

#include "beecrypt.h"
#include "blowfishopt.h"

#define BLOWFISHROUNDS	16
#define BLOWFISHPSIZE	(BLOWFISHROUNDS+2)

/*!\brief This struct holds all the parameters necessary for the Blowfish cipher.
 * \ingroup BC_blowfish_m
 */
typedef struct
{
	/*!\var p
	 * \brief Holds the key expansion.
	 */
	uint32_t p[BLOWFISHPSIZE];
	/*!\var s
	 * \brief Holds the s-boxes.
	 */
	uint32_t s[1024];
	/*!\var fdback
	 * \brief Buffer to be used by block chaining or feedback modes.
	 */
	uint32_t fdback[2];
} blowfishParam;

#ifdef __cplusplus
extern "C" {
#endif

extern const BEECRYPTAPI blockCipher blowfish;

BEECRYPTAPI
int		blowfishSetup   (blowfishParam*, const byte*, size_t, cipherOperation);
BEECRYPTAPI
int		blowfishSetIV   (blowfishParam*, const byte*);
BEECRYPTAPI
int		blowfishEncrypt (blowfishParam*, uint32_t*, const uint32_t*);
BEECRYPTAPI
int		blowfishDecrypt (blowfishParam*, uint32_t*, const uint32_t*);
BEECRYPTAPI
uint32_t*	blowfishFeedback(blowfishParam*);

#ifdef __cplusplus
}
#endif

#endif
