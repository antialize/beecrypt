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

/*!\file blockmode.c
 * \brief Blockcipher operation modes.
 * \todo Additional modes, such as CFB and OFB.
 * \todo Add generic routines, instead of specific ones for each algorithm.
 *       The latter mode can stay for optimized functions, for instance if
 *       they're written in assembler.
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup BC_m
 */

#define BEECRYPT_DLL_EXPORT

#include "blockmode.h"
#include "mp32.h"

/*!\addtogroup BC_m
 * \{
 */

int blockEncrypt(const blockCipher* bc, blockCipherParam* bp, cipherMode mode, int blocks, uint32* dst, const uint32* src)
{
	if (bc->mode)
	{
		register const blockMode* bm = bc->mode+mode;

		if (bm)
		{
			register const blockModeEncrypt be = bm->encrypt;

			if (be)
				return be(bp, blocks, dst, src);
		}
	}

	return -1;
}

int blockDecrypt(const blockCipher* bc, blockCipherParam* bp, cipherMode mode, int blocks, uint32* dst, const uint32* src)
{
	if (bc->mode)
	{
		register const blockMode* bm = bc->mode+mode;

		if (bm)
		{
			register const blockModeEncrypt bd = bm->decrypt;

			if (bd)
				return bd(bp, blocks, dst, src);
		}
	}

	return -1;
}

/*!\}
 */
