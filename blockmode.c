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
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup BC_m
 */

#define BEECRYPT_DLL_EXPORT

#include "blockmode.h"

/*!\addtogroup BC_m
 * \{
 */

/*!\fn blockEncryptECB(const blockCipher* bc, blockCipherParam* bp, int count, uint32_t* dst, const uint32_t* src)
 * \brief Encrypts multiple blocks in Electronic Code Book (ECB) mode.
 * \param bc The blockcipher.
 * \param bp The cipher's parameter block.
 * \param nblocks The number of blocks to be encrypted.
 * \param dst The destination (ciphertext data) address; the uint32_t pointer type
 *            is only used for memory alignment purposes.
 * \param src The source (cleartext data) address; the uint32_t pointer type
 *            is only used for memory alignment purposes.
 * \param fdback The feedback (unused by this function).
 * \retval 0 on success.
 * \retval -1 on failure.
 */
int blockEncryptECB(const blockCipher* bc, blockCipherParam* bp, int nblocks, uint32_t* dst, const uint32_t* src)
{
	/* assumes that every blockcipher's blocksize is a multiple of 32 bits */
	register int blockwords = bc->blocksize >> 2;

	while (nblocks > 0)
	{
		bc->encrypt(bp, dst, src);

		dst += blockwords;
		src += blockwords;

		nblocks--;
	}
	return 0;
}

int blockDecryptECB(const blockCipher* bc, blockCipherParam* bp, int nblocks, uint32_t* dst, const uint32_t* src)
{
	/* assumes that every blockcipher's blocksize is a multiple of 32 bits */
	register int blockwords = bc->blocksize >> 2;

	while (nblocks > 0)
	{
		bc->decrypt(bp, dst, src);

		dst += blockwords;
		src += blockwords;

		nblocks--;
	}
	return 0;
}

int blockEncryptCBC(const blockCipher* bc, blockCipherParam* bp, int nblocks, uint32_t* dst, const uint32_t* src)
{
	/* assumes that every blockcipher's blocksize is a multiple of 32 bits */
	register int blockwords = bc->blocksize >> 2;
	register uint32_t* fdback = bc->getfb(bp);

	if (nblocks > 0)
	{
		register int i;

		for (i = 0; i < blockwords; i++)
			dst[i] = src[i] ^ fdback[i];

		bc->encrypt(bp, dst, dst);

		dst += blockwords;
		src += blockwords;

		nblocks--;

		while (nblocks > 0)
		{
			for (i = 0; i < blockwords; i++)
				dst[i] = src[i] ^ dst[i-blockwords];

			bc->encrypt(bp, dst, dst);

			dst += blockwords;
			src += blockwords;

			nblocks--;
		}

		for (i = 0; i < blockwords; i++)
			fdback[i] = dst[i-blockwords];
	}
	return 0;
}

int blockDecryptCBC(const blockCipher* bc, blockCipherParam* bp, int nblocks, uint32_t* dst, const uint32_t* src)
{
	/* assumes that every blockcipher's blocksize is a multiple of 32 bits */
	register int blockwords = bc->blocksize >> 2;
	register uint32_t* fdback = bc->getfb(bp);
	register uint32_t* buf = (uint32_t*) malloc(blockwords * sizeof(uint32_t));

	if (buf)
	{
		while (nblocks > 0)
		{
			register uint32_t tmp;
			register int i;

			bc->decrypt(bp, buf, src);

			for (i = 0; i < blockwords; i++)
			{
				tmp = src[i];
				dst[i] = buf[i] ^ fdback[i];
				fdback[i] = tmp;
			}

			dst += blockwords;
			src += blockwords;

			nblocks--;
		}
		free(buf);
		return 0;
	}
	return -1;
}

/*
int blockEncrypt(const blockCipher* bc, blockCipherParam* bp, cipherMode mode, int blocks, uint32_t* dst, const uint32_t* src)
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

int blockDecrypt(const blockCipher* bc, blockCipherParam* bp, cipherMode mode, int blocks, uint32_t* dst, const uint32_t* src)
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
*/

/*!\}
 */
