/*
 * Copyright (c) 2004 Beeyond Software Holding BV
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/lang/NullPointerException.h"
using beecrypt::lang::NullPointerException;
#include "beecrypt/c++/lang/UnsupportedOperationException.h"
using beecrypt::lang::UnsupportedOperationException;
#include "beecrypt/c++/lang/Long.h"
using beecrypt::lang::Long;
#include "beecrypt/c++/crypto/Cipher.h"
using beecrypt::crypto::Cipher;
#include "beecrypt/c++/crypto/SecretKey.h"
using beecrypt::crypto::SecretKey;
#include "beecrypt/c++/crypto/spec/IvParameterSpec.h"
using beecrypt::crypto::spec::IvParameterSpec;
#include "beecrypt/c++/security/ProviderException.h"
using beecrypt::security::ProviderException;
#include "beecrypt/c++/security/Security.h"
using beecrypt::security::Security;
#include "beecrypt/c++/provider/BlockCipher.h"

using namespace beecrypt::provider;

#define BUFFER_SIZE		4096	// must be a whole number of blocks

const int BlockCipher::MODE_ECB = 0;
const int BlockCipher::MODE_CBC = 1;

const int BlockCipher::PADDING_NONE = 0;
const int BlockCipher::PADDING_PKCS5 = 1;

/*!\todo investigate getting buffer size from beecrypt.conf
 */
BlockCipher::BlockCipher(const blockCipher& cipher) : _ctxt(&cipher), _iv(cipher.blocksize)
{
	size_t blocksize = _ctxt.algo->blocksize;

	try
	{
		// check value of property blockcipher.buffer.size in beecrypt.conf
		const String* tmp = Security::getProperty("blockcipher.buffer.size");
		if (tmp)
		{
			// value was configured
			javalong l = Long::parseLong(*tmp);

			if (l <= 1024)
				throw ProviderException("blockcipher.buffer.size must be greater than or equal to 1024");

			if (l % blocksize)
				throw ProviderException("blockcipher.buffer.size is not a multiple of this cipher's blocksize");

			_buffer.resize((size_t) l);
		}
		else
		{
			// no value configured; use 1K blocks
			_buffer.resize(1024 * blocksize);
		}
	}
	catch (NumberFormatException)
	{
		throw ProviderException("blockcipher.buffer.size not set to a numeric value");
	}

	// clear the iv
	memset(_iv.data(), 0, _iv.size());

	_opmode = NOCRYPT;
	_blmode = MODE_ECB;
	_padding = PADDING_NONE;
	_bufcnt = 0;
	_buflwm = 0;

}

BlockCipher::~BlockCipher()
{
}

bytearray* BlockCipher::engineDoFinal(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalBlockSizeException, BadPaddingException)
{
	bytearray* tmp = 0;

	size_t outputLength = engineGetOutputSize(inputLength);

	if (outputLength > 0)
	{
		tmp = new bytearray(outputLength);

		size_t realLength = engineDoFinal(input, inputOffset, inputLength, *tmp, 0);

		// unpadding may have shortened the output
		if (realLength == 0)
		{	// nothing remains
			delete tmp;
			tmp = 0;
		}
		else if (realLength < outputLength)
		{
			tmp->resize(realLength);
		}
	} 

	reset();

	return tmp;
}

size_t BlockCipher::engineDoFinal(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (ShortBufferException, IllegalBlockSizeException, BadPaddingException)
{
	size_t blocksize = _ctxt.algo->blocksize;

	_buflwm = 0;

	size_t total = process(input+inputOffset, inputLength, output.data() + outputOffset, output.size() - outputOffset);

	if ((_padding == PADDING_PKCS5) && (_opmode == Cipher::ENCRYPT_MODE))
	{
		size_t padvalue = _bufcnt % blocksize;

		if (padvalue == 0)
			padvalue = blocksize;

		memset(_buffer.data() + _bufcnt, padvalue, padvalue);

		_bufcnt += padvalue;

		outputOffset += total;

		total += process(0, 0, output.data() + outputOffset, output.size() - outputOffset);
	}

	if (_bufcnt)
		throw BadPaddingException("input is not a whole number of blocks");

	if ((_padding = PADDING_PKCS5) && (_opmode == Cipher::DECRYPT_MODE))
	{	// sanity check: total must be a non-zero whole number of blocks
		const byte* unpad_check = output.data() + outputOffset + total;

		byte unpadvalue = *(--unpad_check);

		if (unpadvalue > blocksize)
			throw BadPaddingException("last padding byte value is greater than blocksize");

		// check all values
		for (byte b = unpadvalue; b > 1; b--)
			if (unpadvalue != *(--unpad_check))
				throw BadPaddingException("not all padding bytes have same value");

		total -= unpadvalue;
	}

	reset();

	return total;
}

size_t BlockCipher::engineGetBlockSize() const throw ()
{
	return _ctxt.algo->blocksize;
}

size_t BlockCipher::engineGetKeySize(const Key& key) const throw (InvalidKeyException)
{
	const SecretKey* secret = dynamic_cast<const SecretKey*>(&key);
	if (secret)
	{
		const String* format = secret->getFormat();

		if (!format)
			throw InvalidKeyException("key has no format");

		if (format->compare("RAW"))
			throw InvalidKeyException("key format isn't RAW");
			
		const bytearray* raw = secret->getEncoded();

		if (!raw)
			throw InvalidKeyException("key contains no data");

		return (raw->size() << 3);
	}
	else
		throw InvalidKeyException("not a SecretKey");
}

size_t BlockCipher::engineGetOutputSize(size_t inputLength) throw ()
{
	size_t total = _bufcnt + inputLength;

	// PKCS5 padding + encryption can add up to (blocksize) bytes
	if ((_padding == PADDING_PKCS5) && (_opmode == Cipher::ENCRYPT_MODE))
	{
		size_t blocksize = _ctxt.algo->blocksize;

		total += blocksize - (total % blocksize);
	}

	return total;
}

bytearray* BlockCipher::engineGetIV()
{
	return new bytearray(_iv);
}

AlgorithmParameters* BlockCipher::engineGetParameters() throw ()
{
	return 0;
}

void BlockCipher::engineInit(int opmode, const Key& key, SecureRandom* random) throw (InvalidKeyException)
{
	_opmode = opmode;

	_keybits = engineGetKeySize(key);

	if (blockCipherContextValidKeylen(&_ctxt, _keybits) <= 0)
		throw InvalidKeyException("unsupported key length");

	_key = *(dynamic_cast<const SecretKey&>(key).getEncoded());

	reset();
}

void BlockCipher::engineInit(int opmode, const Key& key, AlgorithmParameters* params, SecureRandom* random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	engineInit(opmode, key, random);

	if (params)
		throw InvalidAlgorithmParameterException("BlockCipher doesn't support initialization with AlgorithmParameters");
}

void BlockCipher::engineInit(int opmode, const Key& key, AlgorithmParameterSpec* params, SecureRandom* random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	engineInit(opmode, key, random);

	if (params)
	{
		const IvParameterSpec* iv = dynamic_cast<const IvParameterSpec*>(params);
		if (!iv)
			throw InvalidAlgorithmParameterException("BlockCipher only accepts an IvParameterSpec");

		if (iv->getIV().size() != _ctxt.algo->blocksize)
			throw InvalidAlgorithmParameterException("IV length must be equal to blocksize");

		if (blockCipherContextSetIV(&_ctxt, iv->getIV().data()))
			throw ProviderException("BeeCrypt internal error in blockCipherContextSetIV");

		_iv = iv->getIV();
	}
}

bytearray* BlockCipher::engineUpdate(const byte* input, size_t inputOffset, size_t inputLength)
{
	bytearray* tmp = new bytearray(engineGetOutputSize(inputLength));

	size_t total = process(input+inputOffset, inputLength, tmp->data(), tmp->size());

	if (total == 0)
	{
		delete tmp;
		tmp = 0;
	}
	else if (total < tmp->size())
	{
		tmp->resize(total);
	}

	return tmp;
}

size_t BlockCipher::engineUpdate(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (ShortBufferException)
{
	return process(input+inputOffset, inputLength, output.data() + outputOffset, output.size() - outputOffset);
}

void BlockCipher::engineSetMode(const String& mode) throw (NoSuchAlgorithmException)
{
	if (mode.length() == 0 || mode.caseCompare("ECB", 0) == 0)
		_blmode = MODE_ECB;
	else if (mode.caseCompare("CBC", 0) == 0)
		_blmode = MODE_CBC;
	else
		throw NoSuchAlgorithmException();
}

void BlockCipher::engineSetPadding(const String& padding) throw (NoSuchPaddingException)
{
	if (padding.length() == 0 ||
			padding.caseCompare("None", 0) == 0 ||
			padding.caseCompare("NoPadding", 0) == 0)
		_padding = PADDING_NONE;
	else if (padding.caseCompare("PKCS5", 0) == 0 ||
			padding.caseCompare("PKCS#5", 0) == 0 ||
			padding.caseCompare("PKCS5Padding", 0) == 0)
		_padding = PADDING_PKCS5;
	else
		throw NoSuchPaddingException();
}

/*!\brief The core encryption/decryption processing function.
 *        It makes sure that:
 *        - all input and output is properly 32-bit aligned
 *        - at least 'buffer low water mark' bytes remain in the buffer (for unpadding)
 */
size_t BlockCipher::process(const byte* input, size_t inputLength, byte* output, size_t outputLength) throw (ShortBufferException)
{
	size_t blocksize = _ctxt.algo->blocksize;
	size_t total = 0;

	do
	{
		bool copyIn, copyOut;
		const uint32_t *in;
		uint32_t *out;
		size_t blocks;
		size_t bytes;

		copyIn = ((((size_t) input) & 0x3) != 0) || (_bufcnt > 0) || (_bufcnt < _buflwm);
		if (copyIn)
		{
			size_t copy = _buffer.size() - _bufcnt;

			if (copy > inputLength)
				copy = inputLength;

			if (copy)
			{
				memcpy(_buffer.data() + _bufcnt, input, copy);

				_bufcnt += copy;
				input += copy;
				inputLength -= copy;
			}

			blocks = (_bufcnt - _buflwm) / blocksize;

			in = (const uint32_t*) _buffer.data();
		}
		else
		{
			blocks = inputLength / blocksize;

			in = (const uint32_t*) input;
		}
 
		copyOut = (((size_t) output) & 0x3) != 0;
		if (copyOut)
		{
			size_t maxblocks = _buffer.size() / blocksize;

			if (blocks > maxblocks)
				blocks = maxblocks;

			out = (uint32_t*) _buffer.data();
		}
		else
			out = (uint32_t*) output;
		 
		bytes = blocks * blocksize;

		if (bytes > outputLength)
			throw ShortBufferException("BlockCipher output buffer too short");

		switch (_blmode)
		{
		case MODE_ECB:
			blockCipherContextECB(&_ctxt, out, in, blocks);
			break;
		case MODE_CBC:
			blockCipherContextCBC(&_ctxt, out, in, blocks);
			break;
		}

		if (copyOut)
			memcpy(output, out, bytes);

		total += bytes;

		if (_bufcnt > bytes)
		{
			// bytes remain in buffer; move them to the front
			memmove(_buffer.data(), _buffer.data() + _bufcnt, _bufcnt - bytes);
		}

		if (copyIn)
		{
			_bufcnt -= bytes;
		}
		else
		{
			input += bytes;
			inputLength -= bytes;
		}

		output += bytes;
		outputLength -= bytes;

		if (inputLength < (blocksize + _buflwm))
		{
			// less than one block remains; copy it into the buffer
			memcpy(_buffer.data() + _bufcnt, input, inputLength);

			_bufcnt += inputLength;

			inputLength = 0;
		}
	} while (inputLength > 0);

	return total;
}

void BlockCipher::reset()
{
	if (_opmode == Cipher::ENCRYPT_MODE || _opmode == Cipher::DECRYPT_MODE)
	{
		if (blockCipherContextSetup(&_ctxt, _key.data(), _keybits, (cipherOperation) _opmode))
			throw ProviderException("BeeCrypt internal error in blockCipherContextSetup");

		if (_opmode == Cipher::DECRYPT_MODE && _padding == PADDING_PKCS5)
		{
			// keep one block for unpadding
			_buflwm = _ctxt.algo->blocksize;
		}
	}
	else
		throw UnsupportedOperationException("unsupported mode");
}