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

#define BEECRYPT_CXX_DLL_EXPORT

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/crypto/Cipher.h"
#include "beecrypt/c++/security/Security.h"
using beecrypt::security::Security;

#include <unicode/regex.h>

using namespace beecrypt::crypto;

namespace {
	RegexPattern* _amppat = 0;
}

const int Cipher::ENCRYPT_MODE = 1;
const int Cipher::DECRYPT_MODE = 2;
const int Cipher::WRAP_MODE = 3;
const int Cipher::UNWRAP_MODE = 4;

Cipher::Cipher(CipherSpi* spi, const String& transformation, const Provider& provider)
{
	_cspi = spi;
	_algo = transformation;
	_prov = &provider;
	_init = false;
}

Cipher::~Cipher()
{
	delete _cspi;
}

Cipher* Cipher::getInstance(const String& transformation) throw (NoSuchAlgorithmException, NoSuchPaddingException)
{
	UErrorCode status = U_ZERO_ERROR;

	if (!_amppat)
	{
		UParseError error;

		_amppat = RegexPattern::compile("(\\w+)(?:/(\\w*))?(?:/(\\w+))?", error, status);
		// shouldn't happen
		if (U_FAILURE(status))
			throw RuntimeException("ICU regex compilation problem");
	}

	RegexMatcher *m = _amppat->matcher(transformation, status);

	if (m->matches(status))
	{
		Security::spi* tmp;
		Cipher* result;

		// Step 1: try to find complete transformation
		try
		{
			tmp = Security::getSpi(transformation, "Cipher");

			result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

			delete tmp;

			return result;
		}
		catch (NoSuchAlgorithmException)
		{
			// no problem yet
		}

		String algorithm, mode, padding;

		algorithm = m->group(1, status);
		mode = m->group(2, status);
		padding = m->group(3, status);

		// clean up the matcher; we don't need it anymore
		delete m;

		// Step 2: try to find algorithm/mode
		if (mode.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "/" + mode, "Cipher");

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (padding.length())
				{
					try
					{
						result->_cspi->engineSetPadding(padding);
					}
					catch (NoSuchPaddingException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 3: try to find algorithm//padding
		if (padding.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "//" + padding, "Cipher");

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (mode.length())
				{
					try
					{
						result->_cspi->engineSetMode(mode);
					}
					catch (NoSuchAlgorithmException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 4: try to find algorithm
		tmp = Security::getSpi(algorithm, "Cipher");

		result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

		delete tmp;

		if (mode.length())
		{
			try
			{
				result->_cspi->engineSetMode(mode);
			}
			catch (NoSuchAlgorithmException)
			{
				delete result;
				throw;
			}
		}

		if (padding.length())
		{
			try
			{
				result->_cspi->engineSetPadding(padding);
			}
			catch (NoSuchPaddingException)
			{
				delete result;
				throw;
			}
		}

		return result;
	}
	else
		throw NoSuchAlgorithmException("Incorrect Algorithm/Mode/Padding syntax");
}

Cipher* Cipher::getInstance(const String& transformation, const String& provider) throw (NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException)
{
	UErrorCode status = U_ZERO_ERROR;

	if (!_amppat)
	{
		UParseError error;

		_amppat = RegexPattern::compile("(\\w+)(?:/(\\w*))?(?:/(\\w+))?", error, status);
		// shouldn't happen
		if (U_FAILURE(status))
			throw RuntimeException("ICU regex compilation problem");
	}

	RegexMatcher *m = _amppat->matcher(transformation, status);

	if (m->matches(status))
	{
		Security::spi* tmp;
		Cipher* result;

		// Step 1: try to find complete transformation
		try
		{
			tmp = Security::getSpi(transformation, "Cipher", provider);

			result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

			delete tmp;

			return result;
		}
		catch (NoSuchAlgorithmException)
		{
			// no problem yet
		}

		String algorithm, mode, padding;

		algorithm = m->group(1, status);
		mode = m->group(2, status);
		padding = m->group(3, status);

		// clean up the matcher; we don't need it anymore
		delete m;

		// Step 2: try to find algorithm/mode
		if (mode.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "/" + mode, "Cipher", provider);

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (padding.length())
				{
					try
					{
						result->_cspi->engineSetPadding(padding);
					}
					catch (NoSuchPaddingException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 3: try to find algorithm//padding
		if (padding.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "//" + padding, "Cipher", provider);

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (mode.length())
				{
					try
					{
						result->_cspi->engineSetMode(mode);
					}
					catch (NoSuchAlgorithmException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 4: try to find algorithm
		tmp = Security::getSpi(algorithm, "Cipher", provider);

		result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

		delete tmp;

		if (mode.length())
		{
			try
			{
				result->_cspi->engineSetMode(mode);
			}
			catch (NoSuchAlgorithmException)
			{
				delete result;
				throw;
			}
		}

		if (padding.length())
		{
			try
			{
				result->_cspi->engineSetPadding(padding);
			}
			catch (NoSuchPaddingException)
			{
				delete result;
				throw;
			}
		}

		return result;
	}
	else
		throw NoSuchAlgorithmException("Incorrect Algorithm/Mode/Padding syntax");
}

Cipher* Cipher::getInstance(const String& transformation, const Provider& provider) throw (NoSuchAlgorithmException, NoSuchPaddingException)
{
	UErrorCode status = U_ZERO_ERROR;

	if (!_amppat)
	{
		UParseError error;

		_amppat = RegexPattern::compile("(\\w+)(?:/(\\w*))?(?:/(\\w+))?", error, status);
		// shouldn't happen
		if (U_FAILURE(status))
			throw RuntimeException("ICU regex compilation problem");
	}

	RegexMatcher *m = _amppat->matcher(transformation, status);

	if (m->matches(status))
	{
		Security::spi* tmp;
		Cipher* result;

		// Step 1: try to find complete transformation
		try
		{
			tmp = Security::getSpi(transformation, "Cipher", provider);

			result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

			delete tmp;

			return result;
		}
		catch (NoSuchAlgorithmException)
		{
			// no problem yet
		}

		String algorithm, mode, padding;

		algorithm = m->group(1, status);
		mode = m->group(2, status);
		padding = m->group(3, status);

		// clean up the matcher; we don't need it anymore
		delete m;

		// Step 2: try to find algorithm/mode
		if (mode.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "/" + mode, "Cipher", provider);

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (padding.length())
				{
					try
					{
						result->_cspi->engineSetPadding(padding);
					}
					catch (NoSuchPaddingException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 3: try to find algorithm//padding
		if (padding.length())
		{
			try
			{
				tmp = Security::getSpi(algorithm + "//" + padding, "Cipher", provider);

				result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

				delete tmp;

				if (mode.length())
				{
					try
					{
						result->_cspi->engineSetMode(mode);
					}
					catch (NoSuchAlgorithmException)
					{
						delete result;
						throw;
					}
				}

				return result;
			}
			catch (NoSuchAlgorithmException)
			{
				// no problem yet
			}
		}

		// Step 4: try to find algorithm
		tmp = Security::getSpi(algorithm, "Cipher", provider);

		result = new Cipher((CipherSpi*) tmp->cspi, tmp->name, tmp->prov);

		delete tmp;

		if (mode.length())
		{
			try
			{
				result->_cspi->engineSetMode(mode);
			}
			catch (NoSuchAlgorithmException)
			{
				delete result;
				throw;
			}
		}

		if (padding.length())
		{
			try
			{
				result->_cspi->engineSetPadding(padding);
			}
			catch (NoSuchPaddingException)
			{
				delete result;
				throw;
			}
		}

		return result;
	}
	else
		throw NoSuchAlgorithmException("Incorrect Algorithm/Mode/Padding syntax");
}

bytearray* Cipher::doFinal() throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineDoFinal(0, 0, 0);
}

bytearray* Cipher::doFinal(const bytearray& input) throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineDoFinal(input.data(), 0, input.size());
}

size_t Cipher::doFinal(bytearray& output, size_t outputOffset) throw (IllegalStateException, IllegalBlockSizeException, ShortBufferException, BadPaddingException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineDoFinal(0, 0, 0, output, outputOffset);
}

bytearray* Cipher::doFinal(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalStateException, IllegalBlockSizeException, BadPaddingException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineDoFinal(input, inputOffset, inputLength);
}

size_t Cipher::doFinal(byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (IllegalStateException, IllegalBlockSizeException, ShortBufferException, BadPaddingException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineDoFinal(input, inputOffset, inputLength, output, outputOffset);
}

size_t Cipher::getBlockSize() const throw ()
{
	return _cspi->engineGetBlockSize();
}

bytearray* Cipher::getIV()
{
	return _cspi->engineGetIV();
}

size_t Cipher::getOutputSize(size_t inputLength) throw ()
{
	return _cspi->engineGetOutputSize(inputLength);
}

const String& Cipher::getAlgorithm() const throw ()
{
	return _algo;
}

const Provider& Cipher::getProvider() const throw ()
{
	return *_prov;
}

void Cipher::init(int opmode, const Certificate& certificate, SecureRandom* random) throw (InvalidKeyException)
{
	_cspi->engineInit(opmode, certificate.getPublicKey(), random);

	_init = true;
}

void Cipher::init(int opmode, const Key& key, SecureRandom* random) throw (InvalidKeyException)
{
	_cspi->engineInit(opmode, key, random);

	_init = true;
}

void Cipher::init(int opmode, const Key& key, AlgorithmParameters* params, SecureRandom* random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	_cspi->engineInit(opmode, key, params, random);

	_init = true;
}

void Cipher::init(int opmode, const Key& key, AlgorithmParameterSpec* params, SecureRandom* random) throw (InvalidKeyException, InvalidAlgorithmParameterException)
{
	_cspi->engineInit(opmode, key, params, random);

	_init = true;
}

bytearray* Cipher::update(const bytearray& input) throw (IllegalStateException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineUpdate(input.data(), 0, input.size());
}

bytearray* Cipher::update(const byte* input, size_t inputOffset, size_t inputLength) throw (IllegalStateException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineUpdate(input, inputOffset, inputLength);
}

size_t Cipher::update(const byte* input, size_t inputOffset, size_t inputLength, bytearray& output, size_t outputOffset) throw (IllegalStateException, ShortBufferException)
{
	if (!_init)
		throw IllegalStateException("Cipher not initialized");

	return _cspi->engineUpdate(input, inputOffset, inputLength, output, outputOffset);
}
