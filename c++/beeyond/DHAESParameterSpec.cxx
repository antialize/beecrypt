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

#include "beecrypt/c++/beeyond/DHAESParameterSpec.h"

using namespace beecrypt::beeyond;

DHAESParameterSpec::DHAESParameterSpec(const DHAESParameterSpec& copy) : DHParameterSpec(copy), _mac(copy._mac)
{
	_messageDigestAlgorithm = copy._messageDigestAlgorithm;
	_cipherAlgorithm = copy._cipherAlgorithm;
	_macAlgorithm = copy._macAlgorithm;

	_cipherKeyLength = copy._cipherKeyLength;
	_macKeyLength = copy._macKeyLength;

	_y = copy._y;
}

DHAESParameterSpec::DHAESParameterSpec(const DHParams& params, const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength, size_t macKeyLength) : DHParameterSpec(params), _mac()
{
	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;
}

DHAESParameterSpec::DHAESParameterSpec(const DHParameterSpec& spec, const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength, size_t macKeyLength) : DHParameterSpec(spec), _mac()
{
	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;
}

DHAESParameterSpec::DHAESParameterSpec(const DHPublicKey& pub, const bytearray& mac, const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, size_t cipherKeyLength, size_t macKeyLength) : DHParameterSpec(pub.getParams()), _mac(mac)
{
	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;

	_y = pub.getY();
}

DHAESParameterSpec::~DHAESParameterSpec()
{
}

const String& DHAESParameterSpec::getCipherAlgorithm() const throw ()
{
	return _cipherAlgorithm;
}

size_t DHAESParameterSpec::getCipherKeyLength() const throw ()
{
	return _cipherKeyLength;
}

const String& DHAESParameterSpec::getMacAlgorithm() const throw ()
{
	return _macAlgorithm;
}

size_t DHAESParameterSpec::getMacKeyLength() const throw ()
{
	return _macKeyLength;
}

const String& DHAESParameterSpec::getMessageDigestAlgorithm() const throw ()
{
	return _messageDigestAlgorithm;
}

const mpnumber& DHAESParameterSpec::getEphemeralPublicKey() const throw ()
{
	return _y;
}

const bytearray& DHAESParameterSpec::getMac() const throw ()
{
	return _mac;
}
