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

#include "beecrypt/c++/lang/Integer.h"
using beecrypt::lang::Integer;
#include "beecrypt/c++/lang/StringBuilder.h"
using beecrypt::lang::StringBuilder;

using namespace beecrypt::beeyond;

DHAESParameterSpec::DHAESParameterSpec(const DHAESParameterSpec& copy)
{
	_messageDigestAlgorithm = copy._messageDigestAlgorithm;
	_cipherAlgorithm = copy._cipherAlgorithm;
	_macAlgorithm = copy._macAlgorithm;

	_cipherKeyLength = copy._cipherKeyLength;
	_macKeyLength = copy._macKeyLength;
}

DHAESParameterSpec::DHAESParameterSpec(const String& messageDigestAlgorithm, const String& cipherAlgorithm, const String& macAlgorithm, int cipherKeyLength, int macKeyLength)
{
	if (cipherKeyLength < 0 || macKeyLength < 0)
		throw IllegalArgumentException("key lengths must be >= 0");

	if (cipherKeyLength & 0x3 || macKeyLength & 0x3)
		throw IllegalArgumentException("key lengths must be a multiple of 8 bits");

	if (cipherKeyLength == 0 && macKeyLength != 0)
		throw IllegalArgumentException("if cipherKeyLength equals 0, then macKeyLength must also be 0");

	_messageDigestAlgorithm = messageDigestAlgorithm;
	_cipherAlgorithm = cipherAlgorithm;
	_macAlgorithm = macAlgorithm;

	_cipherKeyLength = cipherKeyLength;
	_macKeyLength = macKeyLength;
}

const String& DHAESParameterSpec::getCipherAlgorithm() const throw ()
{
	return _cipherAlgorithm;
}

int DHAESParameterSpec::getCipherKeyLength() const throw ()
{
	return _cipherKeyLength;
}

const String& DHAESParameterSpec::getMacAlgorithm() const throw ()
{
	return _macAlgorithm;
}

int DHAESParameterSpec::getMacKeyLength() const throw ()
{
	return _macKeyLength;
}

const String& DHAESParameterSpec::getMessageDigestAlgorithm() const throw ()
{
	return _messageDigestAlgorithm;
}

String DHAESParameterSpec::toString() const throw ()
{
	StringBuilder tmp("DHAES(");

	tmp.append(_messageDigestAlgorithm).append(',').append(_cipherAlgorithm).append(',').append(_macAlgorithm);

	if (_macKeyLength)
	{
		tmp.append(',').append(Integer::toString(_cipherKeyLength));
		tmp.append(',').append(Integer::toString(_macKeyLength));
	}
	else if (_cipherKeyLength)
	{
		tmp.append(',').append(Integer::toString(_cipherKeyLength));
	}

	return tmp.append(')').toString();
}
