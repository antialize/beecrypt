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
#include "beecrypt/c++/provider/SHA512Digest.h"

using namespace beecrypt::provider;

SHA512Digest::SHA512Digest() : _digest(64)
{
	sha512Reset(&_param);
}

SHA512Digest::~SHA512Digest()
{
}

SHA512Digest* SHA512Digest::clone() const
{
	SHA512Digest* result = new SHA512Digest();

	memcpy(&result->_param, &_param, sizeof(sha512Param));

	return result;
}

const bytearray& SHA512Digest::engineDigest()
{
	sha512Digest(&_param, _digest.data());

	return _digest;
}

size_t SHA512Digest::engineDigest(byte* data, size_t offset, size_t length) throw (ShortBufferException)
{
	if (!data)
		throw NullPointerException();

	if (length < 64)
		throw ShortBufferException();

	sha512Digest(&_param, data);

	return 64;
}

size_t SHA512Digest::engineGetDigestLength()
{
	return 64;
}

void SHA512Digest::engineReset()
{
	sha512Reset(&_param);
}

void SHA512Digest::engineUpdate(byte b)
{
	sha512Update(&_param, &b, 1);
}

void SHA512Digest::engineUpdate(const byte* data, size_t offset, size_t length)
{
	sha512Update(&_param, data+offset, length);
}
