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
#include "beecrypt/c++/provider/SHA256Digest.h"

using namespace beecrypt::provider;

SHA256Digest::SHA256Digest() : _digest(32)
{
	sha256Reset(&_param);
}

SHA256Digest::~SHA256Digest()
{
}

SHA256Digest* SHA256Digest::clone() const
{
	SHA256Digest* result = new SHA256Digest();

	memcpy(&result->_param, &_param, sizeof(sha256Param));

	return result;
}

const bytearray& SHA256Digest::engineDigest()
{
	sha256Digest(&_param, _digest.data());

	return _digest;
}

size_t SHA256Digest::engineDigest(byte* data, size_t offset, size_t length) throw (ShortBufferException)
{
	if (!data)
		throw NullPointerException();

	if (length < 32)
		throw ShortBufferException();

	sha256Digest(&_param, data);

	return 32;
}

size_t SHA256Digest::engineGetDigestLength()
{
	return 32;
}

void SHA256Digest::engineReset()
{
	sha256Reset(&_param);
}

void SHA256Digest::engineUpdate(byte b)
{
	sha256Update(&_param, &b, 1);
}

void SHA256Digest::engineUpdate(const byte* data, size_t offset, size_t length)
{
	sha256Update(&_param, data+offset, length);
}
