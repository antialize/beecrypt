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

#include "beecrypt/c++/nio/ByteBuffer.h"

using namespace beecrypt::nio;

ByteBuffer::fakebytearray::~fakebytearray()
{
	_data = 0;
	_size = 0;
}

ByteBuffer::ByteBuffer(size_t capacity) throw (std::bad_alloc) : Buffer(capacity, 0, false)
{
	_data = (byte*) malloc(capacity);
	if (!_data)
		throw std::bad_alloc();

	_fake.set(_data, _capacity);

	_order = &ByteOrder::BIG_ENDIAN;
}

ByteBuffer::~ByteBuffer()
{
	if (_data)
	{
		free(_data);
		_data = 0;
	}
}

ByteBuffer* ByteBuffer::allocateDirect(size_t capacity) throw (std::bad_alloc)
{
	return new ByteBuffer(capacity);
}

bytearray& ByteBuffer::array() throw (ReadOnlyBufferException, UnsupportedOperationException)
{
	if (_readonly)
		throw ReadOnlyBufferException();

	return _fake;
}

const bytearray& ByteBuffer::array() const throw (UnsupportedOperationException)
{
	return _fake;
}

size_t ByteBuffer::arrayOffset() const throw (ReadOnlyBufferException, UnsupportedOperationException)
{
	if (_readonly)
		throw ReadOnlyBufferException();

	return _position;
}

bool ByteBuffer::isDirect() const throw ()
{
	return true;
}

bool ByteBuffer::hasArray() const throw ()
{
	return !_readonly;
}

int ByteBuffer::compareTo(const ByteBuffer& compare) const throw ()
{
	if (_capacity == 0)
	{
		if (compare._capacity == 0)
		{
			return 0;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		if (compare._capacity == 0)
		{
			return 1;
		}
		else if (_capacity == compare._capacity)
		{
			return memcmp(_data, compare._data, _capacity);
		}
		else if (_capacity < compare._capacity)
		{
			if (memcmp(_data, compare._data, _capacity) == 0)
				return 1;
			else
				return -1;
		}
		else
		{
			if (memcmp(_data, compare._data, compare._capacity) == 0)
				return -1;
			else
				return 1;
		}
	}
}

const ByteOrder& ByteBuffer::order() const throw ()
{
	return *_order;
}
