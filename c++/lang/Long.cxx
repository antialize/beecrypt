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

#include "beecrypt/c++/lang/Long.h"

namespace {
	#if WIN32
	__declspec(thread) String* result = 0;
	#else
	# if __GNUC__ && __GNUC_PREREQ (3, 3)
	__thread String* result = 0;
	# else
	#  warning Long::toString() and Long::toHexString methods are not multi-thread safe
	String* result = 0;
	# endif
	#endif
};

using namespace beecrypt::lang;

const javalong Long::MIN_VALUE = -0x8000000000000000L;
const javalong Long::MAX_VALUE =  0x7FFFFFFFFFFFFFFFL;

const String& Long::toString(javalong l) throw ()
{
	char tmp[22];

	#if WIN32
	sprintf(tmp, "%I64d", l);
	#elif SIZE_LONG == 8
	sprintf(tmp, "%ld", l);
	#elif HAVE_LONG_LONG
	sprintf(tmp, "%lld", l);
	#else
	# error
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}

const String& Long::toHexString(javalong l) throw ()
{
	char tmp[17];

	#if WIN32
	sprintf(tmp, "%I64x", l);
	#elif SIZEOF_LONG == 8
	sprintf(tmp, "%lx", l);
	#elif HAVE_LONG_LONG
	sprintf(tmp, "%llx", l);
	#else
	# error
	#endif

	if (result)
		delete result;

	result = new String(tmp);

	return *result;
}
