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

/*!\file Long.h
 * \ingroup CXX_LANG_m
 */

#ifndef _BEECRYPT_CLASS_LONG_H
#define _BEECRYPT_CLASS_LONG_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/lang/String.h"
using beecrypt::lang::String;

namespace beecrypt {
	namespace lang {
		/*!\brief This subclass of Throwable is used to indicate a serious
		 *        problem, which should not be caught by the application.
		 * \ingroup CXX_LANG_m
		 */
		class BEECRYPTCXXAPI Long
		{
		public:
			static const javalong MIN_VALUE;
			static const javalong MAX_VALUE;

			static const String& toString(javalong l) throw ();
			static const String& toHexString(javalong l) throw ();
		};
	}
}

#endif

#endif