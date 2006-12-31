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

/*!\file FileInputStream.h
 * \ingroup CXX_IO_m
 */

#ifndef _CLASS_BEE_IO_FILEINPUTSTREAM_H
#define _CLASS_BEE_IO_FILEINPUTSTREAM_H

#include <stdio.h>

#ifdef __cplusplus

#include "beecrypt/c++/io/InputStream.h"
using beecrypt::io::InputStream;

namespace beecrypt {
	namespace io {
		/*!\ingroup CXX_IO_m
		 */
		class BEECRYPTCXXAPI FileInputStream : public InputStream
		{
		private:
			FILE* _f;
			long _mark;

		public:
			FileInputStream(FILE* f);
			virtual ~FileInputStream();

			virtual jint available() throw (IOException);
			virtual void close() throw (IOException);
			virtual void mark(jint readlimit) throw ();
			virtual bool markSupported() throw ();
			virtual jint read() throw (IOException);
			virtual jint read(byte* data, jint offset, jint length) throw (IOException);
			virtual jint read(bytearray&) throw (IOException);
			virtual void reset() throw (IOException);
			virtual jint skip(jint n) throw (IOException);
		};
	}
}

#endif

#endif