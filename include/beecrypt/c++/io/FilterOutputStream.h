/*
 * Copyright (c) 2004 X-Way Rights BV
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

/*!\file FilterOutputStream.h
 * \ingroup CXX_IO_m
 */

#ifndef _CLASS_BEE_IO_FILTEROUTPUTSTREAM_H
#define _CLASS_BEE_IO_FILTEROUTPUTSTREAM_H

#ifdef __cplusplus

#include "beecrypt/c++/io/OutputStream.h"
using beecrypt::io::OutputStream;

namespace beecrypt {
	namespace io {
		/*!\ingroup CXX_IO_m
		 */
		class BEECRYPTCXXAPI FilterOutputStream : public OutputStream
		{
		protected:
			OutputStream& out;

		public:
			FilterOutputStream(OutputStream& out);
			virtual ~FilterOutputStream();

			virtual void close() throw (IOException);
			virtual void flush() throw (IOException);
			virtual void write(byte b) throw (IOException);
			virtual void write(const byte* data, jint offset, jint length) throw (IOException);
			virtual void write(const bytearray& b) throw (IOException);
		};
	}
}

#endif

#endif
