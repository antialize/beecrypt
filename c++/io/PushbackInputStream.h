/*!\file PushbackInputStream.h
 * \ingroup CXX_IO_m
 */

#ifndef _CLASS_PUSHBACKINPUTSTREAM_H
#define _CLASS_PUSHBACKINPUTSTREAM_H

#ifdef __cplusplus

#include "beecrypt/c++/io/FilterInputStream.h"
using beecrypt::io::FilterInputStream;

namespace beecrypt {
	namespace io {
		class BEECRYPTCXXAPI PushbackInputStream : public FilterInputStream
		{
			private:
				bool _closed;

			protected:
				bytearray buf;
				size_t pos;

			public:
				PushbackInputStream(InputStream& in, size_t size = 1);
				virtual ~PushbackInputStream();

				virtual off_t available() throw (IOException);
				virtual void close() throw (IOException);
				virtual bool markSupported() throw ();
				virtual int read() throw (IOException);
				virtual int read(byte* data, size_t offset, size_t length) throw (IOException);
				virtual off_t skip(off_t n) throw (IOException);

				void unread(byte) throw (IOException);
				void unread(const byte* data, size_t offset, size_t length) throw (IOException);
				void unread(const bytearray& b) throw (IOException);

		};
	}
}

#endif

#endif
