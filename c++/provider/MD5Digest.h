/*!\file MD5Digest.h
 * \ingroup CXX_PROV_m
 */

#ifndef _CLASS_MD5DIGEST_H
#define _CLASS_MD5DIGEST_H

#include "beecrypt/beecrypt.h"
#include "beecrypt/md5.h"

#ifdef __cplusplus

#include "beecrypt/c++/security/MessageDigestSpi.h"
using beecrypt::security::MessageDigestSpi;

namespace beecrypt {
	namespace provider {
		class MD5Digest : public MessageDigestSpi
		{
			private:
				md5Param _param;
				bytearray _digest;

			protected:
				virtual const bytearray& engineDigest();
				virtual size_t engineDigest(byte*, size_t, size_t) throw (ShortBufferException);
				virtual size_t engineGetDigestLength();
				virtual void engineReset();
				virtual void engineUpdate(byte);
				virtual void engineUpdate(const byte*, size_t, size_t);

			public:
				MD5Digest();
				virtual ~MD5Digest();

				virtual MD5Digest* clone() const;

		};
	}
}

#endif

#endif
