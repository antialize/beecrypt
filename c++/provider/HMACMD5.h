/*!\file HMACMD5.h
 * \ingroup CXX_PROV_m
 */

#ifndef _CLASS_HMACMD5_H
#define _CLASS_HMACMD5_H

#include "beecrypt/beecrypt.h"
#include "beecrypt/hmacmd5.h"

#ifdef __cplusplus

#include "beecrypt/c++/crypto/MacSpi.h"
using beecrypt::crypto::MacSpi;

namespace beecrypt {
	namespace provider {
		class HMACMD5 : public MacSpi
		{
			private:
				hmacmd5Param _param;
				bytearray _digest;

			protected:
				virtual const bytearray& engineDoFinal();
				virtual size_t engineDoFinal(byte*, size_t, size_t) throw (ShortBufferException);
				virtual size_t engineGetMacLength();
				virtual void engineInit(const Key&, const AlgorithmParameterSpec* spec) throw (InvalidKeyException, InvalidAlgorithmParameterException);
				virtual void engineReset();
				virtual void engineUpdate(byte);
				virtual void engineUpdate(const byte*, size_t, size_t);

			public:
				HMACMD5();
				virtual ~HMACMD5();

				virtual HMACMD5* clone() const;
		};
	}
}

#endif

#endif
