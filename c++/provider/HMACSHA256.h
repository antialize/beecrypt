/*!\file HMACSHA256.h
 * \ingroup CXX_PROV_m
 */

#ifndef _CLASS_HMACSHA256_H
#define _CLASS_HMACSHA256_H

#include "beecrypt/beecrypt.h"
#include "beecrypt/hmacsha256.h"

#ifdef __cplusplus

#include "beecrypt/c++/crypto/MacSpi.h"
using beecrypt::crypto::MacSpi;

namespace beecrypt {
	namespace provider {
		class HMACSHA256 : public MacSpi
		{
			private:
				hmacsha256Param _param;
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
				HMACSHA256();
				virtual ~HMACSHA256();

				virtual HMACSHA256* clone() const;
		};
	}
}

#endif

#endif
