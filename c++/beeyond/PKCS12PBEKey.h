#ifndef _CLASS_PKCS12PBEKEY_H
#define _CLASS_PKCS12PBEKEY_H

#ifdef __cplusplus

#include "beecrypt/c++/array.h"
using beecrypt::array;
using beecrypt::bytearray;
#include "beecrypt/c++/crypto/interfaces/PBEKey.h"
using beecrypt::crypto::interfaces::PBEKey;

namespace beecrypt {
	namespace beeyond {
		class BEECRYPTCXXAPI PKCS12PBEKey : public PBEKey
		{
			private:
				array<javachar>    _pswd;
				bytearray*         _salt;
				size_t             _iter;
				mutable bytearray* _enc;

			public:
				static bytearray* encode(const array<javachar>&, const bytearray*, size_t);

			public:
				PKCS12PBEKey(const array<javachar>&, const bytearray*, size_t);
				virtual ~PKCS12PBEKey();

				virtual PKCS12PBEKey* clone() const;

				virtual size_t getIterationCount() const throw ();
				virtual const array<javachar>& getPassword() const throw ();
				virtual const bytearray* getSalt() const throw ();

				virtual const bytearray* getEncoded() const;

				virtual const String& getAlgorithm() const throw();
				virtual const String* getFormat() const throw ();
		};
	}
}

#endif

#endif
