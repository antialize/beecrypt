/*!\file PKCS12KeyFactory.h
 * \ingroup CXX_PROV_m
 */

#ifndef _CLASS_PKCS12KEYFACTORY_H
#define _CLASS_PKCS12KEYFACTORY_H

#ifdef __cplusplus

#include "beecrypt/c++/crypto/SecretKeyFactorySpi.h"
using beecrypt::crypto::SecretKeyFactorySpi;

namespace beecrypt {
	namespace provider {
		class PKCS12KeyFactory : public SecretKeyFactorySpi
		{
			protected:
				virtual SecretKey* engineGenerateSecret(const KeySpec&) throw (InvalidKeySpecException);
				virtual KeySpec* engineGetKeySpec(const SecretKey&, const type_info&) throw (InvalidKeySpecException);
				virtual SecretKey* engineTranslateKey(const SecretKey&) throw (InvalidKeyException);

			public:
				PKCS12KeyFactory();
				virtual ~PKCS12KeyFactory();
		};
	}
}

#endif

#endif
