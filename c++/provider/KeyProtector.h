#ifndef _CLASS_KEYPROTECTOR_H
#define _CLASS_KEYPROTECTOR_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#include "beecrypt/c++/crypto/interfaces/PBEKey.h"
using beecrypt::crypto::interfaces::PBEKey;
#include "beecrypt/c++/security/PrivateKey.h"
using beecrypt::security::PrivateKey;
#include "beecrypt/c++/security/InvalidKeyException.h"
using beecrypt::security::InvalidKeyException;
#include "beecrypt/c++/security/UnrecoverableKeyException.h"
using beecrypt::security::UnrecoverableKeyException;
#include "beecrypt/c++/security/NoSuchAlgorithmException.h"
using beecrypt::security::NoSuchAlgorithmException;

namespace beecrypt {
	namespace provider {
		class KeyProtector
		{
		private:
			byte _cipher_key[32];
			byte _mac_key[32];
			byte _iv[16];

		public:
			KeyProtector(PBEKey&) throw (InvalidKeyException);
			~KeyProtector() throw ();

			bytearray* protect(const PrivateKey&) throw ();

			PrivateKey* recover(const bytearray&) throw (NoSuchAlgorithmException, UnrecoverableKeyException);
			PrivateKey* recover(const byte*, size_t) throw (NoSuchAlgorithmException, UnrecoverableKeyException);
		};
	}
}

#endif

#endif
