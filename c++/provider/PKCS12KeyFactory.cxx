#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/beeyond/PKCS12PBEKey.h"
using beecrypt::beeyond::PKCS12PBEKey;
#include "beecrypt/c++/crypto/spec/PBEKeySpec.h"
using beecrypt::crypto::spec::PBEKeySpec;
#include "beecrypt/c++/provider/PKCS12KeyFactory.h"

using namespace beecrypt::provider;

PKCS12KeyFactory::PKCS12KeyFactory()
{
}

PKCS12KeyFactory::~PKCS12KeyFactory()
{
}

SecretKey* PKCS12KeyFactory::engineGenerateSecret(const KeySpec& spec) throw (InvalidKeySpecException)
{
	const PBEKeySpec* pbe = dynamic_cast<const PBEKeySpec*>(&spec);
	if (pbe)
	{
		return new PKCS12PBEKey(pbe->getPassword(), pbe->getSalt(), pbe->getIterationCount());
	}
	throw InvalidKeySpecException("Expected a PBEKeySpec");
}

KeySpec* PKCS12KeyFactory::engineGetKeySpec(const SecretKey& key, const type_info& info) throw (InvalidKeySpecException)
{
	const PBEKey* pbe = dynamic_cast<const PBEKey*>(&key);
	if (pbe)
	{
		if (info == typeid(KeySpec) || info == typeid(PBEKeySpec))
		{
			return new PBEKeySpec(&pbe->getPassword(), pbe->getSalt(), pbe->getIterationCount(), 0);
		}
		throw InvalidKeySpecException("Unsupported KeySpec type");
	}
	throw InvalidKeySpecException("Unsupported SecretKey type");
}

SecretKey* PKCS12KeyFactory::engineTranslateKey(const SecretKey& key) throw (InvalidKeyException)
{
	const PBEKey* pbe = dynamic_cast<const PBEKey*>(&key);
	if (pbe)
	{
		return new PKCS12PBEKey(pbe->getPassword(), pbe->getSalt(), pbe->getIterationCount());
	}
	throw InvalidKeyException("Unsupported SecretKey type");
}
