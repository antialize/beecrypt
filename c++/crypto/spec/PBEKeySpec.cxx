#define BEECRYPT_CXX_DLL_EXPORT

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/crypto/spec/PBEKeySpec.h"

using namespace beecrypt::crypto::spec;

PBEKeySpec::PBEKeySpec(const array<javachar>* password) : _password(password ? *password : 0)
{
	_salt = 0;
	_iteration_count = 0;
	_key_length = 0;
}

PBEKeySpec::PBEKeySpec(const array<javachar>* password, const bytearray* salt, size_t iterationCount, size_t keyLength) : _password(password ? *password : 0)
{
	if (salt)
		_salt = new bytearray(*salt);
	_iteration_count = iterationCount;
	_key_length = keyLength;
}

PBEKeySpec::~PBEKeySpec()
{
}

const array<javachar>& PBEKeySpec::getPassword() const throw ()
{
	return _password;
}

const bytearray* PBEKeySpec::getSalt() const throw ()
{
	return _salt;
}

size_t PBEKeySpec::getIterationCount() const throw ()
{
	return _iteration_count;
}

size_t PBEKeySpec::getKeyLength() const throw ()
{
	return _key_length;
}
