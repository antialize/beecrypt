/*
 * Copyright (c) 2004 Beeyond Software Holding BV
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

#define BEECRYPT_CXX_DLL_EXPORT

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/beeyond/BeeCertPathValidatorResult.h"
#include "beecrypt/c++/lang/ClassCastException.h"
using beecrypt::lang::ClassCastException;
#include "beecrypt/c++/lang/RuntimeException.h"
using beecrypt::lang::RuntimeException;
#include "beecrypt/c++/security/KeyFactory.h"
using beecrypt::security::KeyFactory;

using namespace beecrypt::beeyond;

BeeCertPathValidatorResult::BeeCertPathValidatorResult(const BeeCertificate& root, const PublicKey& pub)
{
	_root = root.clone();

	// key may not be cloneable, but we can use a KeyFactory to translate it
	KeyFactory* kf;

	try
	{
		kf = KeyFactory::getInstance(pub.getAlgorithm());

		_pub = dynamic_cast<PublicKey*>(kf->translateKey(pub));

		delete kf;

		if (!_pub)
			throw ClassCastException("KeyFactory didn't translate key into a PublicKey");
	}
	catch (NoSuchAlgorithmException)
	{
		throw CloneNotSupportedException("Unable to clone PublicKey through a KeyFactory of type " + pub.getAlgorithm());
	}
	catch (InvalidKeyException)
	{
		delete kf;
		throw CloneNotSupportedException("Unable to clone PublicKey because KeyFactory says it's invalid");
	}
}

BeeCertPathValidatorResult::~BeeCertPathValidatorResult()
{
	delete _root;
	delete _pub;
}

BeeCertPathValidatorResult* BeeCertPathValidatorResult::clone() const throw ()
{
	return new BeeCertPathValidatorResult(*_root, *_pub);
}

const BeeCertificate& BeeCertPathValidatorResult::getRootCertificate() const
{
	return *_root;
}

const PublicKey& BeeCertPathValidatorResult::getPublicKey() const
{
	return *_pub;
}
