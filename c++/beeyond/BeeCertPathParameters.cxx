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

#include "beecrypt/c++/beeyond/BeeCertPathParameters.h"
#include "beecrypt/c++/beeyond/BeeCertificate.h"

using namespace beecrypt::beeyond;

BeeCertPathParameters::BeeCertPathParameters()
{
}

BeeCertPathParameters::BeeCertPathParameters(KeyStore& keystore) throw (KeyStoreException, InvalidAlgorithmParameterException)
{
	Enumeration* aliases = keystore.aliases();

	while (aliases->hasMoreElements())
	{
		const String* alias = (const String*) aliases->nextElement();

		if (keystore.isCertificateEntry(*alias))
		{
			// only add BeeCertificates
			const BeeCertificate* beecert = dynamic_cast<const BeeCertificate*>(keystore.getCertificate(*alias));

			if (beecert)
				_cert.push_back(beecert);
		}
	}

	if (_cert.size() == 0)
		throw InvalidAlgorithmParameterException("KeyStore doesn't contain any trusted BeeCertificates");
}

const vector<const Certificate*>& BeeCertPathParameters::getTrustedCertificates() const
{
	return _cert;
}

#if 0
CertPathParameters* BeeCertPathParameters::clone() const
{
	BeeCertPathParameters* tmp = new BeeCertPathParameters();

	for (vector<const Certificate*>::const_iterator it = _cert.begin(); it != _cert.end(); it++)
		tmp->_cert.push_back(*it);

	return tmp;
}
#endif
