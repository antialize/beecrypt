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

#include "beecrypt/c++/beeyond/BeeCertPath.h"

using namespace beecrypt::beeyond;

BeeCertPath::BeeCertPath(const BeeCertificate& cert) : CertPath("BEE")
{
	_cert.push_back(&cert);
}

BeeCertPath::~BeeCertPath()
{
}

bool BeeCertPath::operator==(const CertPath& compare) const
{
	const BeeCertPath* cmp = dynamic_cast<const BeeCertPath*>(&compare);
	if (cmp)
	{
		return *(_cert[0]) == *(cmp->_cert[0]);
	}
	return false;
}

const vector<const Certificate*>& BeeCertPath::getCertificates() const
{
	return _cert;
}

const bytearray& BeeCertPath::getEncoded() const
{
	return _cert[0]->getEncoded();
}