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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "beecrypt/c++/provider/DHAESParameters.h"
#include "beecrypt/c++/security/ProviderException.h"
using beecrypt::security::ProviderException;

using namespace beecrypt::provider;

DHAESParameters::DHAESParameters()
{
	_spec = 0;
	_dspec = 0;
}

DHAESParameters::~DHAESParameters()
{
	delete _spec;
	delete _dspec;
}

const bytearray& DHAESParameters::engineGetEncoded(const String* format) throw (IOException)
{
	throw IOException("not implemented");
}

AlgorithmParameterSpec* DHAESParameters::engineGetParameterSpec(const type_info& info) throw (InvalidParameterSpecException)
{
	if (info == typeid(DHAESDecryptParameterSpec))
	{
		if (_dspec)
			return new DHAESDecryptParameterSpec(*_dspec);
	}
	else if (info == typeid(DHAESParameterSpec) || info == typeid(AlgorithmParameterSpec))
	{
		if (_spec)
			return new DHAESParameterSpec(*_spec);
	}
	throw InvalidParameterSpecException();
}

void DHAESParameters::engineInit(const AlgorithmParameterSpec& param) throw (InvalidParameterSpecException)
{
	delete _spec;
	delete _dspec;

	_spec = 0;
	_dspec = 0;

	const DHAESParameterSpec* spec = dynamic_cast<const DHAESParameterSpec*>(&param);
	if (spec)
	{
		_spec = new DHAESParameterSpec(*spec);

		const DHAESDecryptParameterSpec* dspec = dynamic_cast<const DHAESDecryptParameterSpec*>(spec);
		if (dspec)
			_dspec = new DHAESDecryptParameterSpec(*dspec);
	}
	else
		throw InvalidParameterSpecException("Expected a DHAESParameterSpec");
}

void DHAESParameters::engineInit(const byte*, int, const String* format)
{
	throw ProviderException("Not implemented");
}

String DHAESParameters::engineToString() throw ()
{
	if (_dspec)
		return _dspec->toString();
	if (_spec)
		return _spec->toString();

	return String("(uninitialized)");
}
