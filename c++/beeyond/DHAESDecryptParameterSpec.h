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

/*!\file DHAESDecryptParameterSpec.h
 * \ingroup CXX_BEEYOND_m
 */

#ifndef _CLASS_DHAESDECRYPTPARAMETERSPEC_H
#define _CLASS_DHAESDECRYPTPARAMETERSPEC_H

#ifdef __cplusplus

#include "beecrypt/c++/beeyond/DHAESParameterSpec.h"
using beecrypt::beeyond::DHAESParameterSpec;

namespace beecrypt {
	namespace beeyond {
		/*!\ingroup CXX_BEEYOND_m
		 */
		class BEECRYPTCXXAPI DHAESDecryptParameterSpec : public beecrypt::beeyond::DHAESParameterSpec
		{
		private:
			BigInteger _pub;
			bytearray _mac;

		public:
			DHAESDecryptParameterSpec(const DHAESParameterSpec& copy, const BigInteger& key, const bytearray& mac);
			DHAESDecryptParameterSpec(const DHAESDecryptParameterSpec& copy);
			virtual ~DHAESDecryptParameterSpec() {}

			const BigInteger& getEphemeralPublicKey() const throw ();
			const bytearray& getMac() const throw ();
		};
	}
}

#endif

#endif
