/*
 * Copyright (c) 2003 Bob Deblier
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
 *
 */

/*!\file mpnumber.c
 * \brief Multi-precision numbers.
 * \author Bob Deblier <bob.deblier@pandora.be>
 * \ingroup MP_m
 */

#define BEECRYPT_DLL_EXPORT

#if HAVE_CONFIG_H
# include "config.h"
#endif

#include "mpnumber.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

void mpnzero(mpnumber* n)
{
	n->size = 0;
	n->data = (mpw*) 0;
}

void mpnsize(mpnumber* n, size_t size)
{
	if (size)
	{
		if (n->data)
		{
			if (n->size != size)
				n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
		}
		else
			n->data = (mpw*) malloc(size * sizeof(mpw));

		if (n->data == (mpw*) 0)
			n->size = 0;
		else
			n->size = size;

	}
	else if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
		n->size = 0;
	}
}

void mpninit(mpnumber* n, size_t size, const mpw* data)
{
	n->size = size;
	n->data = (mpw*) malloc(size * sizeof(mpw));

	if (n->data)
		mpcopy(size, n->data, data);
}

void mpnfree(mpnumber* n)
{
	if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
	}
	n->size = 0;
}

void mpncopy(mpnumber* n, const mpnumber* copy)
{
	mpnset(n, copy->size, copy->data);
}

void mpnwipe(mpnumber* n)
{
	mpzero(n->size, n->data);
}

void mpnset(mpnumber* n, size_t size, const mpw* data)
{
	if (size)
	{
		if (n->data)
		{
			if (n->size != size)
				n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
		}
		else
			n->data = (mpw*) malloc(size * sizeof(mpw));

		if (n->data)
			mpcopy(n->size = size, n->data, data);
		else
			n->size = 0;
	}
	else if (n->data)
	{
		free(n->data);
		n->data = (mpw*) 0;
		n->size = 0;
	}
}

void mpnsetw(mpnumber* n, mpw val)
{
	if (n->data)
	{
		if (n->size != 1)
			n->data = (mpw*) realloc(n->data, sizeof(mpw));
	}
	else
		n->data = (mpw*) malloc(sizeof(mpw));

	if (n->data)
	{
		n->size = 1;
		n->data[0] = val;
	}
	else
		n->size = 0;
}

void mpnsethex(mpnumber* n, const char* hex)
{
	register size_t len = strlen(hex);
	register size_t size = MP_NIBBLES_TO_WORDS(len + MP_WNIBBLES - 1);

	if (n->data)
	{
		if (n->size != size)
			n->data = (mpw*) realloc(n->data, size * sizeof(mpw));
	}
	else
		n->data = (mpw*) malloc(size * sizeof(mpw));

	if (n->data)
	{
		n->size = size;

		hs2ip(n->data, size, hex, len);
	}
	else
		n->size = 0;
}

int mpninv_w(const mpnumber* n, size_t xsize, const mpw* xdata, mpw* result, mpw* wksp)
{
	/*
	 * Fact: if a element of Zn, then a is invertible if and only if gcd(a,n) = 1
	 * Hence: if n->data is even, then x must be odd, otherwise the gcd(x,n) >= 2
	 *
	 * The calling routine must guarantee this condition.
	 */

	register size_t size = n->size;
	register int full;

	mpw* udata = wksp;
	mpw* vdata = udata+size+1;
	mpw* adata = vdata+size+1;
	mpw* bdata = adata+size+1;
	mpw* cdata = bdata+size+1;
	mpw* ddata = cdata+size+1;

	mpsetx(size+1, udata, size, n->data);
	mpsetx(size+1, vdata, xsize, xdata);
	mpzero(size+1, bdata);
	mpsetw(size+1, ddata, 1);

	if ((full = mpeven(size+1, udata)))
	{
		mpsetw(size+1, adata, 1);
		mpzero(size+1, cdata);
	}

	while (1)
	{
		while (mpeven(size+1, udata))
		{
			mpdivtwo(size+1, udata);

			if ((full && mpodd(size+1, adata)) || mpodd(size+1, bdata))
			{
				if (full) mpaddx(size+1, adata, xsize, xdata);
				mpsubx(size+1, bdata, size, n->data);
			}

			if (full) mpsdivtwo(size+1, adata);
			mpsdivtwo(size+1, bdata);
		}
		while (mpeven(size+1, vdata))
		{
			mpdivtwo(size+1, vdata);

			if ((full && mpodd(size+1, cdata)) || mpodd(size+1, ddata))
			{
				if (full) mpaddx(size+1, cdata, xsize, xdata);
				mpsubx(size+1, ddata, size, n->data);
			}

			if (full) mpsdivtwo(size+1, cdata);
			mpsdivtwo(size+1, ddata);
		}
		if (mpge(size+1, udata, vdata))
		{
			mpsub(size+1, udata, vdata);
			if (full) mpsub(size+1, adata, cdata);
			mpsub(size+1, bdata, ddata);
		}
		else
		{
			mpsub(size+1, vdata, udata);
			if (full) mpsub(size+1, cdata, adata);
			mpsub(size+1, ddata, bdata);
		}

		if (mpz(size+1, udata))
		{
			if (mpisone(size+1, vdata))
			{
				if (result)
				{
					mpsetx(size, result, size+1, ddata);
					if (*ddata & MP_MSBMASK)
					{
						/* keep adding the modulus until we get a carry */
						while (!mpadd(size, result, n->data));
					}
				}
				return 1;
			}
			return 0;
		}
	}
}

int mpninv(mpnumber* inv, const mpnumber* k, const mpnumber* mod)
{
	int rc = 0;
	mpw* wksp = (mpw*) malloc((6*mod->size+6) * sizeof(mpw));

	if (wksp)
	{
		mpnsize(inv, mod->size);
		rc = mpninv_w(mod, k->size, k->data, inv->data, wksp);
		free(wksp);
	}

	return rc;
}
