/*
 * Copyright (c) 2001, 2002 Virtual Unlimited B.V.
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

/*!\file beecrypt.api.h
 * \brief BeeCrypt API, portability headers.
 * \author Bob Deblier <bob@virtualunlimited.com>
 */

#ifndef _BEECRYPT_API_H
#define _BEECRYPT_API_H

#if defined(_WIN32) && !defined(WIN32)
# define WIN32 1
#endif

#if WIN32 && !__CYGWIN32__
# include "beecrypt.win.h"
# ifdef BEECRYPT_DLL_EXPORT
#  define BEECRYPTAPI __declspec(dllexport)
# else
#  define BEECRYPTAPI __declspec(dllimport)
# endif
#else
# include "beecrypt.gnu.h"
# include "beecrypt.gnu.types.h"
# define BEECRYPTAPI
#endif

#ifndef ROTL32
# define ROTL32(x, s) (((x) << (s)) | ((x) >> (32 - (s))))
#endif
#ifndef ROTR32
# define ROTR32(x, s) (((x) >> (s)) | ((x) << (32 - (s))))
#endif

typedef int8	javabyte;
typedef int16	javashort;
typedef int32	javaint;
typedef int64	javalong;

typedef uint16	javachar;

typedef float4	javafloat;
typedef double8	javadouble;

#endif
