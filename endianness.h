/*
 * endianness.h
 *
 * Endian-dependant encoding/decoding, header
 *
 * Copyright (c) 1998, 1999, 2000, 2001 Virtual Unlimited B.V.
 *
 * Author: Bob Deblier <bob@virtualunlimited.com>
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

#ifndef _ENDIANNESS_H
#define _ENDIANNESS_H

#include "beecrypt.h"

#include <stdio.h>

#ifdef __cplusplus
inline int16 swap16(int16 n)
{
	return (    ((n & 0xff) << 8) |
				((n & 0xff00) >> 8) );
}

inline uint16 swapu16(uint16 n)
{
	return (    ((n & 0xffU) << 8) |
				((n & 0xff00U) >> 8) );
}

inline int32 swap32(int32 n)
{
	#if (SIZEOF_LONG == 4)
	return (    ((n & 0xff) << 24) |
				((n & 0xff00) << 8) |
				((n & 0xff0000) >> 8) |
				((n & 0xff000000) >> 24) );
	#else
	return (    ((n & 0xffL) << 24) |
				((n & 0xff00L) << 8) |
				((n & 0xff0000L) >> 8) |
				((n & 0xff000000L) >> 24) );
	#endif
}

inline uint32 swapu32(uint32 n)
{
	#if (SIZEOF_UNSIGNED_LONG == 4)
	return (    ((n & 0xffU) << 24) |
				((n & 0xff00U) << 8) |
				((n & 0xff0000U) >> 8) |
				((n & 0xff000000U) >> 24) );
	#else
	return (    ((n & 0xffUL) << 24) |
				((n & 0xff00UL) << 8) |
				((n & 0xff0000UL) >> 8) |
				((n & 0xff000000UL) >> 24) );
	#endif
}

inline int64 swap64(int64 n)
{
	#if HAVE_LONG_LONG
	return (    ((n & 0xffLL) << 56) |
				((n & 0xff00LL) << 40) |
				((n & 0xff0000LL) << 24) |
				((n & 0xff000000LL) << 8) |
				((n & 0xff00000000LL) >> 8) |
				((n & 0xff0000000000LL) >> 24) |
				((n & 0xff000000000000LL) >> 40) |
				((n & 0xff00000000000000LL) >> 56) );
	#else
	return (    ((n & 0xffL) << 56) |
				((n & 0xff00L) << 40) |
				((n & 0xff0000L) << 24) |
				((n & 0xff000000L) << 8) |
				((n & 0xff00000000L) >> 8) |
				((n & 0xff0000000000L) >> 24) |
				((n & 0xff000000000000L) >> 40) |
				((n & 0xff00000000000000L) >> 56) );
	#endif
}
#else
 int16 swap16 (int16);
uint16 swapu16(uint16);
 int32 swap32 (int32);
uint32 swapu32(uint32);
 int64 swap64 (int64);
#endif

#ifdef __cplusplus
extern "C" {
#endif

BEECRYPTAPI
int encodeByte(javabyte, byte*);
BEECRYPTAPI
int encodeShort(javashort, byte*);
BEECRYPTAPI
int encodeInt(javaint, byte*);

BEECRYPTAPI
int encodeLong(javalong, byte*);
BEECRYPTAPI
int encodeChar(javachar, byte*);
BEECRYPTAPI
int encodeFloat(javafloat, byte*);
BEECRYPTAPI
int encodeDouble(javadouble, byte*);

BEECRYPTAPI
int encodeInts(const javaint*, byte*, int);
BEECRYPTAPI
int encodeIntsPartial(const javaint*, byte*, int);
BEECRYPTAPI
int encodeChars(const javachar*, byte*, int);

BEECRYPTAPI
int decodeByte(javabyte*, const byte*);
BEECRYPTAPI
int decodeShort(javashort*, const byte*);
BEECRYPTAPI
int decodeInt(javaint*, const byte*);
BEECRYPTAPI
int decodeLong(javalong*, const byte*);
BEECRYPTAPI
int decodeChar(javachar*, const byte*);
BEECRYPTAPI
int decodeFloat(javafloat*, const byte*);
BEECRYPTAPI
int decodeDouble(javadouble*, const byte*);

BEECRYPTAPI
int decodeInts(javaint*, const byte*, int);
BEECRYPTAPI
int decodeIntsPartial(javaint*, const byte*, int);
BEECRYPTAPI
int decodeChars(javachar*, const byte*, int);

BEECRYPTAPI
int writeByte(javabyte, FILE*);
BEECRYPTAPI
int writeShort(javashort, FILE*);
BEECRYPTAPI
int writeInt(javaint, FILE*);
BEECRYPTAPI
int writeLong(javalong, FILE*);
BEECRYPTAPI
int writeChar(javachar, FILE*);

BEECRYPTAPI
int writeInts(const javaint*, FILE*, int);
BEECRYPTAPI
int writeChars(const javachar*, FILE*, int);

BEECRYPTAPI
int readByte(javabyte*, FILE*);
BEECRYPTAPI
int readShort(javashort*, FILE*);
BEECRYPTAPI
int readInt(javaint*, FILE*);
BEECRYPTAPI
int readLong(javalong*, FILE*);
BEECRYPTAPI
int readChar(javachar*, FILE*);

BEECRYPTAPI
int readInts(javaint*, FILE*, int);
BEECRYPTAPI
int readChars(javachar*, FILE*, int);

#ifdef __cplusplus
}
#endif

#endif
