/*
 * Copyright (c) 2000, 2001, 2002 Virtual Unlimited B.V.
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

/*!\file beecrypt.win.h
 * \brief BeeCrypt API, windows headers.
 * \author Bob Deblier <bob@virtualunlimited.com>
 */

#ifndef _BEECRYPT_WIN_H
#define _BEECRYPT_WIN_H

#define _REENTRANT

#if !defined(_WIN32_WINNT)
#define _WIN32_WINNT 0x0400
#endif

#include <windows.h>

#if __MWERKS__
# if __INTEL__
#  define WORDS_BIGENDIAN		0
# else
#  error Unknown CPU type in MetroWerks CodeWarrior
# endif
#elif defined(_MSC_VER)
# if defined(_M_IX86)
#  define WORDS_BIGENDIAN		0
#  define ROTL32(x, s) _rotl(x, s)
#  define ROTR32(x, s) _rotr(x, s)
# else
#  error Unknown CPU type in Microsoft Visual C
# endif
#else
# error Unknown compiler for WIN32
#endif

#if defined(_MSC_VER) || __MWERKS__
#define HAVE_ERRNO_H			1
#define HAVE_STRING_H			1
#define HAVE_STDLIB_H			1
#define HAVE_CTYPE_H			1
#define HAVE_FCNTL_H			1
#define HAVE_TIME_H				1

#define HAVE_SYS_TYPES_H		0
#define HAVE_SYS_TIME_H			0

#define HAVE_THREAD_H			0
#define HAVE_SYNCH_H			0
#define HAVE_PTHREAD_H			0
#define HAVE_SEMAPHORE_H		0

#define HAVE_TERMIO_H			0
#define HAVE_SYS_AUDIOIO_H		0
#define HAVE_SYS_IOCTL_H		0
#define HAVE_SYS_SOUNDCARD_H	0

#define HAVE_GETTIMEOFDAY		0
#define HAVE_GETHRTIME			0

#define HAVE_DEV_TTY			0
#define HAVE_DEV_AUDIO			0
#define HAVE_DEV_DSP			0
#define HAVE_DEV_RANDOM			0
#define HAVE_DEV_URANDOM		0
#define HAVE_DEV_TTY			0

#else
#error Not set up for this compiler
#endif

#if __MWERKS__
#define HAVE_UNISTD_H			1
#define HAVE_MALLOC_H			1

#define HAVE_SYS_STAT_H			0

#define HAVE_LONG_LONG			1
#define HAVE_UNSIGNED_LONG_LONG	1

#define HAVE_64_BIT_INT			1
#define HAVE_64_BIT_UINT		1

typedef char		int8;
typedef short		int16;
typedef int			int32;
typedef long long	int64;

typedef unsigned char		uint8;
typedef unsigned short		uint16;
typedef unsigned int		uint32;
typedef unsigned long long	uint64;

#elif defined(_MSC_VER)
#define HAVE_UNISTD_H			0
#define HAVE_MALLOC_H			1

#define HAVE_SYS_STAT_H			1

#define HAVE_LONG_LONG			0
#define HAVE_UNSIGNED_LONG_LONG	0

#define HAVE_64_BIT_INT			1
#define HAVE_64_BIT_UINT		1

typedef __int8	int8;
typedef __int16	int16;
typedef __int32	int32;
typedef __int64	int64;

typedef unsigned __int8		uint8;
typedef unsigned __int16	uint16;
typedef unsigned __int32	uint32;
typedef unsigned __int64	uint64;

#endif

typedef float	float4;
typedef double	double8;

#endif
