/*
 * Copyright (c) 1998, 1999, 2000, 2002 Virtual Unlimited B.V.
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

/*!\file fips186.c
 * \brief FIPS 186 pseudo-random number generator.
 * \author Bob Deblier <bob@virtualunlimited.com>
 * \ingroup PRNG_m PRNG_fips186_m
 */

#define BEECRYPT_DLL_EXPORT

#include "fips186.h"
#include "mp32.h"
#include "mp32opt.h"

#if HAVE_STDLIB_H
# include <stdlib.h>
#endif
#if HAVE_MALLOC_H
# include <malloc.h>
#endif

/*!\addtogroup PRNG_fips186_m
 * \{
 */

static uint32 fips186hinit[5] = { 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0x67452301 };

const randomGenerator fips186prng = { "FIPS 186", sizeof(fips186Param), (const randomGeneratorSetup) fips186Setup, (const randomGeneratorSeed) fips186Seed, (const randomGeneratorNext) fips186Next, (const randomGeneratorCleanup) fips186Cleanup };

static int fips186init(register sha1Param* p)
{
	mp32copy(5, p->h, fips186hinit);
	return 0;
}

int fips186Setup(fips186Param* fp)
{
	if (fp)
	{
		#ifdef _REENTRANT
		# if WIN32
		if (!(fp->lock = CreateMutex(NULL, FALSE, NULL)))
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_init(&fp->lock, USYNC_THREAD, (void *) 0))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_init(&fp->lock, (pthread_mutexattr_t *) 0))
			return -1;
		#  endif
		# endif
		#endif

		fp->digestsize = 0;

		return entropyGatherNext(fp->state, FIPS186_STATE_SIZE);
	}
	return -1;
}

int fips186Seed(fips186Param* fp, const uint32* data, int size)
{
	if (fp)
	{
		#ifdef _REENTRANT
		# if WIN32
		if (WaitForSingleObject(fp->lock, INFINITE) != WAIT_OBJECT_0)
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_lock(&fp->lock))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_lock(&fp->lock))
			return -1;
		#  endif
		# endif
		#endif
		if (data)
			mp32addx(FIPS186_STATE_SIZE, fp->state, size, data);
		#ifdef _REENTRANT
		# if WIN32
		if (!ReleaseMutex(fp->lock))
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_unlock(&fp->lock))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_unlock(&fp->lock))
			return -1;
		#  endif
		# endif
		#endif
		return 0;
	}
	return -1;
}

int fips186Next(fips186Param* fp, uint32* data, int size)
{
	if (fp)
	{
		#ifdef _REENTRANT
		# if WIN32
		if (WaitForSingleObject(fp->lock, INFINITE) != WAIT_OBJECT_0)
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_lock(&fp->lock))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_lock(&fp->lock))
			return -1;
		#  endif
		# endif
		#endif
		while (size > 0)
		{
			register uint32 copy;

			if (fp->digestsize == 0)
			{
				fips186init(&fp->param);
				/* copy the 512 bits of state data into the sha1Param */
				mp32copy(FIPS186_STATE_SIZE, fp->param.data, fp->state);
				/* process the data */
				sha1Process(&fp->param);
				/* set state to state + digest + 1 mod 2^512 */
				mp32addx(FIPS186_STATE_SIZE, fp->state, 5, fp->param.h);
				mp32addw(FIPS186_STATE_SIZE, fp->state, 1);
				/* we now have 5 words of pseudo-random data */
				fp->digestsize = 5;
			}

			copy = (size > fp->digestsize) ? fp->digestsize : size;
			mp32copy(copy, data, fp->param.h + 5 - fp->digestsize);
			fp->digestsize -= copy;
			size -= copy;
			data += copy;
		}
		#ifdef _REENTRANT
		# if WIN32
		if (!ReleaseMutex(fp->lock))
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_unlock(&fp->lock))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_unlock(&fp->lock))
			return -1;
		#  endif
		# endif
		#endif
		return 0;
	}
	return -1;
}

int fips186Cleanup(fips186Param* fp)
{
	if (fp)
	{
		#ifdef _REENTRANT
		# if WIN32
		if (!CloseHandle(fp->lock))
			return -1;
		# else
		#  if HAVE_THREAD_H && HAVE_SYNCH_H
		if (mutex_destroy(&fp->lock))
			return -1;
		#  elif HAVE_PTHREAD_H
		if (pthread_mutex_destroy(&fp->lock))
			return -1;
		#  endif
		# endif
		#endif
		return 0;
	}
	return -1;
}

/*!\}
 */
