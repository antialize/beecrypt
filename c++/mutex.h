#ifndef _CLASS_BEECRYPT_MUTEX_H
#define _CLASS_BEECRYPT_MUTEX_H

#include "beecrypt/api.h"

#ifdef __cplusplus

#if HAVE_ERRNO_H
# include <errno.h>
#endif

namespace beecrypt {
	class BEECRYPTCXXAPI mutex
	{
		private:
			bc_mutex_t _lock;

		public:
			inline void init() throw (char*)
			{
				#if WIN32
				_lock = CreateMutex((LPSECURITY_ATTRIBUTES) 0, FALSE, (LPCSTR) 0);
				if (!_lock)
					throw "CreateMutex failed";
				#else
				register int rc;
				# if HAVE_SYNCH_H
				if ((rc = mutex_init(&_lock, USYNC_THREAD, 0)))
					throw strerror(rc);
				# elif HAVE_PTHREAD_H
				if ((rc = pthread_mutex_init(&_lock, 0)))
					throw strerror(rc);
				# else
				#  error
				# endif
				#endif
			}

			inline void lock() throw (char*)
			{
				#if WIN32
				if (WaitForSingleObject(_lock, INFINITE) == WAIT_OBJECT_0)
					return;
				throw "WaitForSingleObject failed";
				#else
				register int rc;
				# if HAVE_SYNCH_H
				if ((rc = mutex_lock(&_lock)))
					throw strerror(rc);
				# elif HAVE_PTHREAD_H
				if ((rc = pthread_mutex_lock(&_lock)))
					throw strerror(rc);
				# else
				#  error
				# endif
				#endif
			}

			inline bool trylock() throw (char*)
			{
				#if WIN32
				switch (WaitForSingleObject(_lock, 0))
				{
				case WAIT_TIMEOUT:
					return false;
				case WAIT_OBJECT_0:
					return true;
				default:
					throw "WaitForSingleObbject failed";
				}
				#else
				register int rc;
				# if HAVE_SYNCH_H
				if ((rc = mutex_trylock(&_lock)) == 0)
					return true;
				if (rc == EBUSY)
					return false;
				throw strerror(rc);
				# elif HAVE_PTHREAD_H
				if ((rc = pthread_mutex_trylock(&_lock)) == 0)
					return true;
				if (rc == EBUSY)
					return false;
				throw strerror(rc);
				# else
				#  error
				# endif
				#endif
			}

			inline void unlock() throw (char*)
			{
				#if WIN32
				if (!ReleaseMutex(_lock))
					throw "ReleaseMutex failed";
				#else
				register int rc;
				# if HAVE_SYNCH_H
				if ((rc = mutex_unlock(&_lock)))
					throw strerror(rc);
				# elif HAVE_PTHREAD_H
				if ((rc = pthread_mutex_unlock(&_lock)))
					throw strerror(rc);
				# else
				#  error
				# endif
				#endif
			}

			inline void destroy() throw (char*)
			{
				#if WIN32
				if (!CloseHandle(_lock))
					throw "CloseHandle failed";
				#else
				register int rc;
				# if HAVE_SYNCH_H
				if ((rc = mutex_destroy(&_lock)))
					throw strerror(rc);
				# elif HAVE_PTHREAD_H
				if ((rc = pthread_mutex_destroy(&_lock)))
					throw strerror(rc);
				# else
				#  error
				# endif
				#endif
			}
	};
}

#endif

#endif
