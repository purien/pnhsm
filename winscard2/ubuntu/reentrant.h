/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#ifndef REENTRANT_H
#define REENTRANT_H

#ifndef WIN32
  #include <unistd.h>
  #include <pthread.h>
  #include <stdlib.h>
  #include <openssl/crypto.h>
 
#else
  #include <windows.h>
#endif

#if defined(WIN32)
    #define MUTEX_TYPE HANDLE
    #define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
    #define MUTEX_CLEANUP(x) CloseHandle(x)
    #define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
    #define MUTEX_UNLOCK(x) ReleaseMutex(x)
    #define THREAD_ID GetCurrentThreadId( )
	#define TYPESIZE sizeof(HANDLE)

#elif defined(_POSIX_THREADS)
    /* _POSIX_THREADS is normally defined in unistd.h if pthreads are available
       on your platform. */
    #define MUTEX_TYPE pthread_mutex_t
    #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
    #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
    #define THREAD_ID pthread_self( )
	#define TYPESIZE sizeof(MUTEX_TYPE)

#else
    #error You must define mutex operations appropriate for your platform!
#endif

extern MUTEX_TYPE *Pmutex ;

extern int MutexSetup(int nb);
extern int Mutex_cleanup(int nb);

extern int THREAD_setup(void);
extern int THREAD_cleanup(void);

#endif /* REENTRANT_H */