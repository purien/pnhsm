/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "reentrant.h"

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef WIN32
#include <pthread.h>
#define THREAD_CC     void*
#define THREAD_TYPE                    pthread_t
#define THREAD_CREATE(tid, entry, arg) pthread_create(&(tid), NULL, \
                                                      (entry), (arg))
#else
#include <windows.h>
#include <process.h>    /* _beginthread, _endthread */

#define THREAD_CC                      DWORD WINAPI 
#define THREAD_TYPE                    DWORD

#define THREAD_CREATE(tid, entry, arg) do { CreateThread(NULL,128000L,entry,(LPVOID)arg,0L,&tid);\
                                       } while (0)
#endif

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);

int init_OpenSSL(void);

int verify_callback(int ok, X509_STORE_CTX *store);

void seed_prng(void);


