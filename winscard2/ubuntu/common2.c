/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include "common2.h"

void handle_error(const char *file, int lineno, const char *msg)
{
    //ERR_print_errors_fp(stderr);

	#ifdef WIN32  
	    ExitThread(0);
	    
    #else 
    exit(-1);
    #endif
}
    
int init_OpenSSL(void)
{ int err;

  err= THREAD_setup();

    if ( (err == 0) || !SSL_library_init())
	{
        fprintf(stderr, "** OpenSSL initialization failed!\n");
        return -1 ;
    }

    SSL_load_error_strings();
    return 0;
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
 
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int  depth = X509_STORE_CTX_get_error_depth(store);
        int  err = X509_STORE_CTX_get_error(store);
 
        printf("-Error with certificate at depth: %i\n", depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        printf("  issuer   = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        printf("  subject  = %s\n", data);
        printf("  err %i:%s\n", err, X509_verify_cert_error_string(err));
    }
 
    return ok;
}

void seed_prng(void)
{
  RAND_load_file("urandom", 1024);
}
