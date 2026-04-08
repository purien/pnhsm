/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#ifdef COPENSSL
#define MYSHA256_CTX SHA256_CTX
#else
#define MYSHA256_CTX wc_Sha256
#endif
extern char esha256[32] ; // SHA256(EMPTY)
extern int mysha256_dup(MYSHA256_CTX * sha_dest , MYSHA256_CTX * sha_src);
extern int mysha256_init(MYSHA256_CTX * sha);
extern int mysha256_update(MYSHA256_CTX * sha, char *data, int len);
extern int mysha256_final(MYSHA256_CTX * sha, char *result);
extern int  hmac
 ( char *  k32,  int lk,  /* Secret key */
   char *  d, int  ld,    /* data       */
   MYSHA256_CTX * md,
   char *result, 
   int init,
   char * buf160 );
extern int hmacct;