/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define TAGSIZE 16
#define IVSIZE  12
#define KEYSIZE 16
#define SEQSIZE 8

#ifdef WIN32
#include "user_settings.h"
#include <wolfssl/wolfcrypt/aes.h>
#define  AES_CIPHER  Aes
#else
typedef struct AES_CIPHE { char *key;
                         } AES_CIPHER;
//#define byte char
#endif

extern int aesgcm_init(AES_CIPHER* mycipher, char * mykey);
extern int aesgcm_free(AES_CIPHER* mycipher);
extern int aesgcm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);

extern int aesgcm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);


extern int aesccm_init(AES_CIPHER* mycipher, char * mykey);
extern int aesccm_free(AES_CIPHER* mycipher);
extern int aesccm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);
extern int aesccm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);
