/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */


#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <malloc.h>

#ifdef WIN32
#include "crypto2.h"
#else
#include "crypto.h"
#endif

#include "aead.h"
#include "util.h"


int aesgcm_init(AES_CIPHER* mycipher, char * mykey);
int aesgcm_free(AES_CIPHER* mycipher);
int aesgcm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);

int aesgcm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);


int aesccm_init(AES_CIPHER* mycipher, char * mykey);
int aesccm_free(AES_CIPHER* mycipher);
int aesccm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);
int aesccm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);



#ifdef COPENSSL

int ccm_encrypt(unsigned char *plaintext, int text_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
{
EVP_CIPHER_CTX *ctx=NULL;
int irv=0,err=0;
int size_len=3;//15-12

memset(tag,0,16);
memset(ciphertext,0,text_len);

ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL)
return -1;

if (EVP_EncryptInit(ctx, EVP_aes_128_ccm(), NULL, NULL) != 1)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L,size_len, NULL) <= 0)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,16, NULL) <= 0)
return -1;

/* process input data */
if (EVP_EncryptInit(ctx, NULL, key, iv) != 1)
return -1;

if (EVP_EncryptUpdate(ctx, NULL, &irv, NULL, text_len) != 1)
return -1;

if (irv != text_len)
return -1;

irv = -1;
if (EVP_EncryptUpdate(ctx, NULL, &irv, aad, aad_len) != 1)
return -1;

irv = -1;
if (EVP_EncryptUpdate(ctx,ciphertext, &irv, plaintext, text_len) != 1)
return -1;

if (irv != text_len)
return -1;

/*
 * EVP_EncryptFinal(3) doesn't really do anything for CCM.
 * Call it anyway to stay closer to normal EVP_Encrypt*(3) idioms,
 * to match what the OpenSSL Wiki suggests since 2013, and to ease
 * later migration of the code to a different AEAD algorithm.
 */
irv = -1;
if (EVP_EncryptFinal(ctx,ciphertext+text_len,&irv) != 1)
return -1;

err=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, 16,tag);

if (irv != 0)
return -1;

EVP_CIPHER_CTX_free(ctx);

return text_len;
}


int gcm_encrypt(unsigned char *plaintext, int text_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
EVP_CIPHER_CTX *ctx=NULL;
int irv=0;

/* configuration */
ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL)
return -1;

if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
return -1;

if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,iv_len, NULL))
return -1;

/* process input data */
if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
return -1;

irv = -1;
if (EVP_EncryptUpdate(ctx, NULL, &irv, aad, aad_len) != 1)
return -1;

irv = -1;
if (EVP_EncryptUpdate(ctx, ciphertext, &irv, plaintext, text_len) != 1)
return -1;
if (irv != text_len)
return -1;

irv = -1;
if (EVP_EncryptFinal_ex(ctx, ciphertext, &irv) != 1)
return -1;
if (irv != 0)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,16,tag) <= 0)
return -1;
EVP_CIPHER_CTX_free(ctx);

return text_len;
}

int ccm_decrypt(unsigned char *ciphertext, int cipher_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
{
EVP_CIPHER_CTX *ctx=NULL;
int irv=0;
int size_len=3;

ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL)
return -1;

if (EVP_DecryptInit(ctx, EVP_aes_128_ccm(), NULL, NULL) != 1)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L, size_len, NULL) <= 0)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,16, (void *)tag) <= 0)
return -1;

/* process input data */
if (EVP_DecryptInit(ctx, NULL, key, iv) != 1)
return -1;

if (EVP_DecryptUpdate(ctx, NULL, &irv, NULL, cipher_len) != 1)
return -1;

if (irv != cipher_len)
return -1;

irv = -1;
if (EVP_DecryptUpdate(ctx, NULL, &irv, aad, aad_len) != 1)
return -1;

irv = -1;
if (EVP_DecryptUpdate(ctx,plaintext, &irv, ciphertext, cipher_len) != 1)
return -1;
if (irv != cipher_len)
return -1;

EVP_CIPHER_CTX_free(ctx);
return cipher_len;
}


int gcm_decrypt(unsigned char *ciphertext, int cipher_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
EVP_CIPHER_CTX *ctx=NULL;
int irv=0;

ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL)return -1;

if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL,NULL) != 1)
return -1;

if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,iv_len, NULL)<=0)
return -1;

/* process input data */
if (EVP_DecryptInit_ex(ctx, NULL,NULL, key, iv) != 1)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,16,(void *)tag) <= 0)
return -1;

irv = -1;
if (EVP_DecryptUpdate(ctx, NULL, &irv, aad, aad_len) != 1)
return -1;

irv = -1;
if (EVP_DecryptUpdate(ctx, plaintext, &irv, ciphertext, cipher_len) != 1)
return -1;

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,16,(void *)tag) <= 0)
return -1;

irv= EVP_DecryptFinal_ex(ctx, plaintext, &irv);

if (irv >0)    ;
else  return -1;

EVP_CIPHER_CTX_free(ctx);

return cipher_len ;
}

int aesccm_init(AES_CIPHER* mycipher, char * mykey)
{
  mycipher->key= mykey;
  return 0;
}

int aesccm_free(AES_CIPHER* mycipher)
{ 
   return 0;
}


int aesgcm_init(AES_CIPHER* mycipher, char * mykey)
{
  mycipher->key= mykey;
  return 0;
}

int aesgcm_free(AES_CIPHER* mycipher)
{ 
   return 0;
}


int aesccm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz)
{  int err;

/*
int ccm_encrypt(unsigned char *plaintext, int text_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *ciphertext,
                unsigned char *tag)
*/

  err= ccm_encrypt((unsigned char *)in,sz,
                   (unsigned char *)authIn,authInSz,
				   (unsigned char *)mycipher->key,
                   (unsigned char *)iv,
                   (unsigned char *)out,
                   (unsigned char *)authTag);
return err;
}

/*
ccm_decrypt(unsigned char *ciphertext, int cipher_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv,
                unsigned char *plaintext)
*/

int aesccm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz)
{ int err;
  
  err= ccm_decrypt((unsigned char *)in,sz,
                  (unsigned char *)authIn,authInSz,
                  (unsigned char *)authTag,
                  (unsigned char *)mycipher->key,
                  (unsigned char *)iv,
                  (unsigned char *)out);


return err;
}

int aesgcm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz)
{ int err;

  err=  gcm_decrypt((unsigned char *)out, sz,
                (unsigned char *)authIn,authInSz,
                (unsigned char *)authTag,
                (unsigned char *)mycipher->key,
                (unsigned char *)iv, ivSz,
                (unsigned char *)in);
return err;
}

int aesgcm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz)
{  int err;

   err=gcm_encrypt((unsigned char *)in,sz,
                  (unsigned char *)authIn,authInSz,
                  (unsigned char *)mycipher->key,
                  (unsigned char *)iv,ivSz ,
                  (unsigned char *)out,
                  (unsigned char *)authTag);
  return err;
}
int testccm(int argc, char **argv)
{
unsigned char key[16];
unsigned char nonce[12];
unsigned char aad[5] ;
unsigned char plaintext[7];

/* expected output data */
unsigned char ciphertext[7];
unsigned char wanted_tag[16];
char out[512],i=0;

int errr=0;

errr=  Ascii2bin("9559809634335D1886770DE503A3FD68",key);
errr = Ascii2bin("1703030017",aad);
errr=  Ascii2bin("4A7DF52F2F0149EE3B042B30",nonce);
errr = Ascii2bin("08000002000016",(char*)plaintext);

errr=  Ascii2bin("BE11BA9D9DA78F86D47F359263A338E0",wanted_tag);
errr = Ascii2bin("51F653DE60857E",ciphertext);

memmove(out,aad,5);

errr= gcm_encrypt(plaintext,7,
                aad,5,
                key,
                nonce, 12,
                out+5,
                out+12);

if (errr >0)
{ 
printf("Total packet length = %d.", errr+16+5);
printf(" [Authenticated and Encrypted Output]");
for (i = 0; i < (errr+16+5); i++) 
{
	if (i % 16 == 0)
		printf("\n         ");
	if (i % 4 == 0)
		putchar(' ');
	printf(" %02X", 0xFF & out[i]);
}
putchar('\n');
}
else
printf("GCM Encrypt Error\n");

errr=gcm_decrypt(ciphertext,7,
                 aad,5,
                 wanted_tag,
                 key,
                 nonce,12,
                 out+5);
if (errr >0)
{ 
printf("Total packet length = %d.", errr+5);
printf(" [Authenticated and Decrypted Output]");
for (i = 0; i < (errr+5); i++) 
{
	if (i % 16 == 0)
		printf("\n         ");
	if (i % 4 == 0)
		putchar(' ');
	printf(" %02X", 0xFF & out[i]);
}
putchar('\n');
}
else
printf("GCM Decrypt Error\n");


errr=  Ascii2bin("E7C23B63DBF348DA4FF5BA056B67D8B9",key);
errr = Ascii2bin("1703030017",aad);
errr = Ascii2bin("DBEC1385B842A0",ciphertext);
errr=  Ascii2bin("ABBE10C32E04E6CCDDED2DB2",nonce);

errr=  Ascii2bin("A22989C7BBCBA49943FC550114809DA1",wanted_tag);
errr = Ascii2bin("08000002000016",(char*)plaintext);

memmove(out,aad,5);

errr= ccm_encrypt(plaintext,7,
                aad,5,
                key,
                nonce,
                out+5,
                out+12);

if (errr >0)
{ 
printf("Total packet length = %d.", errr+16+5);
printf(" [Authenticated and Encrypted Output]");
for (i = 0; i < (errr+16+5); i++) 
{
	if (i % 16 == 0)
		printf("\n         ");
	if (i % 4 == 0)
		putchar(' ');
	printf(" %02X", 0xFF & out[i]);
}
putchar('\n');
}
else
printf("CCM Encrypt Error\n");


//wanted_tag[0]=0xA5;

errr=ccm_decrypt(ciphertext,7,
                 aad,5,
                 wanted_tag,
                 key,
                 nonce,
                 out+5);
if (errr >0)
{ 
printf("Total packet length = %d.", errr+5);
printf(" [Authenticated and Decrypted Output]");
for (i = 0; i < (errr+5); i++) 
{
	if (i % 16 == 0)
		printf("\n         ");
	if (i % 4 == 0)
		putchar(' ');
	printf(" %02X", 0xFF & out[i]);
}
putchar('\n');
}

else
printf("CCM Decrypt Error\n");



return 0;

}




#else


int aesgcm_init(AES_CIPHER* mycipher, char * mykey)
{ int err;
  
  memset(mycipher,0,sizeof(AES_CIPHER));

  err= wc_AesInit(mycipher,NULL, INVALID_DEVID);
  if (err != 0)
		return -1;
  
   err = wc_AesGcmSetKey(mycipher,mykey,KEYSIZE);
   
   if (err != 0)
		return -1;

   return err;
}

int aesgcm_free(AES_CIPHER* mycipher)
{  wc_AesFree(mycipher);
   return 0;
}

int aesgcm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz)
{  int err;

   err = wc_AesGcmEncrypt(mycipher,out,in,sz,
                          iv,ivSz,
                          authTag, authTagSz,
                          authIn,authInSz);
				   
  return err;
}

int aesgcm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz)
{ int err;

  err=  wc_AesGcmDecrypt(mycipher,in,out,sz,
                         iv, ivSz,
                         authTag,authTagSz,
                         authIn,authInSz);
return err;
}


int aesccm_init(AES_CIPHER* mycipher, char * mykey)
{ int err;
  
  memset(mycipher,0,sizeof(AES_CIPHER));

  err= wc_AesInit(mycipher,NULL, INVALID_DEVID);
  
  if (err != 0)
		return -1;
  
   err = wc_AesCcmSetKey(mycipher,mykey,KEYSIZE);
   
   if (err != 0)
		return -1;

   return err;
}

int aesccm_free(AES_CIPHER* mycipher)
{  wc_AesFree(mycipher);
   return 0;
}

int aesccm_encrypt(AES_CIPHER * mycipher, char* out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz)
{  int err;

   err = wc_AesCcmEncrypt(mycipher,out,in,sz,
                          iv,ivSz,
                          authTag, authTagSz,
                          authIn,authInSz);
				   
  return err;
}

int aesccm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz)
{ int err;

  err=  wc_AesCcmDecrypt(mycipher,out,in,sz,
                         iv, ivSz,
                         authTag,authTagSz,
                         authIn,authInSz);
return err;
}

#endif






int test_aesgcm()
{ char iv[16];
  char tag[16];
  char key[16];
  char auth[64];
  int authsz,sz;
  int i,err;
  char in[512],out[512];
  AES_CIPHER mycipher;
  char seq[8]= {0,0,0,0,0,0,0,0};
  char nonce[16];
  
  /* RFC 5116 
  An AEAD_AES_128_GCM ciphertext is exactly 16 octets longer than its corresponding plaintext.
  Implementations SHOULD support 12-octet nonces in which the Counter field is four
  octets long.
  
       <----- variable ----> <----------- variable ----------->
      +---------------------+----------------------------------+
      |        Fixed        |              Counter             |
      +---------------------+----------------------------------+

                    Figure 1: Recommended nonce format
 */
   

  err= Ascii2bin("9559809634335D1886770DE503A3FD68",key);
  authsz = Ascii2bin("1703030017",auth);
  sz = Ascii2bin("08000002000016",in);
  err = Ascii2bin("4A7DF52F2F0149EE3B042B30",iv);

   memmove(nonce+4,seq,8);
   for (i = 0; i < 4; i++) nonce[i]  = iv[i];
   for (i=4; i<12; i++)    nonce[i] ^= iv[i];

  err= aesgcm_init(&mycipher,key) ;
  
  err= aesgcm_encrypt(&mycipher,out,in,sz,nonce,12,tag,TAGSIZE,auth,authsz);
  
  printf("EncryptGCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");

  printf("tag: ");
  for(i=0;i<TAGSIZE;i++)
	  printf("%02X", tag[i] & 0xFF);
  printf("\n");


 memmove(in,out,sz);
 memset(out,0,sz);
 err= aesgcm_decrypt(&mycipher,in,out, sz,
                     nonce,12,
                     tag,TAGSIZE,
                     auth,  authsz);

  printf("DecryptGCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");
  
   seq[7]++;
   memmove(nonce+4,seq,8);
   for (i = 0; i < 4; i++) // 4
   nonce[i] = iv[i];
   for (i=4; i < 12; i++)
   nonce[i] ^= iv[i];

  authsz = Ascii2bin("1703030035",auth);
  sz  = Ascii2bin("14000020AAF5BE55D5AC6C190697FCEBDF3D1A57200C38D9459D00FDB13C19F8458E978416",in);
 
  err= aesgcm_encrypt(&mycipher,out,in,sz,nonce,12,tag,TAGSIZE,auth,authsz);

  printf("EncryptGCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");

  printf("tag: ");
  for(i=0;i<TAGSIZE;i++)
	  printf("%02X", tag[i] & 0xFF);
  printf("\n");

 memmove(in,out,sz);
 memset(out,0,sz) ;
 err= aesgcm_decrypt(&mycipher,in,out, sz,
                     nonce, 12,
                     tag,TAGSIZE,
                     auth,  authsz);

 printf("DecryptGCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");


aesgcm_free(&mycipher);

return 0;
}
int test_aesccm()
{ //char iv[16];
  char tag[16];
  char key[16];
  char auth[64];
  int authsz,sz;
  int err,i;
  char in[512],out[512];
  AES_CIPHER mycipher;
  char seq[8]= {0,0,0,0,0,0,0,0};
  char nonce[16];
  

/*
Auth: 1703030017
Len : 23
Data: DBEC1385B842A0
Tag : A22989C7BBCBA49943FC550114809DA1
AesKey: E7C23B63DBF348DA4FF5BA056B67D8B9
IV  : ABBE10C32E04E6CCDDED2DB2
*/

 err= Ascii2bin("E7C23B63DBF348DA4FF5BA056B67D8B9",key);
 authsz = Ascii2bin("1703030017",auth);
 sz = Ascii2bin("DBEC1385B842A0",out);
 //              DBEC1385B842A0
 err = Ascii2bin("ABBE10C32E04E6CCDDED2DB2",nonce);
 err=  Ascii2bin("A22989C7BBCBA49943FC550114809DA1",tag);
                //A22989C7BBCBA49943FC550114809DA1
 
 sz = Ascii2bin("08000002000016",in);

 err= aesccm_init(&mycipher,key) ;

  err= aesccm_encrypt(&mycipher,out,in,sz,nonce,12,tag,TAGSIZE,auth,authsz);

  if (err <0) printf("Encryption Error\n");
  else
  {
  printf("EncryptCCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");
  printf("Should be DBEC1385B842A0\n");

  printf("tag: ");
  for(i=0;i<TAGSIZE;i++)
	  printf("%02X", tag[i] & 0xFF);
  printf("\n");
  printf("Should be A22989C7BBCBA49943FC550114809DA1\n");
  }

 
 memmove(in,out,sz);
 memset(out,0,sz);
 err= aesccm_decrypt(&mycipher,out,in, sz,
                     nonce, 12,
                     tag,TAGSIZE,
                     auth,  authsz);

 if (err <0) printf("Decryption Error\n");
 else
 {
 printf("DecryptCCM: ");
  for(i=0;i<sz;i++)
	  printf("%02X", out[i] & 0xFF);
  printf("\n");
  printf("Should be 08000002000016\n");
 }
  
aesccm_free(&mycipher);

return 0;
}


