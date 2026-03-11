/* 
 * Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define TLS_AES_128_GCM_SHA256            0x1301
#define TLS_AES_128_CCM_SHA256            0x1304
#define AES128GCM TLS_AES_128_GCM_SHA256
#define AES128CCM TLS_AES_128_CCM_SHA256

extern void myPrintf(char *str, char  *vli, int size);
extern int Ascii2bin(char *Data_In,char *data_out)   ;

/*
#define MYSHA256_CTX wc_Sha256
extern char esha256[32] ; // SHA256(EMPTY)
extern int mysha256_dup(MYSHA256_CTX * sha_dest , MYSHA256_CTX * sha_src);
extern int mysha256_init(MYSHA256_CTX * sha);
extern int mysha256_update(MYSHA256_CTX * sha, char *data, int len);
extern int mysha256_final(MYSHA256_CTX * sha, char *result);
*/

extern int myrnd_init();
extern int myrnd(int mode,char *r, int len,char *pin, char *aid);

#include "param.h"
#include "aead.h"
#include "hmac.h"

/*
#define TAGSIZE 16
#define IVSIZE  12
#define KEYSIZE 16
#define SEQSIZE 8

#define  AES_CIPHER  Aes

extern int aesgcm_init(AES_CIPHER* mycipher, char * mykey);
extern int aesgcm_free(AES_CIPHER* mycipher);
extern int aesgcm_encrypt(AES_CIPHER * mycipher, byte* out, byte* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);

extern int aesgcm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);


extern int aesccm_init(AES_CIPHER* mycipher, char * mykey);
extern int aesccm_free(AES_CIPHER* mycipher);
extern int aesccm_encrypt(AES_CIPHER * mycipher, byte* out, byte* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn, int authInSz);
extern int aesccm_decrypt(AES_CIPHER * mycipher, char * out, char* in, int sz,
                   char * iv, int ivSz,
                   char * authTag, int authTagSz,
                   char * authIn,  int authInSz);
*/


typedef struct  {  char ms[32];
	               AES_CIPHER aes;
				   char key[16]  ;
				   int ciphersuite;
                   char iv[IVSIZE]   ;
				   char seq[SEQSIZE] ;
                 } CH_CTX ;

typedef struct { char fek[32];
				 char dsk[32];
               } IM_CTX;

extern int ComputePRK(char *salt, int lensalt, char *ikm, int lenikm,char *prk);
extern int DeriveSecret(char *prk, int len, char * label, char *data, int lendata, char *secret);

#define MAXTLSBUFSIZE 2048
typedef struct T_CTX { 
	             CH_CTX ctx0 ;
                 CH_CTX ctx1 ;
                 MYSHA256_CTX sha0;
                 MYSHA256_CTX sha1;
                 MYSHA256_CTX sha2;
				 char pubkey[65];
				 char hs[32];
				 char ms[32];
				 int timeout;
                 int  ciphersuite;
				 char *identity;
			     char *sn  ;
				 int mode  ;
				 int auth  ;
				 int sign  ;
				 int fquiet;
				 char *buf;
				 int bufmax;
                 char s_hs_traffic[32];
                 char c_hs_traffic[32];
                 char s_ap_traffic[32];
                 char c_ap_traffic[32];
                 char tx_key[16];
                 char tx_iv[12];
                 char rx_key[16];
                 char rx_iv[12];
				 char *name;
				 int port;
				 char psk[32] ;
				 char privkey[32];
				 int state;
				 IM_CTX imctx;
				 char *rx;
				 char *tx;
				 int s;
				 //Local IM
				 int index;
				 char  pin[9];
				 char  aid[33];
                 // authentication
				 char CAPub[131]  ; // 
				 char CAPriv[65]  ; // 
				 //remote TLSIM//
				 ////////////////
				 struct T_CTX *netctx ;
                 struct T_CTX *backctx;
				 } T_CTX;


extern int MakeClientHello (T_CTX* ctx);
extern int CheckServerHello(T_CTX * ctx);
extern int CheckEncryptedOPtions(T_CTX *ctx);
extern int CheckServerFinished(T_CTX *ctx);
extern int MakeClientFinished(T_CTX * ctx);

extern int ch_encrypt(CH_CTX * ctx, char *in, int sz, char *out,char *auth, int authsz);
extern int ch_decrypt(CH_CTX * ctx, char *in, int sz, char *out,char *auth, int authsz);
extern int ch_free(CH_CTX * ctx);
extern int ch_init(CH_CTX * ctx,char *key, char *iv,int ciphersuite);

extern int genkeyecc(char *pub, char *priv);
extern int dhecc(char *pub,char * priv,char *dh);
extern int ecc_sign(char *data, int lendata, char *sig, int *lensig, char * priv, int curve);
extern int ecc_verify(char *sig, int siglen, char*data, int datalen, char *pub,int curve);
extern int extractRS(char *sig, char *r,char *s);
extern int asn1(char *sig, char *r, char *s);

extern void init_imv(char *psk, int test, IM_CTX *ctx);
extern void binder(char *data32, char *key32, IM_CTX *ctx);
extern void derive(char *data32, char *key32, IM_CTX *ctx);

#define CTEST        0x08 
#define CDHSOFT      0x20
#define CBINDERIM    0x40
#define CBINDERSOFT  0x80
#define CDHNET       0x100
#define CBINDERNET   0x200
#define CDERIVEIM    0x400
#define CDHIM        0x410 
#define CIMRANDOM    0x800
#define CIMTLSSE     0x1000
#define CIMASK       0x2000


extern int TLSIM_binder(T_CTX *ctx,char *data,int len, char *key);
extern int TLSIM_derive(T_CTX *ctx,char *dhe,int len, char *key);


extern int auth(T_CTX * ctx);
extern int sign(T_CTX * ctx);

