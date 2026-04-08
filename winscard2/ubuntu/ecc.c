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

#include "crypto.h"
#include "util.h"

int extractRS(char *sig, char *r,char *s)
{ int pt1=4,pt2;
  int len1,len2,len3;
  
  //30 len 02 len ... 02 len
  len1 = 0xFF & sig[1];
  len2=  0xFF & sig[3];
  len3=  0xFF & sig[4+len2+1];
  if ( len1 != (len2+len3+4) )
	  return -1;

  pt1=4;
  pt2=4+len2+2;
  if (len2 == 33) pt1++;
  memmove(r,sig+pt1,32);
  if (len3 == 33) pt2++;
  memmove(s,sig+pt2,32);

 return 0;

}

int asn1(char *sig, char *r, char *s)
{ int len1=0,len2=32,len3=32;

  if ( (r[0] & (char)0x80) == (char)0x80) len2++;
  if ( (s[0] & (char)0x80) == (char)0x80) len3++;
	
	sig[0]= 0x30;
	sig[1]= 0xFF & (len2+len3+4);
	sig[2]= 0x02;
	sig[3]= 0xFF & len2;
	sig[4]= 0;
	sig[4+len2]=0x02;
	sig[4+len2+1] = 0xFF & len3;
    sig[4+len2+2] = 0;

	if (len2 == 32)memmove(sig+4,r,32);
	else           memmove(sig+5,r,32);

	if (len3 == 32)memmove(sig+len2+6,s,32);
	else           memmove(sig+len2+7,s,32);

   len1= len2+len3+4 ;
   sig[1]= 0xFF & len1;
   return 2+len1 ;
}



#ifndef COPENSSL
int genkeyecc(char *pub, char*priv);
int ecc_verify(char *sig, int siglen, char*data, int datalen, char *mypub,int curve);
int ecc_sign(char *data, int lendata, char *sig, int *lensig, char * mypriv, int curve);
int dhecc(char *pub, char*priv, char *dh);
int test_ecc();

int dhecc(char *pub, char*priv, char *dh)
{ 
  int ret,len;
  ecc_key key  ;
  int curve_idx;
  ecc_point *ppoint;

  curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
  if (curve_idx == ECC_CURVE_INVALID) return -1  ;
  
  ppoint = wc_ecc_new_point()        ;
  if (ppoint == NULL) return -1      ;
  ret = wc_ecc_import_point_der(pub,65,curve_idx,ppoint);
  if (ret != 0) return-1;

  ret= wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
  if (ret != 0) return-1;
  ret = wc_ecc_set_flags(&key, 0);
  if (ret != 0) return-1;
  ret = wc_ecc_import_private_key(priv, 32, NULL, 0, &key);
  if (ret != 0) return-1;

  len=32;
  ret = wc_ecc_shared_secret_ssh(&key,ppoint,dh,&len);
  if (ret != 0) return-1;
  //myPrintf("DHE",dh,32);

  wc_ecc_del_point(ppoint);
  wc_ecc_free(&key);
  return 0;

}


int genkeyecc(char *pub, char*priv)
{ WC_RNG  rng;
  int ret,len;
  ecc_key key;
  int curve_idx;

  ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);
  if (ret != 0) return-1;
  ret=  wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
  if (ret != 0) return-1;
  ret = wc_ecc_set_flags(&key, 0)      ;
  if (ret != 0) return-1;
  ret = wc_ecc_make_key(&rng, 32, &key);
  if (ret != 0) return-1;

  curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
  if (curve_idx == ECC_CURVE_INVALID) return -1;
  
  len=65;
  ret = wc_ecc_export_point_der(curve_idx,&key.pubkey,pub, &len);
  if (ret != 0) return-1;
 // myPrintf("Pub",pub,len);

  len=32;
  ret = wc_ecc_export_private_only(&key, priv,&len);
  if (ret != 0) return-1;
 // myPrintf("Priv",priv,len);

  wc_ecc_free(&key);
  wc_FreeRng(&rng);

  return 0;
}


/**
 Sign a message digest
 in        The message digest to sign
 inlen     The length of the digest
 out       [out] The destination for the signature
 outlen    [in/out] The max size and resulting size of the signature
 key       A private ECC key
 return    MP_OKAY if successful
 */
int ecc_sign(char *data, int lendata, char *sig, int *lensig, char * priv, int curve)
{  int ret,len;
   WC_RNG  rng;
   ecc_key key;
   int curve_idx;
   
   if (curve == 0)
   curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
   else
   curve_idx = wc_ecc_get_curve_idx(ECC_SECP256K1);

   if (curve_idx == ECC_CURVE_INVALID) return -1  ;

   ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);// -2= INVALID_DEVID
   if (ret != 0) return-1;
   
   wc_ecc_init_ex(&key, NULL, INVALID_DEVID); // -2= INVALID_DEVID
   if (ret != 0) return-1;
   
   ret = wc_ecc_set_flags(&key, 0);
   if (ret != 0) return-1;

   if (curve == 0)
   ret = wc_ecc_import_private_key_ex(priv,32,NULL,0,&key,ECC_SECP256R1);
   else
   ret = wc_ecc_import_private_key_ex(priv,32,NULL,0,&key,ECC_SECP256K1);
    if (ret != 0) return-1;

   len=72;
   do 
   { ret= wc_ecc_sign_hash(data,lendata,sig,&len,&rng,&key);
   }  while (ret == WC_PENDING_E);

  
  *lensig=0;

  wc_ecc_free(&key);
  wc_FreeRng(&rng) ;

  if (ret != 0) return -1;

  *lensig=len;
  return 0;
}

/**
 Verify an ECC signature
 sig         The signature to verify
 siglen      The length of the signature (octets)
 hash        The hash (message digest) that was signed
 hashlen     The length of the hash (octets)
 res         Result of signature, 1==valid, 0==invalid
 key         The corresponding public ECC key
 return      MP_OKAY if successful (even if the signature is not valid)
 */
int ecc_verify(char *sig, int siglen, char*data, int datalen, char *pub,int curve)
{ ecc_key    key;
  int curve_idx,len,ret;
  char k[32];
  
  memset(k,0,32);
  k[31]=1;
  
  if ( curve == 0)
  curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
  else
  curve_idx = wc_ecc_get_curve_idx(ECC_SECP256K1);

  // curve_idx= wc_ecc_get_curve_idx_from_name("secp256k1");
  // curve_idx= ECC_SECP256K1;

  if (curve_idx == ECC_CURVE_INVALID) return -1  ;
   
  ret= wc_ecc_init_ex(&key, NULL, INVALID_DEVID); // -2= INVALID_DEVID
  if (ret != 0) return-1;
   
  ret = wc_ecc_set_flags(&key, 0);
  if (ret != 0) return-1;

  //ret = wc_ecc_import_private_key(k,32,NULL, 0, &key);
  if (curve == 0) ret= wc_ecc_import_private_key_ex(k,32,NULL, 0, &key,ECC_SECP256R1);//curve_idx);
  else            ret= wc_ecc_import_private_key_ex(k,32,NULL, 0, &key,ECC_SECP256K1);
  if (ret != 0) return-1;

  ret = wc_ecc_import_point_der(pub,65,curve_idx,&key.pubkey);
  if (ret != 0) return -1;
  key.type =  ECC_PUBLICKEY ;
    
   //do { ret=wc_ecc_verify_hash(sig,siglen,data,datalen,&len,&key);
   //   } while (ret == WC_PENDING_E);
   len=0;
   ret=wc_ecc_verify_hash(sig,siglen,data,datalen,&len,&key);
     
  wc_ecc_free(&key);
  
  if (ret != 0) return-1;
  if (len == 1) return 0;

  return -1;
}
int test_ecc()
{ WC_RNG  rng;
  int ret;
  ecc_key key;
  ecc_key key1;
  int curve_idx;
  ecc_point* point;
  ecc_point *ppoint;

  char privkey[32];
  char pubkey[65] ;
  int len;
  char privkey1[32];
  char pubkey1[65] ;
  char dh[32];
  char dref[32];

  char r[32] ;
  char s[32] ;
  char sig[72];

  ret = wc_InitRng_ex(&rng, NULL, INVALID_DEVID);// -2= INVALID_DEVID
  if (ret != 0) return -1;
  wc_ecc_init_ex(&key, NULL, INVALID_DEVID); // -2= INVALID_DEVID
  if (ret != 0) return -1;
  ret = wc_ecc_set_flags(&key, 0);
  if (ret != 0) return -1;
  ret = wc_ecc_make_key(&rng, 32, &key);
  if (ret != 0) return -1;
  
  curve_idx = wc_ecc_get_curve_idx(ECC_SECP256R1);
  if (curve_idx == ECC_CURVE_INVALID) return -1  ;
  
  len=65;
  ret = wc_ecc_export_point_der(curve_idx,&key.pubkey,pubkey, &len);
  myPrintf("Pub",pubkey,len);

  len=32;
  ret = wc_ecc_export_private_only(&key, privkey,&len);
  myPrintf("Priv",privkey,len);
   
  len=72;
  do 
  {
  ret= wc_ecc_sign_hash(dh,32,sig,&len,&rng,&key);
  } while (ret == WC_PENDING_E);
  
  ret= extractRS(sig,r,s);
  ret= asn1(sig,r,s);
  ret=wc_ecc_verify_hash(sig,ret,dh,32,&len,&key);

  point = wc_ecc_new_point()  ;
  if (point == NULL) return -1;
  ret = wc_ecc_import_point_der(pubkey,65,curve_idx,point);
  ret=  wc_ecc_cmp_point(point,&key.pubkey);
  if (ret != MP_EQ) return -1;

  wc_ecc_free(&key);
  
  wc_ecc_init_ex(&key, NULL, INVALID_DEVID);
  ret = wc_ecc_set_flags(&key, 0);
  ret = wc_ecc_import_private_key(privkey, 32, NULL, 0, &key);
  len=32;
  ret = wc_ecc_export_private_only(&key, privkey1,&len);
  myPrintf("Priv",privkey1,len);

  
  /*
  ppoint = wc_ecc_new_point()        ;
  if (ppoint == NULL) return -1      ;
  ret = wc_ecc_import_point_der(pubkey,65,curve_idx,ppoint);
  ret = wc_ecc_make_pub(&key, ppoint);
  len=65;
  ret = wc_ecc_export_point_der(curve_idx,&key.pubkey,pubkey1, &len);
  myPrintf("Pub1",pubkey1,len);
  */
  
  
  wc_ecc_init_ex(&key1, NULL, INVALID_DEVID); 
  ret = wc_ecc_set_flags(&key1, 0);
  ret = wc_ecc_make_key(&rng, 32, &key1);

  len=65;
  ret = wc_ecc_export_point_der(curve_idx,&key1.pubkey,pubkey1, &len);
  myPrintf("Pub1",pubkey1,len);
  
  ppoint = wc_ecc_new_point()        ;
  if (ppoint == NULL) return -1      ;
  ret = wc_ecc_import_point_der(pubkey1,65,curve_idx,ppoint);

  //outLen = sizeof(out);
  //ret = wc_ecc_shared_secret_ssh(&key1, &key.pubkey, out, &outLen);

  len=32;
  ret = wc_ecc_shared_secret_ssh(&key,ppoint,dh, &len);
  //myPrintf("DHE",dh,32);

  wc_ecc_del_point(point) ;
  wc_ecc_del_point(ppoint);
  wc_ecc_free(&key);
  wc_ecc_free(&key1);
  wc_FreeRng(&rng);

  ret= genkeyecc(pubkey,privkey);
  ret= dhecc(pubkey1,privkey,dh);

  ret= Ascii2bin("04 38 a0 70 80 aa 63 50 a2 c2 84 29 e8 21 1a 84 0a 2c ed 57 56 06 fb 1c e0 b3 6b 23 e2 53 77 c5 78 be ea 2f e7 47 d4 22 e7 da 35 24 d8 ed 5e 02 2d 1b ea 9f b3 2f 20 2b ff 91 b8 2d 6c 91 f6 16 64",pubkey);
  ret= Ascii2bin("04 F0C2A4942AB1AA0F4A4558E23F5CD1F0BC7A1544D12E32EA674FE5E542B5049340C59A83878C9DA5E69B8F7DCA785CADFDF03D26A5DEB8C1D5BB9C26C36F4341",pubkey1);
  ret= Ascii2bin("44339F299B09AD743B9F69D33654057CA50419D64FCC8235FB3C5D862569D69C",privkey1);
  ret= dhecc(pubkey1,privkey1,dh);
  myPrintf("DH1",dh,32);
  ret= Ascii2bin("E89ABD8565E9889C8FB9067BAE86D9DC8A97555E9AABBCBF5F72FCEC31E251CE",dref);
  //E89ABD8565E9889C8FB9067BAE86D9DC8A97555E9AABBCBF5F72FCEC31E251CE
  if (memcmp(dh,dref,32)!=0) return -1 ;
  ret= dhecc(pubkey,privkey1,dh);
  myPrintf("DH2",dh,32);
  ret= Ascii2bin("C17ACEA9DEFFB7E537312678464E7538640B893A4CFBF7807D9DFA96D9180838",dref); 
  //C17ACEA9DEFFB7E537312678464E7538640B893A4CFBF7807D9DFA96D9180838 
  if (memcmp(dh,dref,32)!=0) return -1 ;
  
  len=72;  
  ret= ecc_sign(dh,32,sig,&len,privkey1,0);
  ret=ecc_verify(sig,len,dh,32,pubkey1,0);

 ret= Ascii2bin("046099836D971593AAA2C1C32B6DB9EF9521041795E21CF1E7511DF3BD358F97DF358B33A875E359CBE236163D6DBAEDFEC6C9393522C7EBC25A7CC85E1F0A7D67",pubkey1);
 ret= Ascii2bin("5CDEE66CAEDE933ADD0CA894393480A076431FCA3EE6AC9A8E1129CE5F794120",privkey1);
 ret= ecc_sign(dh,32,sig,&len,privkey1,1);
 ret=ecc_verify(sig,len,dh,32,pubkey1,1);

 printf("ECC Tests OK\n");

 return 0;

}
#endif
