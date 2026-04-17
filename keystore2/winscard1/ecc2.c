/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>

#include "crypto.h"
#include "util.h"

#ifdef COPENSSL
int genkeyecc(char *pub, char*priv);
int ecc_verify(char *sig, int siglen, char*data, int datalen, char *mypub,int curve);
int ecc_sign(char *data, int lendata, char *sig, int *lensig, char * mypriv, int curve);
int dhecc(char *pub, char*priv, char *dh);
int test_ecc();

int amainecc(int argc, char **argv)
{ char pub[65], priv[32];
  char sig[128];
  char data[32];
  int err=0,lensig=32,i=0;
  char dh[32];
  char pub1[65], priv1[32];

  for(i=0;i<32;i++) data[i]= i+1;
  

genkeyecc(pub,priv);
err= ecc_sign(data,32,sig,&lensig,priv,0);
err= ecc_verify(sig,lensig,data,32,pub,0);
genkeyecc(pub1,priv1);
err= dhecc(pub,priv1,dh);

test_ecc();


return 0;
}


int dhecc(char *mypub, char * mypriv, char *dh)
{   BN_CTX *ctx  = BN_CTX_new();
    EC_POINT *pub_key;
    EC_POINT *tmp = NULL;
    BIGNUM *priv_key = NULL;
    const EC_GROUP *ec_group;
    int ret = 0,err=0,i=0;
   	char apriv[65],apub[131];
	char *ptr=NULL;
	char dhp[65]  ;

    ec_group= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    pub_key = EC_POINT_new(ec_group);
    priv_key = BN_new();

	for(i=0;i<65;i++)
    sprintf(apub+2*i,"%2.2X",0xFF & mypub[i]);
 	pub_key = EC_POINT_hex2point(ec_group,apub,pub_key,ctx);
    
	for(i=0;i<32;i++)
    sprintf(apriv+2*i,"%2.2X",0xFF & mypriv[i]);
    err= BN_hex2bn(&priv_key, apriv);

    tmp = EC_POINT_new(ec_group);
    
    if (!EC_POINT_mul(ec_group, tmp, NULL, pub_key, priv_key, ctx)) 
	return -1;
  
    ptr = EC_POINT_point2hex(ec_group,tmp,POINT_CONVERSION_UNCOMPRESSED,ctx);
    // printf("DH %s\n",ptr);
    err= Ascii2bin(ptr,dhp);
	if (err != 65) return -1;
	memmove(dh,dhp+1,32);
    free(ptr);
	
    ret = 0;

//err:
    EC_POINT_free(tmp);
    EC_POINT_free(pub_key);
    BN_free(priv_key);
    BN_CTX_free(ctx) ;
    return ret;

}


int ecc_verify(char *sig, int siglen, char*data, int datalen, char *mypub,int curve)
{  int err=0,i=0;
   EC_GROUP *ec_group= NULL;
   ECDSA_SIG *signature=NULL;
   EC_KEY *eckey_pub=EC_KEY_new();
   EC_POINT *pub= NULL           ;
   char apub[131];
   BN_CTX *ctx  = BN_CTX_new();

     
// Initialize OpenSSL error handling
//    ERR_load_crypto_strings();

    if (curve ==0)
    ec_group= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    else
    ec_group= EC_GROUP_new_by_curve_name(NID_secp256k1);

    signature = ECDSA_SIG_new();
    signature = d2i_ECDSA_SIG(&signature,&sig,siglen);

    pub = EC_POINT_new(ec_group);

    err = EC_KEY_set_group(eckey_pub,ec_group);


	for(i=0;i<65;i++)
    sprintf(apub+2*i,"%2.2X",0xFF & mypub[i]);
    
	pub = EC_POINT_hex2point(ec_group,apub,pub,ctx);

    err= EC_KEY_set_public_key(eckey_pub,pub);
   
    err= ECDSA_do_verify(data,datalen,signature,eckey_pub);


  //BN_free(priv_key);
  EC_POINT_free( pub );
  //EC_POINT_free( tmp );
  EC_GROUP_free(ec_group ); 
  BN_CTX_free(ctx);
  //ERR_free_strings();

if (err != 1) return -1;
return 0;
}





int ecc_sign(char *data, int lendata, char *sig, int *lensig, char * mypriv, int curve)
{  int err=0,i=0;
   EC_GROUP *ec_group= NULL;
   ECDSA_SIG *signature=NULL;
   EC_KEY *eckey_priv=EC_KEY_new();
   BIGNUM *Priv = BN_new();
   char apriv[65];
    
    // Initialize OpenSSL error handling
    // ERR_load_crypto_strings();

    if (curve ==0)
    ec_group= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    else
    ec_group= EC_GROUP_new_by_curve_name(NID_secp256k1);
  
    err = EC_KEY_set_group(eckey_priv,ec_group);
	for(i=0;i<32;i++)
    sprintf(apriv+2*i,"%2.2X",0xFF & mypriv[i]);
    
	err= BN_hex2bn(&Priv, apriv);
    
	err = EC_KEY_set_private_key(eckey_priv,Priv);

    signature = ECDSA_do_sign(data,lendata, eckey_priv);

    err= i2d_ECDSA_SIG(signature,(unsigned char **)&sig);
    *lensig= err;



 EC_KEY_free(eckey_priv);
 BN_free(Priv);
 ECDSA_SIG_free(signature) ;
 EC_GROUP_free(ec_group ); 

  //ERR_free_strings(); // Clean up error strings
  return 0;
}




int  genkeyecc(char *apub, char *apriv)
{
    EC_KEY *ec_key = NULL;
    int err=0;
    const BIGNUM * priv= NULL;
    const EC_POINT *pub=NULL;
    char *ptr = NULL; 
    EC_GROUP *ec_group= NULL;
    
    // Initialize OpenSSL error handling
    // ERR_load_crypto_strings();

    ec_key = EC_KEY_new();
    if (ec_key == NULL) 
    return -1;

    //ec_group= EC_GROUP_new_byname(OBJ_txt2nid(curve_name));
    ec_group= EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    if (ec_group == NULL)
    return -1;

    if (!EC_KEY_set_group(ec_key, ec_group)) 
    return -1;

   if (!EC_KEY_generate_key(ec_key)) 
   return -1;

   priv = EC_KEY_get0_private_key(ec_key);
   pub=   EC_KEY_get0_public_key(ec_key) ;
  
   ptr = EC_POINT_point2hex(ec_group, pub,POINT_CONVERSION_UNCOMPRESSED,NULL);
   // printf( "PublicKey: %s\n",ptr);
   err = Ascii2bin(ptr,apub);
   free(ptr);
   if (err != 65) return -1;

   ptr=BN_bn2hex(priv);
   // printf( "PrivateKey: %s\n",ptr);
   err = Ascii2bin(ptr,apriv);
   free(ptr);
   if (err != 32) return -1;

   EC_KEY_free(ec_key);
   EC_GROUP_free(ec_group); // Group is duplicated inside EC_KEY_set_group
   
   //ERR_free_strings(); // Clean up error strings
  
   return 0;
}

int test_ecc()
{ 
  char privkey[32];
  char pubkey[65] ;
  int len,ret;
  char privkey1[32];
  char pubkey1[65] ;
  char dh[32];
  char dref[32];

  char sig[72];

  ret= genkeyecc(pubkey,privkey);
  ret= genkeyecc(pubkey1,privkey1);
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
