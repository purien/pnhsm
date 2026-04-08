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
#include "im.h"
#include "net.h"
#include "sim.h"

#include "tls13.h"

#include "hmac.h"
#include "util.h"

int AESct=0;

int MakeEncryptedExtensions(CH_CTX *ctx);

int CipherInfo(char *label,CH_CTX * ctx, char *in, int sz, char *nonce,char *auth,int encrypt)
{ 
/*
int i;
printf("%s\n", label);
if ((sz != 0) && (auth != NULL))
{printf("Auth : "); for(i=0;i<5;i++) printf("%2.2X",0xFF & auth[i]);printf("\n");}
if (sz != 0) printf("Len : %d\n",sz);
if (encrypt && (sz != 0) && (in != NULL))
{ printf("Data : "); for(i=0;i<(sz-16);i++) printf("%2.2X",0xFF & in[i]);printf("\n");
  printf("Tag  : ") ; for(i=0;i<16;i++) printf("%2.2X",0xFF & in[i+sz-16]);printf("\n");
}
else if ((sz != 0) && (in != NULL))
{printf("Data : "); for(i=0;i<sz;i++) printf("%2.2X",0xFF & in[i]);printf("\n");
}
#ifndef WIN32
//printf("AesKey: "); for(i=0;i<16;i++)printf("%2.2X",0xFF & ctx->aes.key[i]);printf("\n");
#endif
printf("Key  : "); for(i=0;i<16;i++)printf("%2.2X",0xFF & ctx->key[i]);printf("\n");
printf("Nonce: "); for(i=0;i<12;i++)printf("%2.2X",0xFF & nonce[i]);printf("\n");
*/

return 0;
}


int ch_free(CH_CTX * ctx)
{ 
 int err ;
 if (ctx->ciphersuite == AES128GCM)
 err= aesgcm_free(&ctx->aes);
 else
 err= aesccm_free(&ctx->aes);

 return err;
}

typedef unsigned long long U64;

void ch_inc(unsigned char * seq)
{ U64 v=0;
  v= 0xFFL & (U64) seq[7];
  v|= 0xFF00L & ((U64)seq[6]<<8);
  v|= 0xFF0000L & ((U64)seq[5]<<16);
  v|= 0xFF000000L & ((U64)seq[4]<<24);
  v|= 0xFF00000000L & ((U64)seq[3]<<32);
  v|= 0xFF0000000000L & ((U64)seq[2]<<40);
  v|= 0xFF000000000000L & ((U64)seq[1]<<48);
  v|= 0xFF00000000000000L & ((U64)seq[0]<<56);
  v++;
  seq[7]= (unsigned char)( v & 0xFFL) ;
  seq[6]= (unsigned char)((v>>8)  & 0xFFL) ;
  seq[5]= (unsigned char)((v>>16) & 0xFFL) ;
  seq[4]= (unsigned char)((v>>24) & 0xFFL) ;
  seq[3]= (unsigned char)((v>>32) & 0xFFL) ;
  seq[2]= (unsigned char)((v>>40) & 0xFFL) ;
  seq[1]= (unsigned char)((v>>48) & 0xFFL) ;
  seq[0]= (unsigned char)((v>>56) & 0xFFL) ;

}

int ch_init(CH_CTX * ctx,char *key, char *iv,int ciphersuite)
{ int err,r,i ;
  char nonce[IVSIZE];
  //AES_CIPHER2 mycipher;

 memset(ctx->seq,0,SEQSIZE)  ;
 memmove(ctx->iv,iv,IVSIZE)  ;
 ctx->ciphersuite=ciphersuite;
   
 memmove(ctx->key,key,16);

 if (ciphersuite == AES128GCM)
 err= aesgcm_init(&ctx->aes,key);
 else
 err= aesccm_init(&ctx->aes,key);

 r= IVSIZE-SEQSIZE ;
 for(i=0;i<r;i++)       nonce[i]   = ctx->iv[i];
 for(i=0;i<SEQSIZE;i++) nonce[i+r] = ctx->seq[i] ^ ctx->iv[i+r];

 CipherInfo("Init",ctx,(char *)NULL,0,nonce,NULL,0);
 return err;
}

int ch_encrypt(CH_CTX * ctx, char *in, int sz, char *out,char *auth, int authsz)
{  int err;
   int i,r;
   char tag[16];
   char nonce[IVSIZE];
   char Out[MAXTLSBUFSIZE]  ;

   if   (sz%16 == 0) AESct= 4+2*(sz/16);
   else              AESct= 5+2*(sz/16);
   
   memset(tag,0,16);
   memset(Out,0,sz);
  
   r= IVSIZE-SEQSIZE ;

  for(i=0;i<r;i++)       nonce[i]   = ctx->iv[i];
  for(i=0;i<SEQSIZE;i++) nonce[i+r] = ctx->seq[i] ^ ctx->iv[i+r];

  CipherInfo("ToEncrypt",ctx,in,sz,nonce,auth,0);

  if (ctx->ciphersuite == AES128GCM)
  err=	aesgcm_encrypt(&ctx->aes,Out,in,sz,nonce,IVSIZE,tag,16,auth,authsz);
  else
  err=	aesccm_encrypt(&ctx->aes,Out,in,sz,nonce,IVSIZE,tag,16,auth,authsz);

  memmove(out,Out,sz);
  memmove(out+sz,tag,16);

  CipherInfo("Encrypted",ctx,out,sz+16,nonce,auth,1);

 //(unsigned char)(ctx->seq[SEQSIZE-1])++;
 ch_inc((unsigned char *)ctx->seq);
  
  if (err < 0)
	   return -1;

  return sz+TAGSIZE;
}

int ch_decrypt(CH_CTX * ctx, char *in, int sz, char *out,char *auth, int authsz)
{  int err,i,r;
   char nonce[IVSIZE];
   char Out[MAXTLSBUFSIZE]  ;

   if   (sz%16 == 0) AESct= 4+2*(sz/16);
   else              AESct= 5+2*(sz/16);
 
  
   r= IVSIZE-SEQSIZE ;
   for(i=0;i<r;i++)       nonce[i]   = ctx->iv[i];
   for(i=0;i<SEQSIZE;i++) nonce[i+r] = ctx->seq[i] ^ ctx->iv[i+r];

   CipherInfo("ToDecrypt",ctx,in,sz,nonce,auth,1);

   if (ctx->ciphersuite == AES128GCM)
   err= aesgcm_decrypt(&ctx->aes,in,Out,sz-TAGSIZE,
                       nonce,IVSIZE,
                       in+sz-TAGSIZE,TAGSIZE,
                       auth, authsz);
   else
   err= aesccm_decrypt(&ctx->aes,Out,in,sz-TAGSIZE,
                       nonce,IVSIZE,
                       in+sz-TAGSIZE,TAGSIZE,
                       auth, authsz);

   memmove(out,Out,sz-TAGSIZE);

   CipherInfo("Decrypted",ctx,Out,sz-TAGSIZE,nonce,auth,0);

   //(unsigned char)(ctx->seq[SEQSIZE-1])++;
   ch_inc((unsigned char *)ctx->seq);

   if (err <0 )
	   return -1;

  return sz-TAGSIZE;
}


char ClientHello[]= 
"   16 03 01 01 21\
    01 00 01 1d 03 03 ed 49 be 48 24 06 86 1b 59 d4\
    35 b5 67 90 9b 26 cd 95 a0 92 ac f4 91 b4 2d bc\
    1e ab 7c df f7 e6 20 e4 d6 2f 95 ac af 77 18 9b\
    f8 17 ae 69 3a 70 56 b2 e3 fa de da c0 cf 09 85\
    62 13 d3 e1 9a 00 48 00 04 13 01 00 ff 01 00 00\
    d0 00 0b 00 04 03 00 01 02 00 0a 00 04 00 02 00\
    17 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04\
    03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08\
    04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02\
    03 04 00 2d 00 02 01 01 00 33 00 47 00 45 00 17\
    00 41 04 38 a0 70 80 aa 63 50 a2 c2 84 29 e8 21\
    1a 84 0a 2c ed 57 56 06 fb 1c e0 b3 6b 23 e2 53\
    77 c5 78 be ea 2f e7 47 d4 22 e7 da 35 24 d8 ed\
    5e 02 2d 1b ea 9f b3 2f 20 2b ff 91 b8 2d 6c 91\
    f6 16 64 00 29 00 3a 00 15 00 0f 43 6c 69 65 6e\
    74 5f 69 64 65 6e 74 69 74 79 00 00 00 00 00 21\
    20 6b 1b f2 4f 43 b6 0d e0 59 75 61 28 9d 84 0a\
    a1 5e 83 ad a2 4e 7e 6c 04 ab 3b 10 bf ae 4d 45\
    91";

char  ChangeCipherSpec[] = "14 03 03 00 01 01";

char ClientFinished[] = "17 03 03 00 35\
     09 da f2 de 2e f3 79 f6 76 1d e5 ec 38 8e 5f 4f\
	 8e ee c8 ff 6b b5 e2 18 12 2b a3 e2 e8 63 ca 4b\
	 a7 e4 af ca 14 66 c3 ab c5 0a 95 b1 20 cd 93 b5\
	 67 ad 08 b2 9b";


char areq[] = "17 03 03 00 18\
			  17 f3 57 72 9b 36 dc 22 aa 63 71 ae 74 ed 48 1f 4e c6 f2-ae 09 b2 e3 3e";

char aresp[]= "17 03 03 00 27\
               6a 9c a8 51 24 98 7f ba-14 5f 02 8a 08 ff 4d 87\
			   03 85 88 b7 9f ec fe 68-2a 11 a6 29 41 e4 c6 57\
			   6d 29 a6 64 94 33 48";                             

char ClientHello2[] = "16 03 01 00 e3\
    01 00 00 df 03 03 7b 7a e2 aa 19 ef d5 61 9d 40\
    93 78 71 bb fd e8 68 ae ec 92 e4 52 bd a9 33 96\
    ef 7e 64 23 fd bb 20 12 82 49 b9 b6 63 f6 5a ca\
    97 15 b5 9d 71 b0 8a 6d 11 0d 20 ee c2 b3 df 36\
    34 75 5c 89 b2 d0 9b 00 04 13 01 00 ff 01 00 00\
    92 00 0b 00 04 03 00 01 02 00 0a 00 04 00 02 00\
    17 00 16 00 00 00 17 00 00 00 0d 00 1e 00 1c 04\
    03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08\
    04 08 05 08 06 04 01 05 01 06 01 00 2b 00 03 02\
    03 04 00 2d 00 02 01 01 00 33 00 47 00 45 00 17\
    00 41 04 c4 b5 f7 68 2c 37 4a ad 1c 91 25 c2 f2\
    25 d3 43 a8 98 6c 8e 0a 47 5e 40 03 f6 c9 8d a1\
    3f 99 9e 80 a5 5e 66 f0 64 4e 84 f7 f6 50 36 15\
    b9 ec 4c b7 c2 84 4a f6 be 7f 90 91 bf 31 9b 02\
    91 a2 d8";

char ClientFinished2[]="17 03 03 00 35\
    87 87 46 1b fb 8c ee 73 6b b8 d7 50 16 78 dd 14\
    be 9d bd 27 2b ac 56 62 e7 eb d8 8c 15 76 94 00\
    c7 f3 f3 20 58 28 fb 3a 42 f1 a0 79 45 51 42 0c\
    15 f0 3a 6a 88";

char mycert[] ="30 82 02 02 30\
    82 01 a7 a0 03 02 01 02 02 14 74 00 f8 ed cc a6\
    f9 9d 76 24 83 bd b3 d6 72 d6 d9 e5 fa 5c 30 0a\
    06 08 2a 86 48 ce 3d 04 03 02 30 81 94 31 0b 30\
    09 06 03 55 04 06 13 02 46 52 31 0f 30 0d 06 03\
    55 04 08 0c 06 46 72 61 6e 63 65 31 0e 30 0c 06\
    03 55 04 07 0c 05 50 61 72 69 73 31 13 30 11 06\
    03 55 04 0a 0c 0a 45 74 68 65 72 54 72 75 73 74\
    31 0d 30 0b 06 03 55 04 0b 0c 04 54 65 73 74 31\
    14 30 12 06 03 55 04 03 0c 0b 50 61 73 63 61 6c\
    55 72 69 65 6e 31 2a 30 28 06 09 2a 86 48 86 f7\
    0d 01 09 01 16 1b 70 61 73 63 61 6c 2e 75 72 69\
    65 6e 40 65 74 68 65 72 74 72 75 73 74 2e 63 6f\
    6d 30 1e 17 0d 32 30 30 36 32 38 31 39 31 36 30\
    39 5a 17 0d 32 38 30 39 31 34 31 39 31 36 30 39\
    5a 30 5d 31 0b 30 09 06 03 55 04 06 13 02 46 52\
    31 14 30 12 06 03 55 04 08 0c 0b 49 6c 65 44 65\
    46 72 61 6e 63 65 31 0e 30 0c 06 03 55 04 07 0c\
    05 50 61 72 69 73 31 17 30 15 06 03 55 04 0a 0c\
    0e 65 74 68 65 72 74 72 75 73 74 2e 63 6f 6d 31\
    0f 30 0d 06 03 55 04 03 0c 06 53 65 72 76 65 72\
    30 59 30 13 06 07 2a 86 48 ce 3d 02 01 06 08 2a\
    86 48 ce 3d 03 01 07 03 42 00 04 5c 8c 90 d0 85\
    9d d9 6c 72 2a 58 9c 4b 62 04 7f f0 13 23 cc 74\
    38 3e 0e 8e b8 0b ea 4e a4 5e 55 b8 54 99 ab d3\
    9d 71 98 85 e8 74 ed 3f 63 27 96 0d 51 9b a2 54\
    23 c3 fb dc 14 e6 fd 0c d5 ed ee a3 0d 30 0b 30\
    09 06 03 55 1d 13 04 02 30 00 30 0a 06 08 2a 86\
    48 ce 3d 04 03 02 03 49 00 30 46 02 21 00 d1 16\
    a5 85 ce f2 a3 7a 9e e0 73 fe dc 4c 06 db 67 31\
    c9 c4 05 c6 a0 65 f8 02 ba 2a d9 16 ff bc 02 21\
    00 ac ea 0c 98 cc 66 f5 02 07 a0 d8 fd 6b 7e 35\
    c7 aa 50 5f e8 0e 4a a1 e5 98 71 05 6d 10 7d d7\
    6f";

char ServerHello2[]="16 03 03 00 9b 02 00 00 97 03 03 3b 8d 8b 94 c8\
4f 60 a1 0a a9 3e d1 e3 24 dd 43 8a fd 28 41 c2\
59 16 38 89 88 45 dc 74 00 21 5b 20 12 82 49 b9\
b6 63 f6 5a ca 97 15 b5 9d 71 b0 8a 6d 11 0d 20\
ee c2 b3 df 36 34 75 5c 89 b2 d0 9b 13 01 00 00\
4f 00 33 00 45 00 17 00 41 04 37 23 20 40 74 10\
08 cf 07 8d 96 bc 8e af c7 63 65 fc 6a 98 af 30\
20 3b 60 22 73 98 13 67 7f a2 6c 1e 01 4a 5f 8c\
fa 67 dd 0d b7 f9 7b 91 20 23 b8 60 63 e3 b9 be\
ad c9 5d 9f 1c 9c cd 12 09 b6 00 2b 00 02 03 04";

char areq2[] = "17 03 03 00 18 5d bd 39 b2 e8 19 d0 06 87 69 02\
96 21 ec 41 c7 b3 d4 09 e3 e8 d4 2e ea";

char aresp2[] = "17 03 03 00 27 c1 e5 d4 05 32 87 97 2c d9 e6 fc\
17 3f 88 45 c8 d6 88 e0 c1 d4 b3 0d 14 b3 d0 59\
f6 07 76 c0 98 4e 4b 23 0d c9 c0 e1";


char rx[MAXTLSBUFSIZE] ;
char rx2[MAXTLSBUFSIZE];
int ptrx=0   ;

int GetRecord()
{ char ptcol, vhigh, vlow ;
  int len;
  ptrx=0;
  
  ptcol= rx[ptrx++];
  vhigh= rx[ptrx++];
  vlow=  rx[ptrx++];
  
  len  =  (rx[ptrx++]<<8) & 0xFF00;
  len |=  rx[ptrx++] & 0xFF;
  
  ptrx+= len;
  return len;

}

#define LMASK 0x0F00 //0xFF00


#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff
#define MY_CURVE  23  //SECP256K1
#define MY_CIPHER    0x1301 // TLS_AES_128_GCM_SHA256 
#define MY_SIGNATURE 0x0403 // ECDSA SHA256
#define MY_DHE  1   // ECDHE
#define MY_COMPRESS  0 // NO_COMPRESS
#define MY_EC_FORMAT 0 // FULL
#define MY_VERSION   0x0304 // TLS 1.3

static char    MY_IDENTITY[]= "Client_identity";
static char    myHandshakeSecret[32];
static char s_hs_traffic[32];
static char c_hs_traffic[32];
static char *s_ap_traffic     = s_hs_traffic ;
static char *c_ap_traffic     = c_hs_traffic ;
static char tx_key[16];
static char tx_iv[12];
static char rx_key[16];
static char rx_iv[12];
static AES_CIPHER aes_tx;
static AES_CIPHER aes_rx;
static char myMasterSecret[32];
static char mypubkey[65];
static MYSHA256_CTX sha0;
static MYSHA256_CTX sha1;
char esha256[32] ;
static int sidlen  ;
static char sid[32];
static CH_CTX ctx0;
static CH_CTX ctx1;


int check_supported_groups(int len, char *ptr)
{ int leng,i,v;
	
 if (len < 2) 
		return -1 ;

  leng  =  (ptr[0]<<8) & LMASK ;
  leng |=  (ptr[1]     & 0xFF) ;
 
 if (len != (2+leng))
	 return -1;

 for (i=0;i<leng;i+=2)
 { v  =  (ptr[i+2]<<8) & 0xFF00 ;
   v |=  (ptr[i+3]     & 0xFF);
   if (v == MY_CURVE)
	   return 0;
 }

 return -1;

}


int check_supported_versions(int len, char *ptr)
{ int lens,i,v;
	
 if (len < 1) 
		return -1 ;

 lens = 0xFF & ptr[0];
 
 if (len != (1+lens))
	 return -1;

 for (i=0;i<lens;i+=2)
 { v  =  (ptr[i+1]<<8) & 0xFF00 ;
   v |=  (ptr[i+2]     & 0xFF);
   if (v == MY_VERSION)
	   return 0;
 }

 return -1;

}

int check_key_share_extension(int len, char *ptr, int *pti)
{ int lene,curve;
  int lenc;
  int b=0,mylenc=-1;
  int remain,found=0;
 
  remain = len ;

  remain-=2;
  if (remain < 0)
	  return -1 ;
  lene  =  (ptr[0]<<8) & LMASK ;
  lene |=  (ptr[1]   & 0xFF);

  if (lene != (len-2) )
  return -1;

  while (remain > 0)
  {
  
  remain-=2;
  if (remain < 0)
	  return -1 ;

  curve  =  (ptr[b+2]<<8) & 0xFF00;
  curve |=  (ptr[b+3]   & 0xFF) ;

  remain-=2;
  if (remain < 0)
	  return -1 ;

  lenc  =  (ptr[b+4]<<8) & LMASK;
  lenc |=  (ptr[b+5]     & 0xFF);

  remain -= lenc;
  if (remain <0) 
	  return -1;

  if (curve == MY_CURVE)
  {	  *pti = b+4;
	  found=1;
	  mylenc= lenc;
  }
  
  /*
  pt= lene-4;
  if (lenc != pt)
	  return -1;
  */

  b += (4+lenc);

  }

  if (found)
	  return mylenc;
  
  return -1;

}

int check_pre_share_key(int len, char *ptr, int *pti)
{ int leni,lenb;
  int lenid,lenbd;
  int pt;
  int b=0;
  int remain,found,ni=0,nb=0;

  if (len < 2+2+1+2+33)
	  return -1;
  
  leni  =  (ptr[b]<<8) & LMASK;
  leni |=  (ptr[b+1]   & 0xFF);

  lenb  =  (ptr[b+2+leni]<<8) & LMASK;
  lenb |=  (ptr[b+3+leni]     & 0xFF);

   pt= 4+leni+lenb;
   if (pt != len)
	   return -1;

  remain = leni;
  found=0;
  b=2;
  while(remain)
  { 
   if (!found) 
   ni++;
       
   remain -=2;
   if (remain <= 0) return -1;
   lenid  =  (ptr[b]<<8) & LMASK;
   lenid |=  (ptr[b+1]   & 0xFF);
   
   remain -= (lenid+4); 
   
   if (remain < 0) 
	   return -1;

   if (lenid == strlen(MY_IDENTITY))
   { if (memcmp((void*)(ptr+b+2),(void *)MY_IDENTITY,lenid)==0) found=1;}

   b+= (2+lenid+4); // => next identity

  }

  if (!found) 
	  return -1;


  *pti= b;
  remain = lenb;
  b+=2;
  nb=0;

  while(remain)
  { 
   nb++;
   remain -=1;
   if (remain <= 0) return -1;

   lenbd=  ptr[b]  & 0xFF;
   remain -= lenbd ;
   
   if (remain < 0) 
	   return -1;

   if (ni == nb) pt= b;
  
   b+= (1+lenbd);

  }
  
  return pt;
}




int check_key_exchange(int len, char *ptr)
{ int i,lenp;

  lenp  =  0xFF & ptr[0] ;

  if (lenp != (len-1))  return -1;
 
  for(i=0;i<lenp;i++)
  {
  if (ptr[i+1] == MY_DHE)
	  return 0;
  }

	
	return -1;
}

int check_ec_point_formats(int len, char *ptr)
{ int i,lenp;

  lenp  =  0xFF & ptr[0] ;

  if (lenp != (len-1))  return -1;
 
  for(i=0;i<lenp;i++)
  {
  if (ptr[i+1] == MY_EC_FORMAT)
	  return 0;
  }

	
	return -1;
}


int check_signature_algorithms(int len, char *ptr)
{ int i;
  int s;
  int lenh;
  
  if (len < 4)
	  return -1;

  lenh  =  (ptr[0]<<8) & LMASK ;
  lenh |=  (ptr[1]     & 0xFF) ;
  
  if (lenh != (len-2))
  return -1;

 if (lenh == 0)      return -1;
 if ( (lenh%2) != 0) return -1;

  for(i=0;i<lenh;i+=2)
  {
  s  =  (ptr[i+2]<<8) & 0xFF00;
  s |=  (ptr[i+3]   & 0xFF);
  if (s == MY_SIGNATURE)
	  return 0;
  
  }

	
	return -1;
}

int ComputePRK(char *salt, int lensalt, char *ikm, int lenikm,char *prk)
{ char buf160[160];
  MYSHA256_CTX sha;

  hmac(salt,lensalt,ikm,lenikm,&sha,prk,3,buf160);

  return 0;

}
int DeriveSecret(char *prk, int len, char * label, char *data, int lendata, char *secret)
{ char buf[128];
  char buf160[160];
  MYSHA256_CTX sha;
  int lent;

  lent=  (int)strlen(label);
  
  buf[0] = 0xFF & (len >> 8);
  buf[1] = 0xFF & len;
  buf[2] = 0xFF & lent;
  memmove(buf+3,label,lent);
  buf[3+lent]= lendata & 0xFF ;
  if (lendata !=0)
  memmove(buf+4+lent,data,lendata);
  buf[4+lent+lendata]= 0x01;

  lent = 5+lent+lendata ;
  hmac(prk,32,buf,lent,&sha,buf,3,buf160);
  memmove(secret,buf,len);

  return 0;
}

int MakeEncryptedFinished(CH_CTX *ctx)
{ 
  char auth[5]= {0x17,3,3,0,0x35};
  char hk[4+32+1] ;
  char k[32];
  char h[32];
  int err,i;

  hk[0]=0x14;
  hk[1]=hk[2]=0;
  hk[3]=0x20;
  hk[4+32]=0x16;

  //Ascii2bin("14000020AAF5BE55D5AC6C190697FCEBDF3D1A57200C38D9459D00FDB13C19F8458E978416",in);
  //Ascii2bin("1703030035",auth);

  memmove(rx,auth,5);
  
  err= mysha256_dup(&sha1,&sha0);
  err= mysha256_final(&sha1,h);

  err= DeriveSecret(s_hs_traffic,32,"tls13 finished",NULL,0,k);

  for(i=0;i<32;i++)
  printf("%02X", 0xFF & k[i]);
  printf("\n");

  err=ComputePRK(k,32,h,32,h);

  for(i=0;i<32;i++)
  printf("%02X", 0xFF & h[i]);
  printf("\n");

  memmove(hk+4,h,32);
  
  err= mysha256_update(&sha0,hk,4+32);
  
  err= ch_encrypt(ctx,hk,4+32+1,rx+5,auth,5);

  
  
  return 0x35;
}

int MakeEncryptedVerify(CH_CTX *ctx,int index,char *pin,char *aid)
{ char *result;
  int len,i,err,ix=0 ;
  char label[]= "TLS 1.3, server CertificateVerify";
  char *ptr;

  result= rx;
  ptr=rx+256;
  
  len= (int)strlen(label);

  for (i=0;i<64;i++)
  result[i]=32;
  
  memmove(result+64,label,len);
  result[64+len]=0;
	  
  mysha256_dup(&sha1,&sha0);
  mysha256_final(&sha1,result+1+64+len);
  
  mysha256_init(&sha1);
  mysha256_update(&sha1,result,1+64+len+32);
  mysha256_final(&sha1,result);

  //myPrintf("hashcert",result,32);


 if (index == 0xFF)
 err=Ascii2bin("30 46 02 21 00 c0 36 07\
 de 71 08 04 fb b5 ca 8c dd 46 e6 57 49 7a 91 88\
 14 87 35 d5 e9 38 cf 5a 74 57 6b a6 34 02 21 00\
 fd 3b b2 64 b3 4c e0 b1 76 e2 bc 0e 80 ac 87 65\
 4c 98 d7 13 20 2f a8 95 4c d8 20 6a 8b 80 2a ba", ptr+8);

 else
 {
  err=IM_open(pin,aid);
  err=IM_ECDSA(index,result,32,ptr+8);
  myPrintf("sign",ptr+8,err);
  IM_close();
 }

*(ptr+8+err)=0x16;

len = err + 4 + 2 + 2 + 1 + TAGSIZE;
rx[0]= 0x17;
rx[1]=3;
rx[2]=3;
rx[3]= (len>>8) & 0xFF ;
rx[4]= len & 0xFF;

len = err + 2 + 2;
ptr[ix++]= 15;
ptr[ix++] = 0;
ptr[ix++] = (len>>8) & 0xFF ;
ptr[ix++] = len & 0xFF;

ptr[ix++] = (MY_SIGNATURE >> 8) & 0xFF ;
ptr[ix++] =  MY_SIGNATURE  & 0xFF ;

len=err;
ptr[ix++] = (len>>8) & 0xFF ;
ptr[ix++]= len & 0xFF;

mysha256_update(&sha0,ptr,err+8);

len= err+8+1+TAGSIZE;
err=ch_encrypt(ctx,ptr,err+8+1,rx+5,rx,5);

return len;
}



int MakeEncryptedCertificate(CH_CTX *ctx)
{ int len,ix=0,err;
  char *ptr  ;
  ptr=rx+1000;

  len=err= Ascii2bin(mycert,ptr+11);
  *(ptr+11+err)=0;
  *(ptr+12+err)=0;
  *(ptr+13+err)=0x16;

  len += (7+2);
  ptr[ix++]= 0xb;
  ptr[ix++]= 0;
  ptr[ix++]= (len>>8) & 0xFF;
  ptr[ix++]= len & 0xFF;

  len -=4;
  ptr[ix++]= 0;
  ptr[ix++]= 0;
  ptr[ix++]= (len>>8) & 0xFF;
  ptr[ix++]= len & 0xFF;

  len = err;
  ptr[ix++]= 0;
  ptr[ix++]= (len>>8) & 0xFF;
  ptr[ix++]= len & 0xFF;

  len = err+11+2+1+TAGSIZE;

  rx[0]= 0x17;
  rx[1]= 3;
  rx[2]= 3;
  rx[3]= (len>>8) & 0xFF;
  rx[4]= len & 0xFF;

  mysha256_update(&sha0,ptr,err+11+2);

  err=ch_encrypt(ctx,ptr,err+11+2+1,rx+5,rx,5);

  return len;

}
int MakeEncryptedExtensions(CH_CTX *ctx)
{ char ext[7]=   {8,0,0,2,0,0,0x16};
  char auth[5]=  {0x17,3,3,0,0x17};
  int err;
 
  memmove(rx,auth,5);
  err= ch_encrypt(ctx,ext,7,rx+5,auth,5);
  mysha256_update(&sha0,ext,6);

return 0x17 ;
}
int MakeServerHello(int mode,int frand,char *pin, char *aid)
{   char *ptr =NULL;
    int len=0,err  ;
	char result[32];
	char zero[32]  ;

	ptr = &rx[5];
    ptr[0]=2;
	ptr[1]=ptr[2]=ptr[3]=0;    // length
	len=4;

	ptr[len++]=3;ptr[len++]=3; // version= TLS1.2

	err= myrnd(frand,ptr+len,32,pin,aid);
	len+=32;

	ptr[len++]= 0xFF & sidlen;
	memmove(ptr+len,sid,sidlen);
	len += sidlen;

    ptr[len++] = 0xFF & (MY_CIPHER>>8);
	ptr[len++] = 0xFF & MY_CIPHER;
	ptr[len++] = 0xFF & MY_COMPRESS;
 
	ptr[len++] = 0;  // extensions length
	if (mode == 1) ptr[len++] = 85;
	else           ptr[len++] = 79; // 85-6    
    
	if (mode == 1)
	{
    ptr[len++] = 0  ;
    ptr[len++] = 41; // pre_share_key
    ptr[len++] = 0;
    ptr[len++] = 2; // pre_share_key length
    ptr[len++] = 0; ptr[len++] = 0;
	}
    
	ptr[len++] = 0  ;
    ptr[len++] = 51; // key_share
    ptr[len++] = 0;
    ptr[len++] = 69; //  key_share length
    ptr[len++] = 0xFF & (MY_CURVE >> 8);
    ptr[len++] = MY_CURVE & 0xFF;
    ptr[len++] = 0 ;
    ptr[len++] = 65;
	memmove(ptr+len,mypubkey,65);
	len += 65;
    
	ptr[len++] = 0  ;
    ptr[len++] = 43; // supported_versions
    ptr[len++] = 0;
    ptr[len++] = 2 ; //  supported_versions length
    ptr[len++] = 0xFF & (MY_VERSION >> 8);
    ptr[len++] = 0xFF & MY_VERSION;
    	
	ptr[2] = 0xFF & ((len-4) >> 8) ;
	ptr[3] = 0xFF & (len-4)        ;

	mysha256_dup(&sha1,&sha0)      ;
	mysha256_update(&sha1,ptr,len) ;
    mysha256_final(&sha1,result)   ;

    myPrintf("SH_hash",result,32);
    
    DeriveSecret(myHandshakeSecret,32, "tls13 s hs traffic", result, 32, s_hs_traffic);
    DeriveSecret(myHandshakeSecret,32, "tls13 c hs traffic", result, 32, c_hs_traffic);
    DeriveSecret(myHandshakeSecret,32, "tls13 derived", esha256, 32, myMasterSecret);
	memset(zero,0,32);
    ComputePRK(myMasterSecret,32,zero,32,myMasterSecret);

	DeriveSecret(s_hs_traffic,16,"tls13 key",NULL,0,tx_key);
    DeriveSecret(s_hs_traffic,12,"tls13 iv",NULL,0,tx_iv);
	DeriveSecret(c_hs_traffic,16,"tls13 key",NULL,0,rx_key);
    DeriveSecret(c_hs_traffic,12,"tls13 iv",NULL,0,rx_iv);
    
    rx[0]=  0x16;
	rx[1] = 0x03;
	rx[2] = 0x03;
	rx[3] = 0xFF & (len >>8);
    rx[4] = 0xFF & len;
    return len;
}


int CheckClientFinished(CH_CTX * ctx )
{ int err;
  char f[37];
  char hs[]=  {0x17,3,3,0,0x35};
  char hd[] = {0x14,0,0,32};
  char k[32];
  char h[32];

  if (memcmp(rx,hs,5) != 0)
   return -1;

  err = ch_decrypt(ctx,rx+5,37+TAGSIZE,f,hs,5);
  if (err < 0)
	  return -1;
  
  if (f[36] != 0x16)
	  return -1;

  err= mysha256_dup(&sha1,&sha0);
  err= mysha256_final(&sha1,h)  ;
  
  myPrintf("hash",h,32);

  err= DeriveSecret(c_hs_traffic,32,"tls13 finished",NULL,0,k);

  err=ComputePRK(k,32,h,32,k);

  if (memcmp(f,hd,4) != 0)
	  return -1;

  if (memcmp(k,f+4,32) != 0)
	  return -1;
  
  DeriveSecret(myMasterSecret,32,"tls13 s ap traffic",h,32,s_ap_traffic);
  DeriveSecret(myMasterSecret,32,"tls13 c ap traffic",h,32,c_ap_traffic);
  DeriveSecret(s_ap_traffic,16,"tls13 key",NULL,0,tx_key);
  DeriveSecret(s_ap_traffic,12,"tls13 iv",NULL,0,tx_iv);
  DeriveSecret(c_ap_traffic,16,"tls13 key",NULL,0,rx_key);
  DeriveSecret(c_ap_traffic,12,"tls13 iv",NULL,0,rx_iv);
    
return 0;
}


int CheckClientChangeCipherSpec()
{  char ccs[] = {0x14,3,3,0,1,1};

    if (memcmp(rx,ccs,ptrx)!=0)
		return -1 ;

	return 0;
}



int CheckClientHello(int index,char *pin,char *aid)
{  char rec,ptcol, vhigh, vlow  ;
   int lenr, len,cipherlen,extlen;
   char *r,*s,*next;
   int remain,found;
   int i,cipher,ii=0;
   int fcipher=-1;
   int extype,err,pti;
   char result[32],v=0;
   char key[32],dkey[32];
   char cpk[65];
   int fpsk=0,fdhe=0,fpki=0,ftls13=0,fbinder=0;

  rec  = rx[0];
  vhigh= rx[1];
  vlow=  rx[2];

  lenr  =  (rx[3]<<8) & LMASK;
  lenr |=   rx[4] & 0xFF;

  ptcol = rx[5];
  if (rx[6] != 0) return -1;
  len =  (rx[7]<<8) & LMASK;
  len |=  rx[8] & 0xFF;
  
  if (len != (lenr-4)) 
	  return -1;
  
  remain=len;

  vhigh= rx[9] ;
  vlow=  rx[10];

 if ( (vhigh != 3) || (vlow != 3) )
	  return -1;
  
  r = &rx[11]; // random 32 bytes

  remain -= 34;
  
  sidlen= 0xFF & rx[43];
  if (sidlen >32)
	  return -1;
  s= &rx[44];
  memmove(sid,&rx[44],sidlen);
  
  remain -= (1+sidlen);

  if (remain <=0) 
	  return -1;

  next= s+sidlen;
  ii= 44+ sidlen;

  remain-=2 ;
  cipherlen  =  (next[0]<<8) & LMASK;
  cipherlen |=   next[1] & 0xFF;
  next+=2;
  ii+=2;

  remain -= cipherlen;
  if (remain <=0) 
	  return -1;


  //if ( (cipherlen >> 1) == 0)
   if ( (cipherlen &0x1) == 0x1)
	  return -1;

  for (i=0;i<cipherlen;i+=2)
  {  cipher  =  (next[i]<<8) & 0xFF00;
     cipher |=   next[i+1] & 0xFF;
	 if (cipher == (int)MY_CIPHER)
	 fcipher=1;
  }

  if (fcipher != 1)
	  return -1;

  next += cipherlen;
  ii+= cipherlen;
  

  remain -=1;
  if (remain <=0) 
	  return -1;
  len = 0xFF & next[0] ;
  
  remain -= len  ;
  if (remain <=0) 
	  return -1;


  found=0;
  for (i=0;i<len;i++)
  { if (next[i+1] == MY_COMPRESS)
	  found=1;
  }

  if (!found) 
	  return -1;
  
  next+=(1+len);
  ii+= (1+ len);

  remain -=2;
  if (remain <=0) 
	  return -1;

  extlen  =  (next[0]<<8) & LMASK;
  extlen |=   next[1] & 0xFF;
  next+=2;
  ii+=2;

  if (remain != extlen)
	  return -1;

  while (remain != 0)
  {
  remain-=4;
  if (remain <0) 
	  return -1;

  extype  =  (next[0]<<8) & 0xFF00;
  extype |=   next[1] & 0xFF;
  extlen  =  (next[2]<<8) & LMASK;
  extlen |=   next[3] & 0xFF;
  remain-=extlen ;
  next+= 4;
  ii+=4;
  
  if (remain < 0) 
	  return -1;

  switch (extype) 
  {
  case 45: // psk_key_exchange_modes
  err= check_key_exchange(extlen,next);
  if (err != 0) 
	  return -1;
  
  break;

  case 13: // signature_algorithms
  err= check_signature_algorithms(extlen,next);
  
  if (err == 0) 
	  fpki= 1;

  break;


  case 41:
  
  err= check_pre_share_key(extlen,next,&pti);
  
  if (err < 0)
	  return -1;

  fpsk=1;
  
  mysha256_init(&sha1);
  mysha256_update(&sha1,rx+5,ii+pti-5);
  mysha256_final(&sha1,result);

  pti=err;
 
  IM_open(pin,aid);
  err= IM_Finished(result,32,key);
  if (err < 0)
	  return -1;
  IM_close();

  if (memcmp((void *)(next+pti+1),(void *)key, 32) !=0)
  return -1;
  
  fbinder=1;

  break;

  case 11:
  err= check_ec_point_formats(extlen,next);
  if (err < 0)
	  return -1;
  break;


  case 51:
  err= check_key_share_extension(extlen,next,&pti);
   if (err < 0)
	  return -1;
   if (err != 65)
	   return -1;
  
  memmove(cpk,&next[2+pti],err);
  fdhe=1;
  break;

  case 43:
  err= check_supported_versions(extlen,next);
  if (err < 0)
  return -1;
  ftls13=1;
  break;
 

  case 10:
  err= check_supported_groups(extlen,next);
  if (err < 0)
  return -1;
  break;

  default:
  break;
  }

  next += extlen;
  ii+= extlen;

  }

  if (fpsk && fdhe && ftls13 && fbinder)
  {  
  IM_open(pin,aid);
  err= IM_ECDHE(index,cpk,65,dkey) ;
  if (err < 0)
	  return -1;
  err= IM_Extract_DHE(dkey,32,myHandshakeSecret);
  if (err < 0)
	  return -1;
  err= IM_ECDHE_PubK(index,NULL,65,mypubkey)  ;
  if (err < 0)
	  return -1;
  IM_close();
 
   return 1;
  }

  if (fpki && ftls13 && fdhe)
  {   
  IM_open(pin,aid);
  err= IM_ECDHE(index,cpk,65,dkey) ;
  if (err < 0)
	  return -1;
  err= IM_ECDHE_PubK(index,NULL,65,mypubkey)  ;
  if (err < 0)
	  return -1;
  IM_close();

  memset(result,0,32);
  v=0;
  ComputePRK(&v,1,result,32,myHandshakeSecret);
  //myPrintf("",myHandshakeSecret,32);
  DeriveSecret(myHandshakeSecret,32,"tls13 derived",esha256,32,myHandshakeSecret);
  //myPrintf("",myHandshakeSecret,32);
  ComputePRK(myHandshakeSecret,32,dkey,32,myHandshakeSecret);
  //myPrintf("",myHandshakeSecret,32);
	 
  return 2;
  }


  return -1;
}




int CheckServerHello(T_CTX * ctx)
{  char rec,ptcol, vhigh, vlow  ;
   int lenr, len,extlen;
   char *r,*s,*next;
   int remain,found;
   int cipher,ii=0;
   int fcipher=-1;
   int extype,err;
   char result[32],v=0;
   char dkey[32];
   char cpk[65];
   int fpsk=0,fdhe=0,fpki=0,ftls13=0;
   int curve;
   char zero[32];

   int mode = ctx->mode;
   int index= ctx->index;
   int ciphersuite= ctx->ciphersuite;
   char* rx= ctx->buf;

  rec  = rx[0];
  vhigh= rx[1];
  vlow=  rx[2];

  lenr  =  (rx[3]<<8) & LMASK;
  lenr |=   rx[4] & 0xFF;

  mysha256_update(&ctx->sha0,rx+5,lenr) ;
  mysha256_final(&ctx->sha0,result);
  //myPrintf("SH_hash",result,32)     ;

  mysha256_update(&ctx->sha1,rx+5,lenr);
  mysha256_update(&ctx->sha2,rx+5,lenr);

  ptcol = rx[5];
  if (ptcol != 2) return -1;
  if (rx[6] != 0) return -1;
  len =  (rx[7]<<8) & LMASK;
  len |=  rx[8] & 0xFF;
  
  if (len != (lenr-4)) 
	  return -1;
  
  remain=len;

  vhigh= rx[9] ;
  vlow=  rx[10];

 if ( (vhigh != 3) || (vlow != 3) )
	  return -1;
  
  r = &rx[11]; // random 32 bytes

  remain -= 34;
  
  sidlen= 0xFF & rx[43];
  if (sidlen >32)
	  return -1;
  s= &rx[44];
  memmove(sid,&rx[44],sidlen);
  
  remain -= (1+sidlen);

  if (remain <=0) 
	  return -1;

  next= s+sidlen;
  ii= 44+ sidlen;

  cipher  =  (next[0]<<8) & 0xFF00;
  cipher |=   next[1]     & 0xFF;
  next+=2;
  ii+=2  ;
  remain-=2;
  if (cipher == ciphersuite) //(int)MY_CIPHER)
  fcipher=1;
  

  if (fcipher != 1)
	  return -1;

  if (remain <=0) 
	  return -1;
  
  found=0;
  if (next[0] == MY_COMPRESS) found=1;
  if (!found) 
  return -1;
  
  next+=1;
  ii+=  1;
  remain -=1;
  if (remain <=0) 
  return -1;

  extlen  =  (next[0]<<8) & LMASK;
  extlen |=   next[1] & 0xFF;
  next+=2;
  ii+=2;
  remain -=2;

  if (remain != extlen)
	  return -1;

  while (remain != 0)
  {
  remain-=4;
  if (remain <0) 
	  return -1;

  extype  =  (next[0]<<8) & 0xFF00;
  extype |=   next[1] & 0xFF;
  extlen  =  (next[2]<<8) & LMASK;
  extlen |=   next[3] & 0xFF;
  remain-=extlen ;
  next+= 4;
  ii+=4;
  
  if (remain < 0) 
	  return -1;

  switch (extype) 
  {
  case 45: // psk_key_exchange_modes
  break;

  case 13: // signature_algorithms
  break;

  case 41: // pre share key =0

  if ( (next[0] != 0) || (next[1] != 0) )
	  return -1;
  fpsk=1;
  break;

  case 11:
  break;

  case 51: // key share
 
  curve  =  (next[0]<<8) & 0xFF00;
  curve |=  (next[1]     & 0xFF) ;
  if (curve != MY_CURVE) return -1;
  err  =  (next[2]<<8) & 0xFF00;
  err |=  (next[3]     & 0xFF) ;
  if (err != 65) return -1;
  memmove(cpk,next+4,65);
  fdhe=1;
  break;

  case 43: // supported version
  
  err  =  (next[0]<<8) & 0xFF00;
  err |=  (next[1]     & 0xFF) ;
  if ( (extlen == 2) && (err == 0x0304) )
  ftls13=1;
  else return -1;
  break;
 
  default:
  break;
  }

  next += extlen;
  ii+= extlen;

  }

  if (fpsk && fdhe && ftls13)
  {  

  if ( (ctx->mode & CDHIM) == CDHIM )
  { IM_open(ctx->pin,ctx->aid);
    if ( (ctx->mode & CTEST) == CTEST )
    err= IM_ECDHE(index,cpk,65,dkey) ; // dkey= Diffie Hellman
	else
	{ err= IM_ECDHE(-255,cpk,65,dkey) ; // dkey= Diffie Hellman
      if (err < 0) return -1;
	  err= IM_ClearKeyDH();
      if (err < 0) return -1;
	}
    err= IM_Extract_DHE(dkey,32,ctx->hs); // compute handshake secret
    if (err < 0)  return -1;
    //err= IM_ECDHE_PubK(index,NULL,65,mypubkey); // retreive public key
    //if (err < 0) return -1;
    IM_close();
  }

  else if ( (ctx->mode & CDHNET) == CDHNET )
  { 
	err= dhecc(cpk,ctx->privkey,dkey);
    if (err != 0)
		 return -1;
	err= TLSIM_derive(ctx->netctx,dkey,32,ctx->hs); // compute handshake secret
    if (err < 0)
	  return -1;

  }

  else
  {  err= dhecc(cpk,ctx->privkey,dkey);
     if (err != 0)
		 return -1;

     if ( (ctx->mode & CDERIVEIM) == CDERIVEIM)
	 { IM_open(ctx->pin,ctx->aid);
	   err= IM_Extract_DHE(dkey,32,ctx->hs); // compute handshake secret
       if (err < 0) return -1;
       IM_close();
	 }
	 else
		 derive(dkey,ctx->hs,&ctx->imctx);
  }

  
  //mysha256_dup(&sha1,&sha0)         ;
  //mysha256_update(&sha1,rx+5,len+4) ;
  //mysha256_final(&sha1,result)      ;
  //myPrintf("SH_hash",result,32)     ;
 
 // mysha256_update(&ctx->sha0,rx+5,lenr) ; //?
 // mysha256_final(&ctx->sha0,result);
 // myPrintf("SH_hash",result,32)     ;


  if ( (mode & CTEST) != CTEST )
  {
  DeriveSecret(ctx->hs,32, "tls13 s hs traffic", result, 32, ctx->s_hs_traffic);
  DeriveSecret(ctx->hs,32, "tls13 c hs traffic", result, 32, ctx->c_hs_traffic);
  DeriveSecret(ctx->hs,32, "tls13 derived", esha256, 32, ctx->ms);
  memset(zero,0,32);
  ComputePRK(ctx->ms,32,zero,32,ctx->ms);
  DeriveSecret(ctx->s_hs_traffic,16,"tls13 key",NULL,0,ctx->tx_key);
  DeriveSecret(ctx->s_hs_traffic,12,"tls13 iv",NULL,0,ctx->tx_iv);
  DeriveSecret(ctx->c_hs_traffic,16,"tls13 key",NULL,0,ctx->rx_key);
  DeriveSecret(ctx->c_hs_traffic,12,"tls13 iv",NULL,0,ctx->rx_iv);


  /*
  DeriveSecret(myHandshakeSecret,32, "tls13 s hs traffic", result, 32, s_hs_traffic);
  DeriveSecret(myHandshakeSecret,32, "tls13 c hs traffic", result, 32, c_hs_traffic);
  DeriveSecret(myHandshakeSecret,32, "tls13 derived", esha256, 32, myMasterSecret);
  memset(zero,0,32);
  ComputePRK(myMasterSecret,32,zero,32,myMasterSecret);
  DeriveSecret(s_hs_traffic,16,"tls13 key",NULL,0,tx_key);
  DeriveSecret(s_hs_traffic,12,"tls13 iv",NULL,0,tx_iv);
  DeriveSecret(c_hs_traffic,16,"tls13 key",NULL,0,rx_key);
  DeriveSecret(c_hs_traffic,12,"tls13 iv",NULL,0,rx_iv);
  */
    
  }
 
  else
  {
  }
	
  
  //
  err = ch_init(&ctx->ctx0,ctx->tx_key,ctx->tx_iv,ctx->ciphersuite);
  err = ch_init(&ctx->ctx1,ctx->rx_key,ctx->rx_iv,ctx->ciphersuite);

  return 1;

  }

  if (fpki && ftls13 && fdhe)
  {   
  /*
  IM_open(mypin);
  err= IM_ECDHE(index,cpk,65,dkey) ;
  if (err < 0)
	  return -1;
  err= IM_ECDHE_PubK(index,NULL,65,mypubkey)  ;
  if (err < 0)
	  return -1;
  IM_close();

  memset(result,0,32);
  v=0;
  ComputePRK(&v,1,result,32,ctx->hs);
 //myPrintf("",myHandshakeSecret,32);
  DeriveSecret(ctx->hs,32,"tls13 derived",esha256,32,ctx->hs);
  //myPrintf("",myHandshakeSecret,32);
  ComputePRK(ctx->hs,32,dkey,32,ctx->hs);
  //myPrintf("",myHandshakeSecret,32);
	 
  return 2;
  */
	  return -1;
  }


  return -1;
}

int CheckEncryptedOPtions(T_CTX *ctx)
{ int err,lenr;
  char *rx= ctx->buf;

  lenr  =  (rx[3]<<8) & LMASK;
  lenr |=   rx[4] & 0xFF;
 

  err = ch_decrypt(&ctx->ctx0,rx+5,lenr,rx+5,rx,5);
  if (err <0) 
	  return -1;

  mysha256_update(&ctx->sha1,rx+5,err-1);
  mysha256_update(&ctx->sha2,rx+5,err-1);


 return err;
}
int CheckServerFinished(T_CTX *ctx)
{ char hk[5+4+32+1] ;
  char k[32];
  char h[32];
  int err,lenr;
  char *rx= ctx->buf;

  lenr  =  (rx[3]<<8) & LMASK;
  lenr |=   rx[4] & 0xFF;

  hk[0]= 0x17;
  hk[1]=3;
  hk[2]=3;
  hk[3]=0;
  hk[4]=0x35;
 
  hk[5+0]=0x14;
  hk[5+1]=0;
  hk[5+2]=0;
  hk[5+3]=0x20;
  hk[5+4+32]=0x16;

  //err= mysha256_dup(&sha1,&sha0);
  //err= mysha256_final(&sha1,h)  ;

  mysha256_final(&ctx->sha1,h);

  err= DeriveSecret(ctx->s_hs_traffic,32,"tls13 finished",NULL,0,k);

  //for(i=0;i<32;i++)
  //printf("%02X", 0xFF & k[i]);
  //printf("\n");

  err=ComputePRK(k,32,h,32,h);

  //for(i=0;i<32;i++)
  //printf("%02X", 0xFF & h[i]);
  //printf("\n");

  memmove(hk+5+4,h,32)  ;
  //myPrintf("hk",hk,37);
  
  ////////////////////////////////////
  //err= mysha256_update(&sha0,hk,4+32);
  ////////////////////////////////////
  
  err = ch_decrypt(&ctx->ctx0,rx+5,lenr,rx+5,rx,5);
   if (err <0) 
	  return -1;
  
  mysha256_update(&ctx->sha2,rx+5,err-1);
 

if (memcmp(rx,hk,err+5) == 0)
return err;

return -1 ;

}

int MakeClientFinished(T_CTX * ctx)
{ int err;
  char f[42];
  char hs[]=  {0x17,3,3,0,0x35};
  char hd[] = {0x14,0,0,32};
  char k[32];
  char h[32];

  char *rx=ctx->buf;
  
  //err= mysha256_dup(&sha1,&sha0);
  //err= mysha256_final(&sha1,h)  ;
  //myPrintf("hash",h,32);
  //645B7BAB9F007971D4F0891A955ADF6F67ED2937AABF9EB3DD5D46D59A777CBC

 mysha256_final(&ctx->sha2,h);
 //myPrintf("hash",h,32);


  err= DeriveSecret(ctx->c_hs_traffic,32,"tls13 finished",NULL,0,k);

  err=ComputePRK(k,32,h,32,k);

  memmove(f,hs,5);
  memmove(f+5,hd,4);
  memmove(f+9,k,32);
  f[9+32]=0x16;

  err = ch_encrypt(&ctx->ctx1,f+5,37,rx+5,f,5);
  memmove(rx,f,5);

  // myPrintf("ClientFinished",rx,5+err);
  // 1703030035
  // 09DAF2DE2EF379F6761DE5EC388E5F4F8EEEC8FF6BB5E218122BA
  // 3E2E863CA4BA7E4AFCA1466C3ABC50A95B120CD93B567AD08B29B

  DeriveSecret(ctx->ms,32,"tls13 s ap traffic",h,32,ctx->s_ap_traffic);
  DeriveSecret(ctx->ms,32,"tls13 c ap traffic",h,32,ctx->c_ap_traffic);
  DeriveSecret(ctx->s_ap_traffic,16,"tls13 key",NULL,0,ctx->tx_key);
  DeriveSecret(ctx->s_ap_traffic,12,"tls13 iv",NULL,0,ctx->tx_iv);
  DeriveSecret(ctx->c_ap_traffic,16,"tls13 key",NULL,0,ctx->rx_key);
  DeriveSecret(ctx->c_ap_traffic,12,"tls13 iv",NULL,0,ctx->rx_iv);
    
return err+5;
}


int myrnd_init()
{   
//#ifndef IM_RANDOM
time_t t;
srand((unsigned) time(&t));
//#endif
	return 0;
}

int myrnd(int mode, char *r, int len, char *pin, char *aid)
{ int err,i ; 

      if (mode == 1)
	  err= Ascii2bin("7a 35 2d bc ed b3 60 bf 03 c3 45 08 63 2a 5a a5\
                      ce 0d 0d b7 3f 78 7d 8e e8 53 f5 d7 3b 25 93 94",r);
	  else if (mode == 2)
      err= Ascii2bin("3b 8d 8b 94 c8 4f 60 a1 0a a9 3e d1 e3 24 dd 43\
					  8a fd 28 41 c2 59 16 38 89 88 45 dc 74 00 21 5b",r);

	  else if (mode == 3)
      err= Ascii2bin("ed 49 be 48 24 06 86 1b 59 d4 35 b5 67 90 9b 26\
					  cd 95 a0 92 ac f4 91 b4 2d bc 1e ab 7c df f7 e6",r);

	  else if (mode == 4)
      err= Ascii2bin("e4 d6 2f 95 ac af 77 18 9b f8 17 ae 69 3a 70 56\
					  b2 e3 fa de da c0 cf 09 85 62 13 d3 e1 9a 00 48",r); 

#ifdef IM_RANDOM
      else if ( (mode & CIMRANDOM) == CIMRANDOM )
	  {  err= IM_open(pin,aid);
		 err =IM_Random(len,r);
		 err= IM_close();
		 return len;
	  }
#endif
      else
	  { for(i=0;i<len;i++)
	    *(r+i)= 0xff & rand();
		return len;
	  }
return err;
}



extern int TxAPDU(char * apdu);



int tls13_se(int fecho, int port,char *pin, char *aid,int timeout)
{ int err,fend,C_OPEN=1,C_CLOSE=2,f_open=0;
  char f_P1=0,v;

  IM_init(aid); 
  IM_open(pin,aid);
  
  startTCPIP();
  server_init(port);

  while(1)
  { 
  f_open=0;f_P1=0;
  //IM_init();IM_open(mypin);
  err=TxAPDU("00D8000000");
  if (err < 0) break  ;
  err = server_wait() ;
  if (err < 0) break  ;
  
  while(1)
  { err=ptrx=NetRecv(rx,(int)sizeof(rx),timeout);
      
   if (err <=0) { //IM_close();
                  close_client();f_open=0;break; }

   if (f_open == 1)  f_P1=(char)1; // Decrypt
   else              f_P1=(char)0;

   fend = IM_send(rx,ptrx,rx,&ptrx,f_P1);
  
   if (fend < 0)
   {//IM_close;
    close_client(); f_open=0;break;}

   if (f_P1 == (char)1)
   { if (ptrx > 1)
     { v = rx[ptrx-3];rx[ptrx-3]=0;// remove CrLf
       printf("Rx: %s ptcol=%2.2X\n",rx,rx[ptrx-1] & 0xFF);
       rx[ptrx-3]=v; rx[ptrx-1]=(char)0x17; f_P1=(char)2;// Encrypt
	   fend = IM_send(rx,ptrx,rx,&ptrx,f_P1);
	   // fend = C_CLOSE;
	   // ptrx=0;
     }
   }

   if (ptrx !=0)
   { err = NetSend(rx,ptrx);
     if (err <0) {
		 //IM_close();
		 close_client(); f_open=0; break;}
   }
   
   if (fend == C_OPEN)
   {   printf("TLS13 session is open\n");
       if (fecho == 1) f_open=1;
   }

   if (fend == C_CLOSE)
   printf("TLS13 session is closed\n");
 
   if (fend == C_CLOSE)
   { //IM_close();
     close_client();f_open=0; break;}
  
  }
  }

return 0;
  }




int _tls13(char *pin, char *aid,int timeout)
{ int err ;
  
  char msg[]= "Welcome on board\r\n";
  int fpsk= 1;

  IM_init(aid);
  myrnd_init();

  mysha256_init(&sha1);
  mysha256_final(&sha1,esha256);
  
  mysha256_init(&sha0);
  startTCPIP();
  server_init(444);

  while(1)
  { 
  mysha256_final(&sha0,rx);
  mysha256_init(&sha0);
  
  err = server_wait() ;
  if (err < 0) 
	  break;
  
  err=ptrx=NetRecv(rx,(int)sizeof(rx),timeout);
  
  if (err <=0) 
  continue;

  mysha256_update(&sha0,rx+5,err-5);
   
  if (rx[5] == 0x01)
  err= CheckClientHello(0xFF,pin,aid);
  
  else 
  { close_client(); continue;}

  if ( err < 0) 
  { close_client(); continue;}


  if (err==1) fpsk=1;
  else        fpsk=0;

  if (fpsk) err= MakeServerHello(1,0,pin,aid);
  else      err= MakeServerHello(2,0,pin,aid);

  if (err < 0) 
  { close_client(); continue;}

  mysha256_update(&sha0,rx+5,err);

  err = NetSend(rx,err+5);
  if (err <0)
  { close_client(); continue;}

   err = ch_init(&ctx0,tx_key,tx_iv,AES128GCM);
   err = ch_init(&ctx1,rx_key,rx_iv,AES128GCM);
    
   err = MakeEncryptedExtensions(&ctx0);
 
   err = NetSend(rx,err+5);
   if (err <0)
   { close_client(); continue;}

   if (!fpsk)
   { err = MakeEncryptedCertificate(&ctx0);
     err = NetSend(rx,err+5);
     if (err <0)
     { close_client(); continue;}
     err = MakeEncryptedVerify(&ctx0,0,pin,aid);
     err = NetSend(rx,err+5);
     if (err <0)
     { close_client(); continue;}

   }

   err= MakeEncryptedFinished(&ctx0);
   if (err <0)
   { close_client(); continue;}

   err = NetSend(rx,err+5);
   if (err <0)
   { close_client(); continue;}

   err=ptrx=NetRecv(rx,(int)sizeof(rx),timeout);
   if (err <=0) 
	{	ch_free(&ctx0); ch_free(&ctx1);
		close_client(); 
		continue;
	}

   if (rx[0] == (char)0x14)
   {
   err= CheckClientChangeCipherSpec();
   
   if (err != 0) 
   {   ch_free(&ctx0); 
       ch_free(&ctx1);
	   close_client(); 
	   continue;
   }

   
	err=ptrx=NetRecv(rx,(int)sizeof(rx),timeout);
	if (err <=0)
	{   ch_free(&ctx0); 
	    ch_free(&ctx1);
		close_client(); 
		continue;
	}
   }

   err= CheckClientFinished(&ctx1);
   if (err !=0)
   {   ch_free(&ctx0); ch_free(&ctx1);
	   close_client(); 
	   continue;
   }

    ch_free(&ctx0);
    ch_free(&ctx1);
    err = ch_init(&ctx0,tx_key,tx_iv,AES128GCM);
    err = ch_init(&ctx1,rx_key,rx_iv,AES128GCM);

   
    err=ptrx=NetRecv(rx,(int)sizeof(rx),timeout);
	if (err <= 0)
	 { ch_free(&ctx0); ch_free(&ctx1);
	   close_client(); 
	   continue;
     }
	
	err = ch_decrypt(&ctx1,rx+5,ptrx-5,rx+ptrx,rx,5);
	if (err <= 0) 
    { ch_free(&ctx0); ch_free(&ctx1); close_client(); continue; }

    if (*(rx+ptrx+err-1) != 0x17)
    { ch_free(&ctx0); ch_free(&ctx1); close_client(); continue; }
     
	 *(rx+ptrx+err-1) = 0 ;
	 printf("%s",rx+ptrx);

	 err = (int)strlen(msg); 
	 *(rx+5+err+1+TAGSIZE+err) = 0x17;
	 memmove(rx+5+err+1+TAGSIZE,msg,err);
	 rx[0] = 0x17; rx[1]=3;rx[2]=3;
	 rx[3] = 0xFF & ((err+1+TAGSIZE)<<8);
     rx[4] = 0xFF &  (err+1+TAGSIZE);

	 err = ch_encrypt(&ctx0,rx+5+err+1+TAGSIZE,err+1,rx+5,rx,5);
     err = NetSend(rx,err+5);
     if (err <0)
     { close_client(); continue;}


    ch_free(&ctx0);
    ch_free(&ctx1);

	close_client();
	
	}

    close_client();
    close_server();
	stopTCPIP();

	return 0;
}



void util()
{  int k,r,adr,l,s=32,err,i;
   char t[64]= "I hear you fa shizzle!";
   char stest[]= "0085FF0A230100200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";
  
   char FSK[] ="FCA24690D17DDE3F727D29D2186A5F83E1AEBD4889A4841793139168A65BFCB0";
   char DSK[]= "E8E7AC087158FC8440E41A12989F9194783764CD5FC36564028037F2C8206E96";
   char pub[]= "047ff01323cc74383e0e8eb80bea4ea45e55b85499abd39d719885e874ed3f6327960d519ba25423c3fbdc14e6fd0cd5edee";
   char priv[]="2e86bdd6d3b241ddbd00999f6a0ac1cb546d2bfb55744dca40f0268ac2bf7338";
   char pub1[]="04 F0C2A4942AB1AA0F4A4558E23F5CD1F0BC7A1544D12E32EA674FE5E542B5049340C59A83878C9DA5E69B8F7DCA785CADFDF03D26A5DEB8C1D5BB9C26C36F4341";
   char priv1[]="44339F299B09AD743B9F69D33654057CA50419D64FCC8235FB3C5D862569D69C";
   char pub2[]="04 37232040741008CF078D96BC8EAFC76365FC6A98AF30203B6022739813677FA26C1E014A5F8CFA67DD0DB7F97B912023B86063E3B9BEADC95D9F1C9CCD1209B6";
   char priv2[]="CFEBA5FB779C84ED89EF364B892E916F52CE6BC20F3A856129EEDE4D1D07BDCB";



//"tls13 s hs traffic"
//"tls13 c hs traffic"
//"tls13 derived"
//"tls13 key"
//"tls13 iv"
//"tls13 s ap traffic"
//"tls13 c ap traffic"
// "tls13 finished"
//


   err= Ascii2bin(stest,rx);
   
   //printf("\n");
   for(i=0;i<err;i++)
   { printf("%s%02X ","0x",0xFF & rx[i]);
   }
  printf("\n\n");

   err= Ascii2bin(FSK,rx);
   for(i=0;i<err;i++)
   { printf("%s%02X, ","0x",0xFF & rx[i]);
   }
   printf("\n\n");

   err= Ascii2bin(DSK,rx);
   for(i=0;i<err;i++)
   { printf("%s%02X, ","0x",0xFF & rx[i]);
   }
printf("\n\n");

   err= Ascii2bin(priv2,rx);
   for(i=0;i<err;i++)
   { printf("%s%02X, ","0x",0xFF & rx[i]);
   }

printf("\n\n");


   err= Ascii2bin(pub2,rx);
   for(i=0;i<err;i++)
   { printf("%s%02X ","0x",0xFF & rx[i]);
   }

printf("\n\n");

   

   err= (int)strlen(t);
   printf("= {");
   for(i=0;i<err;i++)
   { printf("(byte)%s%c%s","'",t[i],"'");
     if (i != (err-1)) printf(",");
   }
   printf("};");

   err= Ascii2bin("hello",rx);
   for(i=0;i<err;i++)
   {  if ((i!=0) && (i%16 == 0) ) printf("\\\n"); 
	  printf("%s%02X%s","0x",0xFF & rx[i],",");
     
   }
   err= Ascii2bin("040B5A6EC31366D6FC7ACB5C0E6EF15335D4DE88B04A5E4CE493E6B8FFB46B243F3261FAB90AA141A5FE646410204FEA2DC45823710AE71606A38D2E42A7D574FF",rx);
   
   printf("\n");
   printf("= {");
   for(i=0;i<err;i++)
   { printf("(byte)%s%02X","0x",0xFF & rx[i]);
     if (i != (err-1)) printf(",");
   }
   printf("};");
   
   
   err= Ascii2bin("00D800033A1703030035F02BF4DFB2D77F4395DF44187EA69041CD84E3F9F7206AF4E93AFED586702D0F44427D74B8C4773AA17DEA360F82658C5551681612",rx);
   
   printf("\n");
  for(i=0;i<err;i++)
   { printf("%s%02X ","0x",0xFF & rx[i]);
   }
   printf("\n");


   
   r=err;
   adr= 0;

   printf("\n");printf("\n");
   r=err;
   for(i=0;i<err;i+=s)
   {  
	  if (r>16) l=s;
      else      l=r;
	 
	  printf("00D0 %04X %02X ",adr,l);
	  for(k=0;k<l;k++) printf("%02X",0xFF & rx[i+k]);
	  printf("\n");
	 
      r   -= s;
	  adr += s;
   }
   printf("\n");

   
}




// se_echo 20 115200 nodebug t0 F=6000 pts=2


extern int proxys(int comport, int baud,int port);
extern int fmono;


int MakeClientHello (T_CTX* ctx)
{   char *ptr =NULL;
    int len=0,err,sidlen=32 ;
	char result[32];
	int pto=0;
	//
	int mode= ctx->mode;
    int index = ctx->index;
    char * buf= ctx->buf;
    char *id= ctx->identity;
    char *sn = ctx->sn;
    int ciphersuite = ctx->ciphersuite;


	memset(ctx->buf,0,ctx->bufmax);

    ptr = buf;
    ptr[0]=22;
    ptr[1]=03;
    ptr[2]=01;
    ptr[3]=0x01;
    ptr[4]=0x21; // 289

	ptr = buf+5;
	len=0;

    ptr[len++]=1; //5
	ptr[len++]=0; //6

	ptr[len++]=0x01; //7
	ptr[len++]=0x1d; //8 length 285
	
	ptr[len++]=3;ptr[len++]=3; // version= TLS1.2

	//err= myrnd(mode,ptr+len,32);
    if ((mode & (int)CTEST) == (int)CTEST) err= myrnd(3   ,ptr+len,32,ctx->pin,ctx->aid);
	else                                   err= myrnd(mode,ptr+len,32,ctx->pin,ctx->aid);
	len+=32;

	ptr[len++]= 0xFF & sidlen;
	if ((mode & (int)CTEST) == (int)CTEST) err= myrnd(4   ,ptr+len,32,ctx->pin,ctx->aid);
	else                                   err= myrnd(mode,ptr+len,32,ctx->pin,ctx->aid);
	len += sidlen;

	ptr[len++]= 0; ptr[len++]= 4; // Cipher Suite Length
    ptr[len++]= 0xFF & (ciphersuite>>8); // 1301 = AES_128_GCM
	ptr[len++]= 0xFF &  ciphersuite;
	ptr[len++]= 0; ptr[len++]= 0xFF; // 00ff  TLS empty renegotiation info scsv 

    ptr[len++] = 1; // METHOD COMPRESSION 
	ptr[len++] = 0xFF & MY_COMPRESS;
   
	pto=len;
	ptr[len++] = 0;  // extensions length
	if ((mode & CTEST) == CTEST) ptr[len++] = 208; // 0xD0
	else                         ptr[len++] = 79;

    // SNI 0000, 000D, 000B, 00=hostname, 0008, 6B6579312E636F6D
	if ( ((mode & CTEST) != CTEST)  && (sn!= NULL))
	{ 
	err = (int)strlen(sn);
	ptr[len++]= 0; ptr[len++]= 0x00; //SNI
	ptr[len++]= 0; ptr[len++]= 0xFF & (5+err); //length
    ptr[len++]= 0; ptr[len++]= 0xFF & (3+err); //length
    ptr[len++]= 0; // Host name
    ptr[len++]= 0; ptr[len++]= 0xFF & err; //length
    memmove(ptr+len,sn,err);
	len+=err;
	}
    
	//00 0b 00 04 03 00 01 02 
    ptr[len++]= 0; ptr[len++]= 0x0B; //ecc format
	ptr[len++]= 0; ptr[len++]= 0x04; //length
    ptr[len++]= 3; //length
	ptr[len++]= 0x00; ptr[len++]= 0x01; ptr[len++]= 0x02; 
   
    ptr[len++]= 0; ptr[len++]= 0x0A; //supported groups
	ptr[len++]= 0; ptr[len++]= 0x04; //length
    ptr[len++]= 0; ptr[len++]= 0x02; //length
    ptr[len++]= 0; ptr[len++]= 0x17; //SECP256r1

    ptr[len++]= 0; ptr[len++]= 22; //encrypt then mac
    ptr[len++]= 0; ptr[len++]= 0 ; //length 

    ptr[len++]= 0; ptr[len++]= 23; //extended master secret
    ptr[len++]= 0; ptr[len++]= 0 ; //length 

	if ( (mode & CTEST) == CTEST )
    {
    ptr[len++]= 0; ptr[len++]= 13; //signatures algorithms  0403 = secp256r1 + sha256
    ptr[len++]= 0; ptr[len++]= 30; //length 
    ptr[len++]= 0; ptr[len++]= 28; //length 
    err= Ascii2bin("04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b\
                    08 04 08 05 08 06 04 01 05 01 06 01",ptr+len);
	len+=err;
	}
	else
	{ptr[len++]= 0; ptr[len++]=  13; //signatures algorithms  0403 = secp256r1 + sha256
     ptr[len++]= 0; ptr[len++]=   4; //length 
     ptr[len++]= 0; ptr[len++]=   2; //length
     ptr[len++]= 04; ptr[len++]= 03; 
	}
    
    ptr[len++]= 0; ptr[len++]= 43; //supported version
    ptr[len++]= 0; ptr[len++]= 3 ; //length 
    ptr[len++]= 2; //length
	ptr[len++]= 0x03;ptr[len++]= 0x04; 

    ptr[len++]= 0; ptr[len++]= 45; //psk key exchange
    ptr[len++]= 0; ptr[len++]= 2 ; //length 
    ptr[len++]= 1; // length
    ptr[len++]= 1; // psk-dh-ke

    ptr[len++]= 0; ptr[len++]= 51; //key share
    ptr[len++]= 0; ptr[len++]= 71; //length 
    ptr[len++]= 0; ptr[len++]= 69; //length 
    ptr[len++]= 0; ptr[len++]= 0x17; //group secp256r1
    ptr[len++]= 0; ptr[len++]= 0x41; //key length
   
	if ( (mode & CTEST) == CTEST)
    err= Ascii2bin("04 38 a0 70 80 aa 63 50 a2 c2 84 29 e8 21\
                    1a 84 0a 2c ed 57 56 06 fb 1c e0 b3 6b 23 e2 53\
                    77 c5 78 be ea 2f e7 47 d4 22 e7 da 35 24 d8 ed\
                    5e 02 2d 1b ea 9f b3 2f 20 2b ff 91 b8 2d 6c 91\
                    f6 16 64",ptr+len);
	else
	{  
	   if ( (mode & CDHIM) == CDHIM)
	   { IM_open(ctx->pin,ctx->aid);
	     err= IM_GenkeyDH(ptr+len);// mypubkey
         IM_close();
	     if (err != 0) return -1;
	   }
	   
	   else
	   {err = genkeyecc(ptr+len,ctx->privkey);
	    if (err != 0) return -1;
	   }
	   
	   err=65;
	}
	memmove(ctx->pubkey,ptr+len,65);
 	len+=err;

	err= (int)strlen(id);
    ptr[len++]= 0; ptr[len++]= 41; //pre shared key
    ptr[len++]= 0; ptr[len++]= 43+err; //58 length 
    ptr[len++]= 0; ptr[len++]= 6+err;  //21 length 
    ptr[len++]= 0; ptr[len++]= 0xff & err; //length = 15 
	strcpy(ptr+len,id);
	len+= (int)strlen(id);
    ptr[len++]= 0;ptr[len++]= 0;ptr[len++]= 0;ptr[len++]= 0; //obfuscated ticket age
    
	ptr[len++]= 0;ptr[len++]= 33;
	ptr[len++]= 32;
	//binder
    
	err= len+32;
	buf[3]= 0xFF & (err >> 8);
	buf[4]= 0xFF & err;
  	
	err= len+32-4;
	ptr[2]=0xFF & (err >> 8);
	ptr[3]=0xFF & err;
	
	err= len+32-(pto+2);
	ptr[pto]  = 0xFF & (err >> 8);
    ptr[pto+1]=0xFF & err;
	
    mysha256_init(&ctx->sha0);
    mysha256_update(&ctx->sha0,ptr,len-3);
    mysha256_final(&ctx->sha0,result);

	if ((mode & CBINDERIM) == CBINDERIM)
	{ IM_open(ctx->pin,ctx->aid);
      err= IM_Finished(result,32,ptr+len);
      if (err < 0)
		  return -1;
	  IM_close();
	}
	else if ((mode & CBINDERNET) == CBINDERNET)
	{ err= TLSIM_binder(ctx->netctx,result,32,ptr+len);
      if (err < 0)
		  return -1;
	}
	else
    binder(result,ptr+len,&ctx->imctx);
	
	len+=32;
	
	//myPrintf("chello",ptr,len);

     mysha256_init(&ctx->sha0);
     mysha256_init(&ctx->sha1);
     mysha256_init(&ctx->sha2);
     mysha256_update(&ctx->sha0,5+ctx->buf,len);
     mysha256_update(&ctx->sha1,5+ctx->buf,len);
     mysha256_update(&ctx->sha2,5+ctx->buf,len);
 
    return len+5;
}



extern void tls13_c(T_CTX * ctx);
extern int test_ecc();
extern int parse(int argc, char  **argv, T_CTX *ctx);


// client tlsse.dyndns.org 7786 Client_identity  key7.com  aesccm
// tclient
// psk

extern int fconsole;
void default_ctx(T_CTX * tctx, T_CTX * tctx2, char *rx, int maxrx, char *rx2, int maxrx2)
{ int i;
       
     memset((char*)tctx, 0,(int)sizeof(T_CTX));
     memset((char*)tctx2,0,(int)sizeof(T_CTX));
     
     mysha256_init(&sha0);
     mysha256_final(&sha0,esha256);
	 
	 tctx->name=  "192.168.1.33";
     tctx->port=  8888;
	 //tctx->name=  "127.0.0.1";
     //tctx->name=  "192.168.1.41";
     //tctx->name=  "10.5.0.2";
     //tctx->port=  444;
     tctx->identity="Client_identity";
     tctx->sn="key20.com";
	 tctx->ciphersuite = AES128CCM ;
     tctx->index=0;
     strcpy(tctx->pin,"0000");
	 strcpy(tctx->aid,"010203040800");
	 tctx->mode=0 ;
	 tctx->buf=rx;
	 tctx->bufmax=maxrx;
	 for(i=0;i<32;i++) tctx->psk[i]= i+1;
	 strcpy(tctx->CAPub,"046099836D971593AAA2C1C32B6DB9EF9521041795E21CF1E7511DF3BD358F97DF358B33A875E359CBE236163D6DBAEDFEC6C9393522C7EBC25A7CC85E1F0A7D67");
     strcpy(tctx->CAPriv,"0102030405060708091011121314151617181920212223242526272829303132");
	 tctx->mode = CBINDERSOFT | CDHSOFT  ;
     //tctx->mode = CBINDERIM |   CDERIVEIM  ;
     //tctx->mode = CBINDERNET  | CDHNET   ;
	 //
	 tctx2->name= "192.168.1.49";
	 tctx2->port= 444;
     tctx2->identity= "Client_identity";
     tctx2->sn="key1.com";
	 tctx2->ciphersuite = AES128GCM ;
	 tctx2->buf=rx2;
	 tctx2->bufmax=maxrx2;
     strcpy(tctx2->aid,"010203040800");
	 strcpy(tctx2->pin,"0000");
     for(i=0;i<32;i++) tctx2->psk[i]= i+1;
     tctx2->mode = CBINDERSOFT | CDHSOFT ;
     tctx2->index=0;

     tctx->timeout=5 ;
     tctx2->timeout=5;

	 init_imv(tctx2->psk,0,&tctx2->imctx);
     tctx->netctx= tctx2;
     //tctx->psk[0]=255;
     init_imv(tctx->psk,0,&tctx->imctx);
     

}

int testtls13psk(char *aid, char *pin)
{ int err,len,i;
  char result[32];
  char psk[32];
  T_CTX tctx;
  T_CTX tctx2;

  memset((char*)&tctx, 0,(int)sizeof(T_CTX));
  memset((char*)&tctx2,0,(int)sizeof(T_CTX));
  for(i=0;i<32;i++) psk[i]=i+1;
  
  init_imv(psk,0,&tctx.imctx);
  
    tctx.ciphersuite = AES128GCM ;
     tctx.sn="key1.com";
	 tctx.identity="Client_identity";
	 strcpy(tctx.aid,aid);
     strcpy(tctx.pin,pin);
	 tctx.index=1;
     tctx.mode= 0;
	 tctx.mode= (int)CTEST | (int)CBINDERSOFT | (int)CDHIM ;
     //tctx.mode= (int)CTEST | (int)CBINDERSOFT | (int)CDHSOFT ;
	 tctx.buf=rx;
	 tctx.bufmax=(int)sizeof(rx);
	 err= MakeClientHello(&tctx);
   

   err= GetRecord();
   if (err <=0) return -1;
   myPrintf("ClientHello",rx,ptrx);

   mysha256_init(&sha1);
   mysha256_update(&sha1,rx+5,err);
   mysha256_final(&sha1,result);
   myPrintf("hash0",result,32);


    mysha256_init(&sha0);
   ////////////////////////////////
    mysha256_update(&sha0,rx+5,err);
   ////////////////////////////////

   err= CheckClientHello(1,pin,aid);
   if (err != 1) return -1         ;

   err= MakeServerHello(err,err,pin,aid);
   if (err <= 0) return -1;
   
   myPrintf("ServerHello",rx,err+5);
   //myPrintf("HS",myHandshakeSecret,32);
   //myPrintf("MasterSecret",myMasterSecret,32);
	  
     memmove(tctx.hs,myHandshakeSecret,32);
	 memmove(tctx.ms,myMasterSecret,32);
	 memmove(tctx.tx_key,tx_key,16);
     memmove(tctx.rx_key,rx_key,16);
	 memmove(tctx.tx_iv,tx_iv,12);
     memmove(tctx.rx_iv,rx_iv,12);
	 memmove(tctx.c_hs_traffic,c_hs_traffic,32); 
     memmove(tctx.s_hs_traffic,s_hs_traffic,32); 
	 
	 len= CheckServerHello(&tctx);
	 if (len != 1) return -1;
     
	 myPrintf("HS",tctx.hs,32);
     myPrintf("MasterSecret",tctx.ms,32);

	////////////////////////////////
    mysha256_update(&sha0,rx+5,err);
	////////////////////////////////

    mysha256_dup(&sha1,&sha0);
    mysha256_final(&sha1,result);
    myPrintf("hash1",result,32);
 
    err= Ascii2bin("17 03 03 00 17 51 f6 53 de 60 85 7e be 11 ba 9d 9d a7 8f 86 d4 7f 35 92 63 a3 38 e0",rx);
    //err = ch_decrypt(&ctx0,rx+5,0x17,rx+5,rx,5);
    err= CheckEncryptedOPtions(&tctx); //&ctx0;
	if (err <0) return -1;
    mysha256_update(&sha0,rx+5,err-1);
   
	err=   Ascii2bin("17 03 03 00 35\
    57 24 c8 1b fb 4e b6 a5 db 77 c0 44 f1 46 fb 5e\
    e7 ba f0 9f 02 08 09 3d de e0 5c 6b d9 b9 99 1b\
    e1 a8 56 b7 37 f6 97 cb 2e 81 dd d4 d7 41 58 94\
    41 5d b1 4f a9",rx); 
	err=CheckServerFinished(&tctx);
	if (err <0) return -1;
    mysha256_update(&sha0,rx+5,err-1);
   
   err=MakeClientFinished(&tctx);

    ch_free(&tctx.ctx0);
    ch_free(&tctx.ctx1);
    err = ch_init(&tctx.ctx0,tctx.tx_key,tctx.tx_iv,tctx.ciphersuite);
    err = ch_init(&tctx.ctx1,tctx.rx_key,tctx.rx_iv,tctx.ciphersuite);

	//17 03 03 00 18
	//GET / \r\n0x17   = 8 bytes
    rx[0]=0x17;
    rx[1]=0x03;
	rx[2]=0x03;
    rx[3]=0x00;
	rx[4]=0x18;
	sprintf(rx+5,"%s","GET /\r\n");
	rx[12]=0x17;
    err = ch_encrypt(&tctx.ctx1,rx+5,8,rx+5,rx,5);
	
	//1703030018 17F357729B36DC22AA6371AE74ED481F4EC6F2AE09B2E33E
	myPrintf("enc",rx,29);
    err = Ascii2bin("17 03 03 00 27\
		             6a 9c a8 51 24 98 7f ba-14 5f 02 8a 08 ff 4d 87\
                     03 85 88 b7 9f ec fe 68-2a 11 a6 29 41 e4 c6 57\
                     6d 29 a6 64 94 33 48",rx);
    err = ch_decrypt(&tctx.ctx0,rx+5,0x27,rx+5,rx,5);
	if (err <= 0) return -1;
	//49206865617220796F75206661207368697A7A6C652117
	//I hear you fa shizzle!
    myPrintf("dec",rx+5,err);

	ch_free(&tctx.ctx0);
    ch_free(&tctx.ctx1);

	err= Ascii2bin("49206865617220796F75206661207368697A7A6C652117",result);
	if (memcmp(result,rx+5,err) ==0)
	printf("Test OK\n");
	else printf("Test ERROR\n");

	return 0;
}

int test_server(char *aid,char *pin,int fpsk)
{ int err,len;
  char result[32];
 
   IM_init(aid);
   myrnd_init();
   mysha256_init(&sha0);
   mysha256_final(&sha0,esha256);

   mysha256_init(&sha0);

   if (fpsk)
   err=  Ascii2bin(ClientHello,rx);
   else
   err=  Ascii2bin(ClientHello2,rx);

   err= GetRecord();
   if (err <=0) return -1;

   myPrintf("ClientHello",rx,ptrx);
   
   mysha256_init(&sha1);
   mysha256_update(&sha1,rx+5,err);
   mysha256_final(&sha1,result);
   myPrintf("hash0",result,32);
   
   mysha256_init(&sha0);
   mysha256_update(&sha0,rx+5,err);
  
   if (rx[5] == 0x01)
   {if (fpsk)  err= CheckClientHello(1,pin,aid);
    else       err= CheckClientHello(2,pin,aid);
   }
   else  return -1;
   if (err <0) return -1;

	err= MakeServerHello(err,err,pin,aid);
	if (err <= 0) return -1;

	myPrintf("ServerHello",rx,err+5);
    myPrintf("HS",myHandshakeSecret,32);
	myPrintf("MasterSecret",myMasterSecret,32);
	
 
   	////////////////////////////////
    mysha256_update(&sha0,rx+5,err);
	////////////////////////////////

   mysha256_dup(&sha1,&sha0);
   mysha256_final(&sha1,result);
   myPrintf("hash1",result,32);

   err = ch_init(&ctx0,tx_key,tx_iv,AES128GCM);
   err = ch_init(&ctx1,rx_key,rx_iv,AES128GCM);
    
	//err= Ascii2bin("17 03 03 00 17 51 f6 53 de 60 85 7e be 11 ba 9d 9d a7 8f 86 d4 7f 35 92 63 a3 38 e0",rx);
    //err = ch_decrypt(&ctx0,rx+5,0x17,rx+5,rx,5);
    err= MakeEncryptedExtensions(&ctx0);
    if (err <0) return -1;
    //mysha256_update(&sha0,rx+5,err-1);
     myPrintf("EncryptedExtension",rx,err+5);

    
	if (!fpsk)
	{ err= MakeEncryptedCertificate(&ctx0)   ;
	  if (err <0) return -1;
      myPrintf("EncryptedCert",rx,err+5);
      err= MakeEncryptedVerify(&ctx0,0xFF,pin,aid);
      if (err <0) return -1;
     
	  myPrintf("EncryptedVerify",rx,err+5);
	}

	err= MakeEncryptedFinished(&ctx0); //ctx0
	mysha256_dup(&sha1,&sha0);
    mysha256_final(&sha1,result);
    //AAF5BE55D5AC6C190697FCEBDF3D1A57200C38D9459D00FDB13C19F8458E9784
	
  
	myPrintf("EncryptedFinished",rx,err+5);
	myPrintf("hash",result,32); 


   err = Ascii2bin(ChangeCipherSpec,rx);
   err= GetRecord();
	if (err <=0) 
	{	ch_free(&ctx0); ch_free(&ctx1);
		return -1;
	}

   err= CheckClientChangeCipherSpec();
   if (err != 0) 
   {   ch_free(&ctx0); ch_free(&ctx1);
	   return -1;
   }
  
   
   if (fpsk)
   err = Ascii2bin(ClientFinished,rx);
   else
   err = Ascii2bin(ClientFinished2,rx);


   err= GetRecord();
	if (err <=0)
	{   ch_free(&ctx0); ch_free(&ctx1);
		return -1;
	}


   err= CheckClientFinished(&ctx1); // ctx1

   if (err !=0)
   {   ch_free(&ctx0); ch_free(&ctx1);
	   return -1;
   }
 
    ch_free(&ctx0);
    ch_free(&ctx1);
    err = ch_init(&ctx0,tx_key,tx_iv,AES128GCM);
    err = ch_init(&ctx1,rx_key,rx_iv,AES128GCM);

	if (fpsk)
    err = Ascii2bin(areq,rx);
	else 
    err = Ascii2bin(areq2,rx);

    err= GetRecord();
	if (err <= 0)
		return -1;

   // "GET \r\n"
	err = ch_decrypt(&ctx1,rx+5,ptrx-5,rx+ptrx,rx,5);
	
	if (err <= 0) 
		return -1;


	if (fpsk)
	len= Ascii2bin(aresp,rx+100);
	else
    len= Ascii2bin(aresp2,rx+100);


    //49206865617220796F75206661207368697A7A6C652117
	//I hear you fa shizzle!
	err= Ascii2bin("170303002749206865617220796F75206661207368697A7A6C652117",rx);
    err = ch_encrypt(&ctx0,rx+5,err-5,rx+5,rx,5);

	if (memcmp(rx,rx+100,len) != 0)
		return -1;
	
    ch_free(&ctx0);
    ch_free(&ctx1);

	return 0;
}


//-c -H timeout6 -H rauth046099836D971593AAA2C1C32B6DB9EF9521041795E21CF1E7511DF3BD358F97DF358B33A875E359CBE236163D6DBAEDFEC6C9393522C7EBC25A7CC85E1F0A7D67      -H auth046099836D971593AAA2C1C32B6DB9EF9521041795E21CF1E7511DF3BD358F97DF358B33A875E359CBE236163D6DBAEDFEC6C9393522C7EBC25A7CC85E1F0A7D67   -H baud115200 -H rim  -H com2 -H  @002#h8012345678 -H reset   -h tlsse.dyndns.org -p 7786 -S key7.com -l TLS_AES_128_CCM_SHA256 -H identityClient_identity -H psk0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20  -H pin0000 -H aid010203040500 -H rpsk0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20  -H rpin0000 -H raid010203040800 -H rp444 -H rh192.168.1.49 -H rlTLS_AES_128_CCM_SHA256    
extern int tcrypto;
extern int ttlsim;
extern int test_ecc()  ;
extern void test_hmac();
extern int test_aesgcm();
extern int test_aesccm();
extern int IM_it(char *aid);
extern int IM_test(char *pin, char *aid);

T_CTX ttctx[64] ;
T_CTX ttctx2[64];
char trx[64][2048] ;
char trx2[64][2048];
extern int largc[64];
extern char *largv[64][512];
extern int ReadOpt();
extern int testapi();

char * iniseid(int n)
{ int err;
  static char name[2048];
	default_ctx(&ttctx[n],&ttctx2[n],trx[n],2047,trx2[n],2047);
    err= parse(largc[n],largv[n],&ttctx[n]);
	sprintf(name,"%s:%d/%s",ttctx[n].name,ttctx[n].port,ttctx[n].sn);
	return name;
}


extern int testclient(char *uri);
int tls13(int argc, char** argv)
{ int err,port=444;
  T_CTX tctx;
  T_CTX tctx2;

  char aid[33]="010203040500";
  char pin[9]="0000";

  mysha256_init(&sha0);
  mysha256_final(&sha0,esha256);

  //testclient("tlsse.dyndns.org:7785");
  //testclient("127.0.0.1:443");
  //stopTCPIP();
  
  //testapi();
  
  
  if ( (strcmp(argv[1],"client") == 0) || (strcmp(argv[1],"-c") == 0) || (strcmp(argv[1],"c") == 0) )
  {  default_ctx(&tctx,&tctx2,rx,(int)sizeof(rx)-1,rx2,(int)sizeof(rx2)-1);
     init_sim=0 ;
	 reset_sim=0;

     if ( (strcmp(argv[1],"-c") == 0) || (strcmp(argv[1],"c") == 0))
	 {   tctx.netctx= &tctx2;
		 err= parse(argc,argv,&tctx);
		 if (err <0) return 0;
	 }
	 else
	 {  fconsole=1      ;
        fim=1 ; myhw=0  ;
        tctx.mode = CBINDERIM | CDERIVEIM  ;
	 }
	 
  if (tcrypto)
  { test_ecc();
    test_hmac();
    #ifndef WIN32
    testccm();
    #endif
    test_aesccm();
    test_aesgcm();
  }

  if (ttlsim)
  {  IM_init(tctx.aid);
     IM_test(tctx.pin,tctx.aid);
  }

     myrnd_init()    ;
     err=startTCPIP();
     tls13_c(&tctx)  ;
     err=stopTCPIP() ;

	 return 0;
     
  }
  
  else if (strcmp(argv[1],"tclient") == 0)
  { IM_init(aid);
    myrnd_init();
	err=  testtls13psk(aid,pin);
	return 0 ;  
  }
  else
  {
   default_ctx(&tctx,&tctx2,rx,(int)sizeof(rx)-1,rx2,(int)sizeof(rx2)-1);
   strcpy(tctx.aid,aid);strcpy(tctx.pin,pin);fim=0;myhw=0;
   tctx.port=444;tctx.timeout=60;
   err= parse(argc,argv,&tctx);
   if      (strcmp(argv[1],"psk") == 0) test_server(aid,pin,1);
   else if (strcmp(argv[1],"pki") == 0) test_server(aid,pin,0);
   else if (strcmp(argv[1],"im") == 0)
   {_tls13(tctx.pin,tctx.aid,tctx.timeout); return 0;}
   else if (strcmp(argv[1],"se") == 0)
   {tls13_se(0,tctx.port,tctx.pin,tctx.aid,tctx.timeout);return 0;}
   else if (strcmp(argv[1],"see") == 0)
   { tls13_se(1,tctx.port,tctx.pin,tctx.aid,tctx.timeout);return 0;}
    
  }
  
 

  return 0;
}


