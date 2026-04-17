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
#include "hmac.h"
#include "util.h"

char * getmeta(char *name, char *meta, int max)
{ FILE *f=NULL;
  int err=0;

meta[0]=0;

f= fopen(name,"rb");
if (f == NULL) return NULL;

#ifdef WIN32
err=fscanf_s(f,"%s",meta,max-1);
#else
err=fscanf(f,"%s",meta);
#endif

fclose(f);
if (err==0) return NULL;
return meta;

}


char * hname(char *name, char *meta, char *aresult)
{ char result[32];
  int i;
  
  MYSHA256_CTX mysha   ;
  mysha256_init(&mysha);
  mysha256_update(&mysha, name,   (int)strlen(name));
  mysha256_update(&mysha, meta, 1+(int)strlen(meta));
  mysha256_final(&mysha,result);
  
  for(i=0;i<8;i++)  result[4*i]= 0xFF & (0x80 | result[4*i]);
  for(i=0;i<32;i++) sprintf(&aresult[2*i],"%2.2X", 0xFF & result[i]);

  return aresult;

}


char * hname2(char *name, char *meta, char *aresult)
{ char result[32];
  int i;
  
  MYSHA256_CTX mysha   ;
  mysha256_init(&mysha);
  mysha256_update(&mysha, name,   (int)strlen(name));
  mysha256_update(&mysha, meta, 1+(int)strlen(meta));
  mysha256_final(&mysha,result);
  
  // for(i=0;i<8;i++)  result[4*i]= 0xFF & (0x80 | result[4*i]);
  for(i=0;i<32;i++) sprintf(&aresult[2*i],"%2.2X", 0xFF & result[i]);

  return aresult;

}

int fcrypt(char *akey, char *name, char *meta)
{ char tag[16] ;
  char key[16] ;
  char *auth =NULL  ;
  int authsz   ;
  int err,i;
  char * in=NULL,*out=NULL;
  AES_CIPHER mycipher;
  char nonce[12];
  FILE *f=NULL,*fd=NULL ;
  long size=0;
  
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
   
    f = fopen(name, "rb");

    if (f == NULL) return -1;
    

    fseek(f, 0, SEEK_END);
    size = ftell(f)      ;
    fseek(f, 0, SEEK_SET);   
    
	in = malloc(size);
	out= malloc(size+TAGSIZE)  ;
	memset(out,0,size+TAGSIZE) ;

    fread(in,1,size,f);
	fclose(f);

    authsz = (int)strlen(name)+1+(int)strlen(meta);
	auth= malloc(authsz);
    strcpy(auth,name);
	strcat(auth,meta);
	 
    for (i = 0; i < 12; i++) nonce[i]  = akey[i]   ;
    for (i = 0; i < 16; i++) key[i]    = akey[i+12];

    err= aesgcm_init(&mycipher,key) ;
    err= aesgcm_encrypt(&mycipher,out,in,size,nonce,12,tag,TAGSIZE,auth,authsz);
    aesgcm_free(&mycipher);

	free(in);
	free(auth);

	printf("file %s ",name);

	strcat(name,".bin");
	fd= fopen(name,"wb+");
	if (fd == NULL) 
	{free(out);return -1;}

	fwrite(meta,1,(int)strlen(meta)+1,fd);
    fwrite(out,1,size,fd);
	fwrite(tag,1,TAGSIZE,fd);
    fclose(fd);

	free(out);
	 
    printf("has been encrypted in %s\n",name);
	printf("metadata: %s\n",meta);

return 0;
}


int fdecrypt(char *akey, char *name)
{ char tag[16] ;
  char key[16] ;
  char *auth =NULL  ;
  int authsz   ;
  int err,i;
  char * in=NULL,*out=NULL;
  AES_CIPHER mycipher;
  char nonce[12];
  FILE *f=NULL,*fd=NULL ;
  long size=0;
  char meta[1024];
  
  
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
    
  if ((int)strlen(name)<5) 
	  return -1;


    f = fopen(name, "rb");

    if (f == NULL) return -1;
 
	fseek(f, 0, SEEK_END);
    size = ftell(f)      ;
    fseek(f, 0, SEEK_SET);  

#ifdef WIN32
    err=fscanf_s(f,"%s",meta,(int)sizeof(meta)-1);
    if (err==0) 
	{ fclose(f); return -1;}
#else
    err=fscanf(f,"%s",meta);
    if (err !=1 ) 
	{ fclose(f); return -1;}
#endif

    //if (err==0) 
	//{ fclose(f); return -1;}
    
	fseek(f, 0, SEEK_SET);  

    size-= (1+(int)strlen(meta));
      
	if (size <= TAGSIZE)
	{fclose(f);return -1;}

    fread(meta,1,1+(int)strlen(meta),f);
    
	in = malloc(size);
	out= malloc(size-TAGSIZE) ;
	memset(out,0,size-TAGSIZE);;

    fread(in,1,size,f);
	fclose(f);

	for(i=0;i<TAGSIZE;i++) tag[i]= in[size-TAGSIZE+i];

    authsz = (int)strlen(name)+1+(int)strlen(meta);
    auth= malloc(authsz);
	strcpy(auth,name);
	auth[(int)strlen(name)-4]=0;
	strcat(auth,meta);
	authsz-=4;
 
    for (i = 0; i < 12; i++) nonce[i]  = akey[i]   ;
    for (i = 0; i < 16; i++) key[i]    = akey[i+12];

    err= aesgcm_init(&mycipher,key) ;
    //err= aesgcm_decrypt(&mycipher,out,in,size-TAGSIZE,nonce,12,tag,TAGSIZE,auth,authsz);
    err= aesgcm_decrypt(&mycipher,in,out,size-TAGSIZE,nonce,12,tag,TAGSIZE,auth,authsz);
    aesgcm_free(&mycipher);

	free(in);free(auth);

	//if (err != 0)
    if (err < 0)
	{   printf("Decryption error for file %s !!!\n",name);
		free(out);
		return -1;
	}

    printf("file %s ",name);

	name[(int)strlen(name)-4]=0;
	fd= fopen(name,"wb+");
	if (fd == NULL) 
	{free(out);return -1;}

    fwrite(out,1,size-TAGSIZE,fd);
	fclose(fd);
	free(out);

    printf("has been decrypted in %s\n",name);
	printf("metadata: %s\n",meta);


return 0;
}

