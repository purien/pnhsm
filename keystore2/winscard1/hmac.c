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
#include "hmac.h"
#include "util.h"


void test_hmac()
{ char key[140];
  MYSHA256_CTX sha;
  char data[256];
  char hbuf[160];
  char result[32];
  int lenk,lend,err,i;

  printf("Tests HMAC\n");

  lenk=  Ascii2bin("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",key);
  lend=  Ascii2bin("4869205468657265",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

  lenk=  Ascii2bin("4a656665",key);
  lend=  Ascii2bin("7768617420646f2079612077616e7420666f72206e6f7468696e673f",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

  lenk=  Ascii2bin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",key);
  lend=  Ascii2bin("dddddddddddddddddddddddddddddddd\
				    dddddddddddddddddddddddddddddddd\
                    dddddddddddddddddddddddddddddddd\
                    dddd",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

  lenk=  Ascii2bin("0102030405060708090a0b0c0d0e0f10111213141516171819",key);
  
  
  lend=  Ascii2bin("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                    cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                    cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\
                    cdcd",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

  lenk=  Ascii2bin("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c ",key);
  lend=  Ascii2bin("546573742057697468205472756e636174696f6e",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");


  lenk=  Ascii2bin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa ",key);
  
  lend=  Ascii2bin("54657374205573696e67204c61726765\
                    72205468616e20426c6f636b2d53697a\
                    65204b6579202d2048617368204b6579\
					204669727374",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

  lenk=  Ascii2bin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
                  aaaaaa",key);

  lend=  Ascii2bin("54686973206973206120746573742075\
                   73696e672061206c6172676572207468\
				   616e20626c6f636b2d73697a65206b65\
                   7920616e642061206c61726765722074\
                   68616e20626c6f636b2d73697a652064\
                   6174612e20546865206b6579206e6565\
                   647320746f2062652068617368656420\
                   6265666f7265206265696e6720757365\
                   642062792074686520484d414320616c\
                   676f726974686d2e",data);
  
  err= hmac (key,lenk, data,lend,&sha,result,3,hbuf); 
  for(i=0;i<32;i++) printf("%02X", result[i] & 0xFF); printf("\n");

printf("Should be\n");
printf("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7\n");
printf("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843\n");
printf("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE\n");
printf("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B\n");
printf("A3B6167473100EE06E0C796C2955552BFA6F7C0A6A8AEF8B93F860AAB0CD20C5\n");
printf("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54\n");
printf("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2\n");

}

#ifdef COPENSSL

int mysha256_dup(MYSHA256_CTX * sha_dest , MYSHA256_CTX * sha_src)
{ 
	memmove((void*)sha_dest,(void *)sha_src,sizeof(MYSHA256_CTX));
	return 0;
}

int mysha256_init(MYSHA256_CTX * sha)
{ SHA256_Init(sha);
  return 0;
}

int mysha256_update(MYSHA256_CTX * sha, char *data, int len)
{ SHA256_Update(sha,data,len);
  return 0;
}

int mysha256_final(MYSHA256_CTX * sha, char *result)
{ 
  SHA256_Final(result,sha);
  return 0;
}


#else

int mysha256_dup(MYSHA256_CTX * sha_dest , MYSHA256_CTX * sha_src)
{ 
	memmove((void*)sha_dest,(void *)sha_src,sizeof(MYSHA256_CTX));
	return 0;
}

int mysha256_init(MYSHA256_CTX * sha)
{ int ret ;
  ret = wc_InitSha256_ex(sha, NULL, INVALID_DEVID);
  return ret;
}

int mysha256_update(MYSHA256_CTX * sha, char *data, int len)
{ int ret ;
  ret = wc_Sha256Update(sha,data,len);
  return ret;
}

int mysha256_final(MYSHA256_CTX * sha, char *result)
{ int ret ;
  ret= wc_Sha256Final(sha,result);
  wc_Sha256Free(sha);
  return ret;
}

#endif

int hmacct=0;
 
int  hmac
 ( char *  k32,  int lk,  /* Secret key */
   char *  d, int  ld,  /* data       */
   MYSHA256_CTX * md,
   char *result, 
   int init,
   char * buf160)
   {  	     
   int i,DIGESTSIZE=32,BLOCKSIZE=64; 
   //DIGESTSIZE= (short)32; BLOCKSIZE = (short)64; }

   if (ld%64 <= 55) hmacct+= (4+ld/64);
   else             hmacct+= (5+ld/64);

   if ((init == 0) || (init==3) )
   {
   if (lk > (short)BLOCKSIZE ) 
   {  mysha256_init(md);
      mysha256_update(md,k32,lk);
      mysha256_final(md,k32);
      lk = DIGESTSIZE ;
   }
	//=====================================================
	// BLOCKSIZE+DIGESTSIZE+BLOCKSIZE = 64 + 32 + 64 = 160 
    //=====================================================
     for (i= 0 ; i< lk ; i++) 
     buf160[i+BLOCKSIZE+DIGESTSIZE] = (char)(k32[i]^(char)0x36) ;
  
	 memset((void*)(buf160+BLOCKSIZE+DIGESTSIZE+lk),0x36,BLOCKSIZE-lk);
	   	   
     for (i=0; i<lk ;i++) 
     buf160[i] = (char) (k32[i] ^(char)0x5C);

     memset((void*)(buf160+lk),0x5C,BLOCKSIZE-lk);
		  
	}
			
           if ( (init == 0) ||(init==3) )
		   { // md.reset();
			 mysha256_init(md);
             mysha256_update(md,(char *)(buf160+BLOCKSIZE+DIGESTSIZE),BLOCKSIZE);
             mysha256_update(md,d,ld);
			 if (init == 3)
			 { mysha256_final(md,(char*)(buf160+BLOCKSIZE));
			   mysha256_init(md);
		       mysha256_update(md,buf160,DIGESTSIZE+BLOCKSIZE);        
		       mysha256_final(md,result);
			 }
           }

		   else if (init == 1)
		   { 
			   mysha256_update(md,d,ld);
           }

		   
		   else if (init == 2)
		   { mysha256_update(md,d,ld);
			 mysha256_final(md,(char*)(buf160+BLOCKSIZE));
			 mysha256_init(md);
		     mysha256_update(md,buf160,DIGESTSIZE+BLOCKSIZE);        
		     mysha256_final(md,result);
		   }

		   return 0;
   }


