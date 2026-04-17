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
#include "tls13.h"


void binder(char *data32, char *key32, IM_CTX *ctx)
{ 
	ComputePRK(ctx->fek,32,data32,32,key32);
}

//derive(DHE)= HMAC(DSK, DHE) 
void derive(char *data32, char *key32, IM_CTX *ctx)
{ 
	ComputePRK(ctx->dsk,32,data32,32,key32);
    //memmove(HS_Secret,key32,32)       ;
}

void init_imv(char *psk, int ctest, IM_CTX *ctx)
{ MYSHA256_CTX sha0;
  char Salt[32] ;
  int i=0,err;
  char data32[32];
  char key32[32] ;

char MYPSK[32];
char H0[32];
char ESK[32];
char DSK[32];
char BSK[32];
char FEK[32];

  for(i=0;i<32;i++) data32[i]= 0;
  for(i=0;i<32;i++) key32[i]= 0;
  for(i=0;i<32;i++) Salt[i]=0;
   
 mysha256_init(&sha0);
 mysha256_final(&sha0,H0);

 memmove (MYPSK,psk,32);

 //ESK= HMAC(salt=0,PSK)
 ComputePRK(Salt,32,MYPSK,32,ESK);

 //DSK=HMAC(ESK,HL16||0d746c7331332064657269766564||HL8||H0||01)
 DeriveSecret(ESK,32,"tls13 derived",H0,32,DSK);

 //BSK=HMAC(ESK,HL16||10746c733133206578742062696e646572||HL8||H0||01)
 DeriveSecret(ESK,32,"tls13 ext binder",H0,32,BSK);

 //FEK=HMAC(BSK,HL16||0E746C7331332066696E69736865640001)
 DeriveSecret(BSK,32,"tls13 finished",NULL,0,FEK);

 memmove(ctx->fek,FEK,32);
 memmove(ctx->dsk,DSK,32);

 if (ctest)
 {
 myPrintf("H0",H0,32);
 myPrintf("ESK",ESK,32);
 myPrintf("DSK",DSK,32);
 myPrintf("BSK",BSK,32);
 myPrintf("FEK",FEK,32);

 
 err= Ascii2bin("C0C27BBFDBAF30C5888732734BCE1B47E3F14FAA4BE578A25BD81BBDE2D2B1FA",data32);
// MAC(feBSK,Os)
// 0085 000C 20 C0C27BBFDBAF30C5888732734BCE1B47E3F14FAA4BE578A25BD81BBDE2D2B1FA
// 811ABCE77E614232741AE2F59E0497E8801D31D7388577FAED73EF63BD1B6791
 binder(data32,key32,ctx);
 myPrintf("BINDER",key32,32);


 err= Ascii2bin("97C3CF6C99EA9840D2E35F0AE684C97A2B4B68D5F8196C0C1D0C85E2F8BF43AB",data32);
 derive(data32,key32,ctx);
 myPrintf("DERIVE",key32,32);
//0085 000E 20 97C3CF6C99EA9840D2E35F0AE684C97A2B4B68D5F8196C0C1D0C85E2F8BF43AB
//98F057EE0CC6C17E27983B9C2019111AE1E440517863C803030877139C047BD
 }
memset(MYPSK,0,32);
memset(ESK,0,32);
memset(BSK,0,32);
}