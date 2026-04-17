/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

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

extern int Ascii2bin(char *Data_In,char *data_out);

int TLS_open(T_CTX *ctx);
int TLS_close(T_CTX *ctx);
int TLS_write(T_CTX * ctx, int len);
int TLS_read(T_CTX * ctx);
int TLS_cmd(T_CTX * ctx, int len);

//////////Added for winscard/////////////////////////////
extern T_CTX ttctx[64] ;

int tlspsk_open(int n)
{ return TLS_open(&ttctx[n]);
}

int tlspsk_close(int n)
{ return TLS_close(&ttctx[n]);
}

int tlspsk_cmd(int n,char *buf, int max)
{ int err; 
   strcpy(ttctx[n].tx, buf);
   err= TLS_cmd(&ttctx[n], (int)strlen(ttctx[n].tx));
   if (err >= 0) { strcpy(buf,ttctx[n].rx); err=0;}
   return err;
}
////////////////////////////////////////////////////////////////////////////


int TLSIM_txAPDU(T_CTX * ctx, char *apdu,int len, char *response,int *size)
{ int i,err;
  
  strcpy(ctx->tx,"A ");
  for(i=0;i<len;i++)
  sprintf(2+ctx->tx+(2*i),"%2.2X",0xFF & apdu[i]);
  strcat(ctx->tx,"\r\n");
  
  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) {TLS_close(ctx); return -1;}
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  *size= Ascii2bin(ctx->rx,response);
  return 0;
}
int TLSIM_APDU(T_CTX * ctx, char * apdu)
{ char buf[900],out[260];
  char Response[260]    ;
  int len,Rsize=260  ;
  int err;

  strcpy(buf,apdu);
  len=  Ascii2bin(buf,out);

  err=TLSIM_txAPDU(ctx,buf,len,Response,&Rsize);
  if (err != 0){return -1;}
   
  if( (Rsize >=2) && (Response[Rsize-2] == (char)0x90) && (Response[Rsize-1]== (char)0x00) )
  return 0;
  
  return -1;
}





int TLSIM_binder(T_CTX *ctx,char *data,int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;
  int ftlsse=0,i=0;

 if ((ctx->mode & CIMTLSSE) == CIMTLSSE)
 ftlsse=1;
 
 if (ftlsse)
 { strcpy(ctx->tx,"?D0");
   for (i=0;i<len;i++) sprintf(ctx->tx+3+2*i,"%2.2X",0xFF & data[i]);
   strcat(ctx->tx,"\r\n");

   if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
   err= TLS_cmd(ctx, (int)strlen(ctx->tx));
   if (!ctx->fquiet) if (err >= 0) printf("RxNet: %s",ctx->rx);
   if ( strcmp(ctx->rx,"ERROR\r\n")==0) return -1;
   err=Ascii2bin(ctx->rx,key);
   if (err != 32) return -1;
   return 0;

 }

  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x00;
  apdu[3]= 0x0C;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= TLSIM_txAPDU(ctx,apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


return 0;

}


int TLSIM_derive(T_CTX *ctx,char *dhe,int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;
  int ftlsse=0,i;

 if ((ctx->mode & CIMTLSSE) == CIMTLSSE)
 ftlsse=1;
 
 if (ftlsse)
 {  if ((ctx->mode & CIMASK) == CIMASK)
	 strcpy(ctx->tx,"?D2");
    else
     strcpy(ctx->tx,"?D1");

   for (i=0;i<len;i++) sprintf(ctx->tx+3+2*i,"%2.2X",0xFF & dhe[i]);
   strcat(ctx->tx,"\r\n");

   if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
   err= TLS_cmd(ctx, (int)strlen(ctx->tx));
   if (!ctx->fquiet) if (err >= 0) printf("RxNet: %s",ctx->rx);
   if ( strcmp(ctx->rx,"ERROR\r\n")==0) return -1;
   err=Ascii2bin(ctx->rx,key);
   if (err != 32) return -1;
   return 0;

 }


  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x00;
  apdu[3]= 0x0E;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],dhe,len);

  err= TLSIM_txAPDU(ctx,apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


return 0;

}


int TLSIM_close(T_CTX *ctx)
{ int err;

  if ((ctx->mode & CIMTLSSE) == CIMTLSSE)
  return TLS_close(ctx);
  
  strcpy(ctx->tx,"off\r\n");
  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (!ctx->fquiet) if (err >= 0) printf("RxNet: %s",ctx->rx);
  
  return TLS_close(ctx);


}

int TLSIM_open(T_CTX * ctx)
{ int err,ftlsse=0;
  
  if ((ctx->mode & CIMTLSSE) == CIMTLSSE)
  {  ctx->ciphersuite= TLS_AES_128_CCM_SHA256;
     ftlsse=1;
  }
  else
      ctx->ciphersuite= TLS_AES_128_GCM_SHA256;

  err=TLS_open(ctx);
  if (err !=0 ) return err;



  if (ftlsse) 
  {   
	  if (ctx->sign)
      err=sign(ctx);
	  
   if (ctx->auth)
   {   err=auth(ctx);
       if (err != 1)
	   { printf("Client is not authenticated...\n");
		 TLS_close(ctx);
	     return -1;
	   }
   }

 

   return 0;
  }
  
  
  strcpy(ctx->tx,"on\r\n");
  if (!ctx->fquiet)  printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) {TLS_close(ctx); return -1;}
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"OK\r\n") != 0) return -1;
 
  sprintf(ctx->tx,"A 00A40400%02d%s\r\n",(int)strlen(ctx->aid)/2,ctx->aid);
  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) {TLS_close(ctx); return -1;}
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"9000\r\n") != 0) return -1;
 
  sprintf(ctx->tx,"A 00200000%02X%02X%02X%02X%02X\r\n", 0xFF & strlen(ctx->pin),0xFF&ctx->pin[0],0xFF&ctx->pin[1],0xFF&ctx->pin[2],0xFF&ctx->pin[3]);
  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) {TLS_close(ctx); return -1;}
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"9000\r\n") != 0) return -1;
  
  return 0;
}

int TLS_open(T_CTX *ctx)
{  int sclient,err,fccs=0 ;
   char *rx=ctx->buf;
   char ccs[] = {0x14,3,3,0,1,1};

   ctx->state=0;
   ctx->rx = ctx->buf + 5;
   ctx->tx = ctx->buf + 5;
   
   //if (!ctx->fquiet) printf("ConnectTo: %s:%d\n", ctx->name, ctx->port);
   sclient= ConnectServer(ctx->name,ctx->port);
   if (sclient  <= 0) return -1;
   //if (!ctx->fquiet) printf("Connected\n");
   ctx->state=1;
   ctx->s = sclient;
   err= MakeClientHello(ctx);
   if (err < 0) return -1;
   err= netsend(ctx->buf,err,sclient);
   if (err <0 ) return -1;
   //if (!ctx->fquiet) printf("ClientHello\n");
   ctx->state=2;
   err= netrecv(ctx->buf,sclient,ctx->bufmax,ctx->timeout);
   if (err <0 ) return -1;
   //if (!ctx->fquiet) printf("ServerHello\n");
   err= CheckServerHello(ctx);
   if (err <0 ) return -1;
   ctx->state=3;
   err= netrecv(ctx->buf,sclient,ctx->bufmax,ctx->timeout);
   if (err <0 ) return -1;

   if (ctx->buf[0]== (char)0x14)
   { err= memcmp(ctx->buf,ccs,(int)sizeof(ccs));
     if (err !=0) return -1;
	 fccs=1;
     //if (!ctx->fquiet) printf("CCS\n");
     err= netrecv(ctx->buf,sclient,ctx->bufmax,ctx->timeout);
   }
   if (err <0 ) return -1;
   //if (!ctx->fquiet) printf("EncryptedOptions\n");
   err= CheckEncryptedOPtions(ctx);
   if (err <0 ) return -1;
   ctx->state=4;
   err= netrecv(ctx->buf,sclient,ctx->bufmax, ctx->timeout);
   if (err <0 ) return -1;
   //if (!ctx->fquiet) printf("ServerFinished\n");
   err= CheckServerFinished(ctx) ;
   if (err <0 ) return -1;
  
   ctx->state=5;
   
   if (fccs)
   {   err=(int)sizeof(ccs);
	   memmove(ctx->buf,ccs,err);
       //if (!ctx->fquiet) printf("CCS\n");
	   err= netsend(ctx->buf,err,sclient);
      if (err <0 ) return -1;
   }

   err= MakeClientFinished(ctx);
   if (err <0 ) return -1 ;
   //if (!ctx->fquiet) printf("ClientFinished\n");
   err= netsend(ctx->buf,err,sclient);
   if (err <0 ) return -1;
   ctx->state=6;

   ch_free(&ctx->ctx0);
   ch_free(&ctx->ctx1);
   err = ch_init(&ctx->ctx0,ctx->tx_key,ctx->tx_iv,ctx->ciphersuite);
   err = ch_init(&ctx->ctx1,ctx->rx_key,ctx->rx_iv,ctx->ciphersuite);

   return 0;

}

int TLS_close(T_CTX *ctx)
{ 
 int s= ctx->s;

 if (ctx->state >=3)
	{ ch_free(&ctx->ctx0);
      ch_free(&ctx->ctx1);
	}
 if (ctx->state > 0)
 DeconnectServer(s);
 
 ctx->state=0;
 return 0;
}

int TLS_sendbuf(T_CTX * ctx, char *buf, int len)
{ memmove(ctx->tx,buf,len) ;
  return TLS_write(ctx,len);
}

int TLS_recvbuf(T_CTX * ctx, int fbin)
{ int err=-1,i=0;
  int s= ctx->s     ;
  char *rx= ctx->buf;
  char reply2[MAXTLSBUFSIZE] ;
  int  ptcol=0;

  if (ctx->state == 0) return -1;

  // ignore message not for record layer (handshake == 22)
  while (ptcol != 23)
  {
  err=netrecv(ctx->buf,s,ctx->bufmax,ctx->timeout);
  if (err <0 ) return -1 ;
  err = ch_decrypt(&ctx->ctx0,rx+5,err-5,rx+5,rx,5);
  if (err <=0 ) return -1;
  ptcol= (int)0xFF & rx[5+err-1];
  if (ptcol == 21) return -1;
  if (ptcol == 0)  return -1;
  }

  /*
     enum {
          invalid(0),
          change_cipher_spec(20),
          alert(21),
          handshake(22),
          application_data(23),
          heartbeat(24), 
          (255)
         } ContentType;
  */

  
  if (fbin==0)
  rx[5+err-1]=0 ;
  else
  { if (err <2) return -1;
    else if (err==2) return err;
	for(i=0;i<(err-2);i++)
	sprintf(&reply2[2*i],"%2.2X",0xFF & ctx->rx[i]);
	sprintf(ctx->rx,"%s\r\n",reply2);
    return (int)strlen(ctx->rx);
  }
  
  return err-1;
}


int TLS_write(T_CTX * ctx, int len)
{ int err=-1    ;
  int s= ctx->s ;
  char *rx= ctx->buf;

  if (ctx->state == 0) return -1;

  rx[0]=0x17;
  rx[1]=3;
  rx[2]=3;
  rx[3]= 0xFF & ((len+1+TAGSIZE)>>8);
  rx[4]= 0xFF &  (len+1+TAGSIZE);
  rx[5+len]=0x17;
  err = ch_encrypt(&ctx->ctx1,rx+5,len+1,rx+5,rx,5);
  if (err <0 ) return -1;
  err = netsend(ctx->buf,len+1+TAGSIZE+5,s);
  if (err <0 ) return -1;
  return 0;
}



int TLS_read(T_CTX * ctx)
{ int err=-1;
  int s= ctx->s     ;
  char *rx= ctx->buf;

  if (ctx->state == 0) return -1;

  err=netrecv(ctx->buf,s,ctx->bufmax,ctx->timeout);
  if (err <0 ) return -1 ;
  err = ch_decrypt(&ctx->ctx0,rx+5,err-5,rx+5,rx,5);
  if (err <0 ) return -1;
  rx[5+err-1]=0 ;
  return err-1;
}

int TLS_cmd(T_CTX * ctx, int len)
{ int err;
  
  if (ctx->state == 0) return -1;

  err=TLS_write(ctx,len);
  if (err <0) return -1 ;
  err=TLS_read(ctx);
  return err;
}

int TLS_cmda(T_CTX * ctx, char *cmd)
{ int err; 
   strcpy(ctx->tx,cmd);
   if (!ctx->fquiet) printf("Tx: %s",ctx->tx);
   err= TLS_write(ctx,(int)strlen(ctx->tx));
   if (err <0) return -1 ;
   err= TLS_read(ctx)    ;
   if (err <0) return -1  ;
   if (!ctx->fquiet) printf("Rx:%s",ctx->rx);
   return err;
}

int open_tlsim(T_CTX * ctx)
{ int err;
   if ( ((ctx->mode & CDHIM) == CDHIM) || ((ctx->mode & CBINDERIM) == CBINDERIM) || ((ctx->mode & CDERIVEIM) == CDERIVEIM) )
   return IM_init(ctx->aid);
   
   if ( ( (ctx->mode & CDHNET) == CDHNET) || ((ctx->mode & CBINDERNET) == CBINDERNET)  )
   { err= TLSIM_open(ctx->netctx);
     if (err !=0) {err=TLS_close(ctx->netctx);return -1;}
   }

   return 0;
}
int close_tlsim(T_CTX * ctx)
{    
   if ( ((ctx->mode & CDHIM) == CDHIM) || ((ctx->mode & CBINDERIM) == CBINDERIM) || ((ctx->mode & CDERIVEIM) == CDERIVEIM) )
   IM_end();
   
   if ( ((ctx->mode & CDHNET) == CDHNET) || ((ctx->mode & CBINDERNET) == CBINDERNET)  )
   TLSIM_close(ctx->netctx);
  
   return 0;
}

extern void shell(T_CTX * ctx);

int tls13_c(T_CTX * ctx)
{  int err  ;
   struct timeb timebuffer0;
   long t1=0,t2=0;
   int cfnet=0,cfim=0;
   
   // if (open_tlsim(ctx)!=0) return;
   if ( ((ctx->mode & CDHIM) == CDHIM) || ((ctx->mode & CBINDERIM) == CBINDERIM) || ((ctx->mode & CDERIVEIM) == CDERIVEIM) )
   { err= IM_init(ctx->aid) ;
     if (err != 0) return -1;
	 cfim=1;
   }
   
   if ( ( (ctx->mode & CDHNET) == CDHNET) || ((ctx->mode & CBINDERNET) == CBINDERNET)  )
   { //err= TLSIM_open(ctx->netctx);
     //if (err !=0) {err=TLS_close(ctx->netctx);return -1;}

    if (ctx->netctx == (T_CTX *)NULL) return -1;
    ctx->netctx->backctx=ctx;
	cfnet=1;
	
    if ( (ctx->netctx->mode & CIMTLSSE) == CIMTLSSE) //TLSSE
	{ ctx->netctx->ciphersuite= TLS_AES_128_CCM_SHA256;
	}
    else
	{ ctx->netctx->ciphersuite= TLS_AES_128_GCM_SHA256;
	}

    // err=TLS_open(ctx);
    // if (err !=0 ) return err;
   }

   /////////////////////
   // err= TLS_open(ctx) ;
   //if (ctx->netctx != (T_CTX*) NULL) 
   if (cfnet)
   { ftime(&timebuffer0);	
     t1 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
   	 err= tls13_c(ctx->netctx) ;
	 if (err <0) 
	 { if (!ctx->fquiet) 
	   { printf("TLS1.3 Connexion Failed with %s\n",ctx->netctx->sn);
	     printf("TLS1.3 Disconnected from %s\n",ctx->netctx->backctx->sn);
	   }
	   TLS_close(ctx->netctx->backctx);
	   return -1;
	 }
   }
   else                              
   {
   if (!ctx->fquiet)   
   { 
   printf("ConnectTo: %s@%s:%d\n", ctx->sn, ctx->name, ctx->port);
   if (cfim)
   printf ("Using Local Identity Module HW=%d\n",myhw);
   else if (cfnet)
   { if ((ctx->netctx->mode & CIMTLSSE) == CIMTLSSE) 
     printf("Using Identity Module over TLSSE\n")  ;
     else 
	 printf("Using Identity Module over RACSL\n");
   }
   else printf("Using Sofware Identity Module\n");
   }
   ftime(&timebuffer0);	
   t1 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
   err= TLS_open(ctx)   ;
   if (err <0) 
   { if (!ctx->fquiet) 
     printf("TLS1.3 Connection Failed with with %s\n",ctx->sn);
     return -1;
   }
   ftime(&timebuffer0);	
   t2 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
   if (!ctx->fquiet) 
   printf("TLS1.3 Client %s is connected in %d ms\n",ctx->sn,(int)(t2-t1));
   }
   /////////////////////

 
   if (ctx->ciphersuite == TLS_AES_128_CCM_SHA256)
   {
   if (ctx->sign)
   { err=sign(ctx); 
     if ((err != 1) && !ctx->fquiet)
     printf("Client %s Signature Failed !!!\n",ctx->sn);
   }

   if (ctx->auth)
   {   err=auth(ctx);
       if (err != 1)
	   { if (!ctx->fquiet)
	     { printf("Client %s Authentication Failed !!!\n",ctx->sn);
	       TLS_close(ctx);
           printf("TLS1.3 Disconnected from %s\n",ctx->sn);
	     }
	     return -1;
	   }
   }
  }

  else if (ctx->backctx != (T_CTX*) NULL)
  {
  while(1)
  {
  strcpy(ctx->tx,"on\r\n");
  if (!ctx->fquiet)  printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) break;
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"OK\r\n") != 0) {err=-1;break;}
 
  //sprintf(ctx->tx,"A 00A40400%02d%s\r\n",(int)strlen(ctx->aid)/2,ctx->aid);
  sprintf(ctx->tx,"A 00A40400%02d%s\r\n",(int)strlen(ctx->backctx->aid)/2,ctx->backctx->aid);


  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) break;
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"9000\r\n") != 0)  {err=-1;break;}
 
  //sprintf(ctx->tx,"A 00200000%02X%02X%02X%02X%02X\r\n", 0xFF & strlen(ctx->pin),0xFF&ctx->pin[0],0xFF&ctx->pin[1],0xFF&ctx->pin[2],0xFF&ctx->pin[3]);
  sprintf(ctx->tx,"A 00200000%02X%02X%02X%02X%02X\r\n", 0xFF & strlen(ctx->backctx->pin),0xFF&ctx->backctx->pin[0],0xFF&ctx->backctx->pin[1],0xFF&ctx->backctx->pin[2],0xFF&ctx->backctx->pin[3]);
  if (!ctx->fquiet) printf("TxNet: %s",ctx->tx);
  err= TLS_cmd(ctx, (int)strlen(ctx->tx));
  if (err <0) break;
  if (!ctx->fquiet) printf("RxNet: %s",ctx->rx);
  if (strcmp(ctx->rx,"9000\r\n") != 0)  {err=-1;break;}
  err=0;
  break;
  }

  if (err < 0)
  {  TLS_close(ctx);
     if (!ctx->fquiet) printf("TLS1.3 Disconnected from %s\n",ctx->sn);
	 return -1;
  }
  }
  
   
    //close_tlsim(ctx);
   if (ctx->backctx != (T_CTX*) NULL)
   {
   if (!ctx->backctx->fquiet)   
   { 
   printf("ConnectTo: %s@%s:%d\n", ctx->backctx->sn, ctx->backctx->name, ctx->backctx->port);
   if ( ((ctx->backctx->mode & CDHIM) == CDHIM) || ((ctx->backctx->mode & CBINDERIM) == CBINDERIM) || ((ctx->backctx->mode & CDERIVEIM) == CDERIVEIM) )
   printf ("Using Local Identity Module HW=%d\n",myhw);
   else if ( ( (ctx->backctx->mode & CDHNET) == CDHNET) || ((ctx->backctx->mode & CBINDERNET) == CBINDERNET)  )
   { if ((ctx->backctx->netctx->mode & CIMTLSSE) == CIMTLSSE) printf("Use Identity Module over TLSSE\n");
     else printf("Using Identity Module over RACSL\n");
   }
   else printf("Using Sofware Identity Module\n");
   }
  	  ftime(&timebuffer0);	
      t1 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
	  err= TLS_open(ctx->backctx);
      ftime(&timebuffer0);	
      t2 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
      TLS_close(ctx);
      if (!ctx->fquiet) 
      printf("TLS1.3 Disconnected from %s\n",ctx->sn);
      if (!ctx->backctx->fquiet && (err>=0) ) 
      printf("TLS1.3 Client %s is connected in %d ms\n",ctx->backctx->sn,(int)(t2-t1));
      return err;
   }
   
   //if (err <0) 
   //{ TLS_close(ctx);return -1 ;}
    
   ftime(&timebuffer0);	
   t2 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;

   if (!ctx->fquiet) 
   printf("ClientSession with %s opened in %d ms\n",ctx->sn,(int)(t2-t1));
 
   shell(ctx);
   //err= TLS_cmda(ctx,"?00\r\n");
   TLS_close(ctx);
   
   if (!ctx->fquiet) 
   printf("TLS1.3 Disconnected from %s\n",ctx->sn);
 

   return 0;

}





void tls13_c0(T_CTX * ctx)
{  int err  ;
   struct timeb timebuffer0;
   long t1=0,t2=0;

   if (open_tlsim(ctx)!=0) return;
   
   ftime(&timebuffer0);	
   t1 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
   err= TLS_open(ctx) ;
   ftime(&timebuffer0);	
   t2 =  (long)((timebuffer0.time % 3600)*1000) + (long)timebuffer0.millitm   ;
 
   close_tlsim(ctx);
   
   if (err <0) { TLS_close(ctx);return ;}
   if (!ctx->fquiet) 
   printf("TLS1.3 Client is connected in %d ms\n",(int)(t2-t1));

   if (ctx->sign)
   err=sign(ctx); 

   if (ctx->auth)
   {   err=auth(ctx);
       if (err != 1)
	   { printf("Client is not authenticated...\n");
		 TLS_close(ctx);
	     return ;
	   }
   }
   
   shell(ctx);
   //err= TLS_cmda(ctx,"?00\r\n");
   
   TLS_close(ctx);

   return;

}

int auth(T_CTX * ctx)
{ int err,len;
  char pub[65] ;
  char sig[72];
  char rs[64];
  char zero[64];
  char CAPub[65];
  char rnd[32]  ;
  MYSHA256_CTX sha2;
  char h[32];
  int i;

  memset(zero,0,64);

  strcpy(ctx->tx,"?0A\r\n");len=(int)strlen(ctx->tx);
  if (!ctx->fquiet) printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return -1;
  if (strcmp(ctx->rx,"ERROR\r\n") == 0)
	  return 0;
  if (err != 132) return 0;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);
  ctx->rx[130]=0;
  err= Ascii2bin(ctx->rx,pub);
  if (err != 65) return 0;

  strcpy(ctx->tx,"?0B\r\n");len=(int)strlen(ctx->tx);
  if (!ctx->fquiet)  printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return -1;
  if (strcmp(ctx->rx,"ERROR\r\n") == 0)
	  return 0;
  if (err != 130) return 0;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);
  ctx->rx[128]=0;
  err= Ascii2bin(ctx->rx,rs);
  if (err != 64) return 0;
  if (memcmp(rs,zero,64) == 0) return 0;
  
  len= asn1(sig,rs,rs+32);

  err= Ascii2bin(ctx->CAPub,CAPub);
  mysha256_init(&sha2);
  mysha256_update(&sha2,pub+1,64);
  mysha256_final(&sha2,h);

  err= ecc_verify(sig, len, h, 32, CAPub,1);
  if (err != 0) return 0;

  err=myrnd(0,rnd,32,ctx->pin,ctx->aid);

  strcpy(ctx->tx,"?0C");
  for(i=0;i<32;i++) sprintf(ctx->tx+3+2*i,"%2.2X",0xFF & rnd[i]);
  strcat(ctx->tx,"\r\n");len=(int)strlen(ctx->tx);
  if (!ctx->fquiet)  printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return 0;
  if (strcmp(ctx->rx,"ERROR\r\n") == 0) return 0;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);

  mysha256_init(&sha2);
  mysha256_update(&sha2,ctx->hs,32);
  mysha256_update(&sha2,rnd,32);
  mysha256_final(&sha2,h);

  len=Ascii2bin(ctx->rx,sig);
  err= ecc_verify(sig, len, h, 32, pub,1);
  if (err != 0) return 0;
  if (!ctx->fquiet) printf("Device %s is authenticated...\n",ctx->sn);
 
  return 1;
}

int sign(T_CTX * ctx)
{ int err,len;
  char pub[65] ;
  char priv[32];
  char sig[72];
  char rs[64];
  char zero[64];
  MYSHA256_CTX sha2;
  char h[32];
  int i;

  memset(zero,0,64);

 strcpy(ctx->tx,"?0B\r\n");len=(int)strlen(ctx->tx);
 if (!ctx->fquiet)  printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return -1;
  if (strcmp(ctx->rx,"ERROR\r\n") == 0)
	  return 0;
  if (err != 130) return 0;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);
  ctx->rx[128]=0;
  err= Ascii2bin(ctx->rx,rs);
  if (err != 64) return 0;
  if (memcmp(rs,zero,64) != 0) return 0;

  strcpy(ctx->tx,"?0A\r\n");len=(int)strlen(ctx->tx);
  if (!ctx->fquiet) printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return -1;
  if (strcmp(ctx->rx,"ERROR\r\n") == 0)
	  return 0;
  if (err != 132) return 0;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);
  ctx->rx[130]=0;
  err= Ascii2bin(ctx->rx,pub);
  if (err != 65) return 0;

  mysha256_init(&sha2);
  mysha256_update(&sha2,pub+1,64);
  mysha256_final(&sha2,h);

  err= Ascii2bin(ctx->CAPriv,priv);
  if (err != 32) return 0;
  len=0;
  err= ecc_sign(h,32,sig,&len,priv,1);
  if (err != 0) return 0;
  err= extractRS(sig,rs,rs+32);
  if (err != 0) return 0;
  strcpy(ctx->tx,"?0E");
  for(i=0;i<64;i++)
  sprintf(ctx->tx+3+2*i,"%2.2X",0xFF & rs[i]);
  strcat(ctx->tx,"\r\n");

  len=(int)strlen(ctx->tx);
  if (!ctx->fquiet) printf("Tx: %s",ctx->tx);
  err= TLS_cmd(ctx,len);
  if (err <0) return -1;
  if (!ctx->fquiet) printf("Rx: %s",ctx->rx);
  if (strcmp(ctx->rx,"OK\r\n") != 0)
  return 0;
  
 
  return 1;
}