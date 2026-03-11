/* 
 * Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
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

#ifndef WIN32
#include <unistd.h>
#define Sleep sleep
#endif

extern int TLS_sendbuf(T_CTX * ctx, char *buf, int len);
extern int TLS_recvbuf(T_CTX * ctx, int fbin);

extern int fconsole  ;
extern int f_for_ever;

#define CMDMAXSIZE MAXTLSBUFSIZE
extern int  fcomd,fbanner,fcptr,fcnb;
extern char mycomd[128][CMDMAXSIZE];
extern char acomd[CMDMAXSIZE];
extern char reply[CMDMAXSIZE];
extern int  ncmd[128];
extern int  mydelay;

extern char myfkey[128];
extern char *pfx       ;
extern char px;
extern int  fxset;
extern int  fxset2;
#define MAXMETA 1024
#define MAXFILE   64
extern int  fkey[MAXFILE];
extern char fxmeta[MAXFILE][MAXMETA];
extern char fxname[MAXFILE][1024];
extern int  fxnb;
extern int  ptfx;
extern int  fenc[MAXFILE];
int  fdec[MAXFILE];
extern int  fench[MAXFILE];
extern int  fdech[MAXFILE];

extern char *  hname(char *name, char *meta, char * aresult);
extern char * hname2(char *name, char *meta, char * aresult);
extern int Ascii2bin(char *Data_In,char *data_out);
char * getmeta(char *name, char *meta, int max);
extern int fcrypt(char *akey, char *name,char *meta);
extern int fdecrypt(char *akey, char *name);


void shell(T_CTX * ctx)
{
   	int delay=0;
    struct timeb timebuffer1;
    struct timeb timebuffer2;
	long t1=0,t2=0;
	int fbin=0; 
	int fcomd=1;
	int err;

	char *reply=ctx->rx;
	char line[CMDMAXSIZE];
	char msg[128]="?00\r\n";

    ftime(&timebuffer1);	
	
    if ( (fconsole == 0) && (fbanner == 1) )
	{ if (!ctx->fquiet) printf("\nRecv: ");
	  err = TLS_recvbuf(ctx,fbin);
	  if (err <= 0) return;
	  ftime(&timebuffer2);
      t1 =  (long)((timebuffer1.time % 3600)*1000) + (long)timebuffer1.millitm   ;
      t2 =  (long)((timebuffer2.time % 3600)*1000) + (long)timebuffer2.millitm   ;
	  printf("%s",ctx->rx);
	  printf("in %d ms\n",(int)(t2-1));
	  if (mydelay != 0) Sleep(mydelay);
      ftime(&timebuffer1);	
	}

    if ( (fconsole == 0) && (fbanner == 0) )
	if (!ctx->fquiet) printf("\n");

    while(1)
	{

    if (fconsole == 0)
	{ if (fcomd == 0) 
	  { if (!ctx->fquiet) printf("Send: %s\n",msg);
		ftime(&timebuffer1);
	    err = TLS_sendbuf(ctx,msg,(int)strlen(msg));
		if (err != 0) break;
	  }
	  else          
	  { if (fcnb >0)
	    { if ( (mycomd[fcptr][0] == '!') || (mycomd[fcptr][0] == ':') )
	       break;
	      
	       if (mycomd[fcptr][0] == '=')
			{   delay= atoi(&mycomd[fcptr][1]);
				Sleep(delay);
                ncmd[fcptr]--;
				if (ncmd[fcptr] <=0)
				{ fcptr++;
				  fcnb-- ;
				}
                ftime(&timebuffer1);	
				continue ;
			}

			else
			{ if (!ctx->fquiet) printf("Send: %s",mycomd[fcptr]);
			  
			 if (mycomd[fcptr][0] == (char)'#') 
			 { fbin=0;
			   if      (mycomd[fcptr][1] == (char)'#') fbin++;
			   else if (mycomd[fcptr][1] == (char)'.')
			   { fbin++;
			     if (mycomd[fcptr][2] == (char)'#') fbin++;
			   }
			   memmove(acomd,&mycomd[fcptr][1],(int)strlen(mycomd[fcptr])-1);
	           err= Ascii2bin(&mycomd[fcptr][4+fbin],&acomd[3+fbin]);
               acomd[3+fbin+err]= '\r' ;
               acomd[4+fbin+err]= '\n' ;
			   err= 5+err+fbin;
			   fbin=1;
			 }

			  if (mycomd[fcptr][0]== px) 
				  fxset=1;
              if (mycomd[fcptr][0]== (char)'h') 
				  fxset2=1;

			  ftime(&timebuffer1);
			  if (fbin == 0)
     		  err= TLS_sendbuf(ctx, mycomd[fcptr], (int)strlen(mycomd[fcptr]));
              else
			  err= TLS_sendbuf(ctx,acomd,err);
			  
			  if (err != 0) break;
			}

	        ncmd[fcptr]--;
			if (ncmd[fcptr] <=0)
			{ fcptr++;
			  fcnb-- ;
			}

	      }
	  }
	}
	else
	{
	if (f_for_ever == 1){strcpy(line,msg);	}
	else
	{
	printf("Send (! or : to exit)\n");
	scanf("%s",line);
	if ((strcmp(line,"!") == 0) || (strcmp(line,":") == 0)) break;
    strcat(line,"\r\n");
	}

    ftime(&timebuffer1);	
	err = TLS_sendbuf(ctx,line,(int)strlen(line));
	}
    if (err != 0) break;
 
	if (fconsole == 0) 
	{ if (fcomd == 0)
	  {err = TLS_recvbuf(ctx,fbin);
	   if (err <= 0) return;
	   ftime(&timebuffer2);	
       t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
       t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
	   printf("%s",ctx->rx);
	   if (!ctx->fquiet) printf("in %d ms\n",(int)(t2-t1));
	  }
	  else
	  {   if (!ctx->fquiet) printf("Recv: "); 
	      // fbin...
	      err = TLS_recvbuf(ctx,fbin);
          if (err <= 0) return;
		  fbin=0;
          
		  if ( (fxset==1) && (fenc[ptfx] || fdec[ptfx]) && (strlen(reply) == 66) )
		  {  fxset=3; strcpy(myfkey,reply); myfkey[64]=0;
		     Ascii2bin(myfkey,myfkey);
		     if (fenc[ptfx]) fcrypt(myfkey,fxname[ptfx],fxmeta[ptfx])  ;
			 if (fdec[ptfx]) fdecrypt(myfkey,fxname[ptfx]);
			 fxset=0;
			 ptfx++;
		  }

		  if ( (fxset2==1) && (fench[ptfx] || fdech[ptfx]) && (strlen(reply) == 66) )
		  {  fxset2=3; strcpy(myfkey,reply); myfkey[64]=0;
		     Ascii2bin(myfkey,myfkey);
		     if (fench[ptfx]) fcrypt(myfkey,fxname[ptfx],fxmeta[ptfx])  ;
			 if (fdech[ptfx]) fdecrypt(myfkey,fxname[ptfx]);
			 fxset2=0;
			 ptfx++;
		  }
		  
		  if (mycomd[fcptr])
          ftime(&timebuffer2);	
          t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
          t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
	      printf("%s",ctx->rx);
		  if (!ctx->fquiet) printf("in %d ms\n",(int)(t2-t1));

	  }
	}

	else 
	{ if (!ctx->fquiet) printf("Recv:\n");
      //fbin
	  err = TLS_recvbuf(ctx,fbin);
	  if (err > 0) memmove(line,ctx->rx,err+1);
	  else break;
	  ftime(&timebuffer2);
      t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
      t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
      printf("%s",line);
	  if (!ctx->fquiet) printf("in %d ms\n",(int)(t2-t1));
	}


    if (fconsole == 1);
	else if (fcnb == 0)	break;

	}
	
	return;
}
	