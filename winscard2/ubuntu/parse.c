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

int fconsole=0;
int f_for_ever=0;
static int f_client=0;

extern int verbose,ftrace,do_verbose,mybaud;

extern int fim,myhw,fmono,comport,reset_sim;
extern int RESETWAITTIME;

#define CMDMAXSIZE MAXTLSBUFSIZE
int  fcomd=0,fbanner=0,fcptr=0,fcnb=0;
char mycomd[128][CMDMAXSIZE];
char acomd[CMDMAXSIZE];
char reply[CMDMAXSIZE];
int  ncmd[128];
int  mydelay=0;

char myfkey[128];
char *pfx=NULL  ;
char px='r';
int  fxset=0;
int  fxset2=0;
#define MAXMETA 1024
#define MAXFILE   64
int  fkey[MAXFILE];
char fxmeta[MAXFILE][MAXMETA];
char fxname[MAXFILE][1024];
int  fxnb=0;
int  ptfx=0;
int  fenc[MAXFILE];
int  fdec[MAXFILE];
int  fench[MAXFILE];
int  fdech[MAXFILE];

int  usePsk=1;
char *host="127.0.0.1";
int   port=8888;
char *cipher="aesccm";
char *sniHostName="key1.com";
char impin[32]= "0000";
char imaid[64]= "010203040500";
char MYPSK[129];
char MYPSKID[129];

char MYPSKID2[129];

int tcrypto=0;
int ttlsim=0;

extern char serialport[512];
extern char cardconfig[512];

extern char *  hname(char *name, char *meta, char * aresult);
extern char * hname2(char *name, char *meta, char * aresult);
extern int Ascii2bin(char *Data_In,char *data_out);
char * getmeta(char *name, char *meta, int max);
extern int fcrypt(char *akey, char *name,char *meta);
extern int fdecrypt(char *akey, char *name);


static int   myoptind=0;
static char* myoptarg=NULL;
static char* next = NULL;

#define XSTRNCMP(s1,s2,n) strncmp((s1),(s2),(n))

static int mygetopt(int argc, char** argv, const char* optstring)
{
    static char  c=0;
    static char* cp=NULL;

    if (argv == NULL)  {
        myoptarg = NULL;
        return -1;
    }

    if (myoptind == 0)
        next = NULL;   /* we're starting new/over */

    if (next == NULL || *next == '\0')
	{
        if (myoptind == 0)
		{  if (argc==1) return -1;  
		   myoptind=2 ;
		}

        if (myoptind >= argc || argv[myoptind] == NULL ||
            argv[myoptind][0] != '-' || argv[myoptind][1] == '\0') 
		{
            myoptarg = NULL;
            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        if (strcmp(argv[myoptind], "--") == 0) 
		{
            myoptind++;
            myoptarg = NULL;

            if (myoptind < argc)
                myoptarg = argv[myoptind];

            return -1;
        }

        next = argv[myoptind];
        next++;                  /* skip - */
        myoptind++;
    }

    c  = *next++;
    /* The C++ strchr can return a different value */
    cp = (char*)strchr(optstring, c);

    if (cp == NULL || c == ':')
    return '?';

    cp++;

    if (*cp == ':') {
        if (*next != '\0') 
		{
            myoptarg = next;
            next     = NULL;
        }
        else if (myoptind < argc) 
		{
            myoptarg = argv[myoptind];
            myoptind++;
        }
        else
            return '?';
    }

    return c;
}

   
  
  
 int parse(int argc, char  **argv,T_CTX *ctx)
 { int ch=0,lng_index=0;
   int err=0;
   
   myoptind=0;

   while ((ch = mygetopt(argc, argv, "?:""cc"
		"ab:defgh:ijk:l:mnop:q:rstuv:wxyz"
            "A:B:CDE:F:GH:IJKL:M:NO:PQRS:TUVW:XYZ:"
            "01:23:458")) != -1) 
	    {
        switch (ch) 
		{
            case '?' :
                if(myoptarg!=NULL) 
				{
                    lng_index = atoi(myoptarg);
                    if(lng_index<0||lng_index>1){
                        lng_index = 0;
                    }
                }
                //Usage();
                return 0;

			case 'c' :
                f_client=1;
				break;

            case 's' :
                usePsk = 1;
                break;

  
            case 'h' :
                host   = myoptarg;
				ctx->name = host ;
                break;

            case 'p' :
                port = atoi(myoptarg);
				ctx->port=port;
                break;

 
            case 'V' :
                //ShowVersions();
                return 0;

			case 'l' :
                cipher = myoptarg;
				if (strcmp(cipher,"TLS_AES_128_GCM_SHA256")==0) ctx->ciphersuite=AES128GCM ;
				else if (strcmp(cipher,"aesgcm")==0)            ctx->ciphersuite=AES128GCM ;
				else ctx->ciphersuite=AES128CCM ;
                break;

            case 'H' :
              
				if (XSTRNCMP(myoptarg, "noconsole", 9) == 0) 
                    fconsole=0;
				
				else if (XSTRNCMP(myoptarg, "console", 7) == 0) 
                    fconsole=1;

                else if (XSTRNCMP(myoptarg, "forever", 7) == 0) 
					 {  f_for_ever= 1; fconsole=1;}

                
				else if (XSTRNCMP(myoptarg, "timeout", 7) == 0) 
					 ctx->timeout= ctx->netctx->timeout=atoi(myoptarg+7);

				else if (XSTRNCMP(myoptarg, "rstwait", 7) == 0) 
					 RESETWAITTIME=atoi(myoptarg+7);

				else if (XSTRNCMP(myoptarg, "quiet", 5) == 0) 
				{  ctx->fquiet=1; 
				   ctx->netctx->fquiet=1;
				   verbose=ftrace=do_verbose=0;
				}

				else if (XSTRNCMP(myoptarg, "verbose", 7) == 0) 
				{  ctx->fquiet=0;
				   verbose=ftrace=do_verbose=1;
				}

				else if (XSTRNCMP(myoptarg, "cardconf", 8) == 0) 
				{  strcpy(cardconfig,myoptarg+8);
				}

                else if (XSTRNCMP(myoptarg, "noreset", 7) == 0) 
                    reset_sim=0;


				else if (XSTRNCMP(myoptarg, "reset", 5) == 0) 
                    reset_sim=1;

               
				else if (XSTRNCMP(myoptarg, "baud",4) == 0) 
			         mybaud=atoi(myoptarg+4);
				
                else if (XSTRNCMP(myoptarg, "im", 2) == 0) 
					 { fim=1;
				       myhw=0;fmono=0;
					   mybaud=19200;
					   ctx->mode = CDERIVEIM  | CBINDERIM ;
				     }

                else if (XSTRNCMP(myoptarg, "noim", 4) == 0) 
					 { fim=0;
				       myhw=0;fmono=0;
                       ctx->mode = CBINDERSOFT | CDHSOFT ;
				     }


                else if (XSTRNCMP(myoptarg, "rnoim", 5) == 0) 
					 { fim=0;
				       myhw=0;fmono=0;
                       ctx->mode = CBINDERSOFT | CDHSOFT ;
				     }


               else if (XSTRNCMP(myoptarg, "tc", 2) == 0) 
					 { fim=1 ;
			           myhw=1;fmono=0;
                       mybaud=19200;
                       ctx->mode = CDERIVEIM | CBINDERIM ;
				     }
               
			   else if (XSTRNCMP(myoptarg, "mc", 2) == 0) 
					 { fim=1;
			           myhw=2;fmono=1;mybaud=115200;
                       ctx->mode = CDERIVEIM | CBINDERIM ;
					 }
			   
			   else if (XSTRNCMP(myoptarg, "hw", 2) == 0) 
					 { fim=1;fmono=0;mybaud=19200;
					   myhw= atoi(myoptarg+2);
					   ctx->mode = CDERIVEIM | CBINDERIM ;
                       if (myhw==2)   {fmono=1;mybaud=115200;}  
                       if (myhw==101) {fmono=0;mybaud=19200;} 
                       if (myhw==144) {fmono=0;mybaud=9600;}  
					 }

               else if (XSTRNCMP(myoptarg, "rhw", 3) == 0) 
					 { fim=1;fmono=0;mybaud=19200;
					   myhw= atoi(myoptarg+3);
					   ctx->netctx->mode |= CDERIVEIM | CBINDERIM;
                       if (myhw==2)   {fmono=1;mybaud=115200;}  
                       if (myhw==101) {fmono=0;mybaud=19200;} 
                       if (myhw==144) {fmono=0;mybaud=9600;}  
					 }


			   else if (XSTRNCMP(myoptarg, "rh", 2) == 0) 
			   {  host   = myoptarg+2;
				  ctx->netctx->name = host ;
			   }

               else if (XSTRNCMP(myoptarg, "rS", 2) == 0) 
			   {  sniHostName = myoptarg+2;
				  ctx->netctx->sn=sniHostName ;
			   }
               
			   else if (XSTRNCMP(myoptarg, "rl", 2) == 0)
			   {cipher = myoptarg+2;
				if (strcmp(cipher,"TLS_AES_128_GCM_SHA256")==0) ctx->netctx->ciphersuite=AES128GCM ;
				else if (strcmp(cipher,"aesgcm")==0)            ctx->netctx->ciphersuite=AES128GCM ;
				else ctx->netctx->ciphersuite=AES128CCM ;
			   }

               else if (XSTRNCMP(myoptarg, "com", 3) == 0) 
					 { comport= atoi(myoptarg+3);
			         }

               else if (XSTRNCMP(myoptarg, "serial", 6) == 0) 
					 { strcpy(serialport,myoptarg+6);
			         }
              

               else if (XSTRNCMP(myoptarg, "ttcrypto", 8) == 0) 
					 { tcrypto=1;
			         }

              else if (XSTRNCMP(myoptarg, "tttlsim", 7) == 0) 
					 { ttlsim=1;
			         }




			   else if (XSTRNCMP(myoptarg, "pin", 3) == 0) 
					 { strcpy(impin,myoptarg+3);
			           strcpy(ctx->pin,impin)  ;
			         }

               else if (XSTRNCMP(myoptarg, "aid", 3) == 0) 
					 { strcpy(imaid,myoptarg+3);
			           strcpy(ctx->aid,imaid)  ;
				     }
			   
			   else if (XSTRNCMP(myoptarg, "rpin", 4) == 0) 
					 { strcpy(impin,myoptarg+4);
			           strcpy(ctx->netctx->pin,impin)  ;
			         }

			   else if (XSTRNCMP(myoptarg, "rpsk", 4) == 0) 
					 {  if ((int)strlen(myoptarg+4) > 64) break   ;
						err= Ascii2bin(myoptarg+4,(char *)MYPSK)  ;
			            if (err == 32) memmove(ctx->netctx->psk,MYPSK,err);
			         }
			   
               else if (XSTRNCMP(myoptarg, "rp", 2) == 0) 
			   {  port = atoi(myoptarg+2);
				  ctx->netctx->port=port;
			   }

               else if (XSTRNCMP(myoptarg, "raid", 4) == 0) 
					 { strcpy(imaid,myoptarg+4);
			           strcpy(ctx->netctx->aid,imaid);
				     }

               
			   else if (XSTRNCMP(myoptarg, "rimtlsse", 8) == 0) 
					 { ctx->mode = CDHNET | CBINDERNET ;
			           ctx->netctx->mode = CIMTLSSE    ;
				     }

			   else if (XSTRNCMP(myoptarg, "rimask", 6) == 0) 
					 { ctx->mode = CDHNET | CBINDERNET ;
			           ctx->netctx->mode = CIMTLSSE | CIMASK  ;
				     }
 
               
			   else if (XSTRNCMP(myoptarg, "rim", 3) == 0) 
					 { ctx->mode = CDHNET | CBINDERNET ;
				     }

			   else if (XSTRNCMP(myoptarg, "psk", 3) == 0) 
					 {  if ((int)strlen(myoptarg+3) > 64) break   ;
						err= Ascii2bin(myoptarg+3,(char *)MYPSK)  ;
			            if (err == 32) memmove(ctx->psk,MYPSK,err);
			         }


			   
			   else if (XSTRNCMP(myoptarg, "identity", 8) == 0) 
					 {  strcpy(MYPSKID,myoptarg+8);
			            ctx->identity=myoptarg+8;//MYPSKID;
 		             }
          

			   else if (XSTRNCMP(myoptarg, "ridentity", 9) == 0) 
					 {  strcpy(MYPSKID2,myoptarg+9);
			            ctx->netctx->identity=myoptarg+9;//MYPSKID2;
 		             }
 

			   else if (XSTRNCMP(myoptarg, "rauth", 5) == 0) 
					 { strcpy(ctx->netctx->CAPub,myoptarg+5);
			           ctx->netctx->auth=1;
 		             }


			   else if (XSTRNCMP(myoptarg, "auth", 4) == 0) 
					 { strcpy(ctx->CAPub,myoptarg+4);
			           ctx->auth=1;
 		             }


			   else if (XSTRNCMP(myoptarg, "rsign", 5) == 0) 
					 { strcpy(ctx->netctx->CAPriv,myoptarg+5);
			           ctx->sign=1;
 		             }


			   else if (XSTRNCMP(myoptarg, "sign", 4) == 0) 
					 { strcpy(ctx->CAPriv,myoptarg+4);
			           ctx->sign=1;
 		             }




			   else if (XSTRNCMP(myoptarg, "enc", 3) == 0) 
			   {  
						if ( (myoptarg+3) == NULL) break;
						
						strcpy(fxname[fxnb],myoptarg+3);
				 
			            sprintf(mycomd[fcnb],"%s%2.2X","b",0xFF & fkey[fxnb]);
						hname(fxname[fxnb],fxmeta[fxnb],3+mycomd[fcnb]);
				        strcat(mycomd[fcnb],"\r\n");
				        ncmd[fcnb]=1;
                        fcnb++ ;
                        sprintf(mycomd[fcnb],"%s%2.2X","r",0xFF & fkey[fxnb]);
                        strcat(mycomd[fcnb],"\r\n");
                        ncmd[fcnb]=1;
                        fcnb++ ;
				        fcomd=1;
                        fdec[fxnb]=0 ;
			            fenc[fxnb]=1 ;
						fxnb++;
				     }
			   
			   else if (XSTRNCMP(myoptarg, "dec", 3) == 0) 
					 {  if ( (myoptarg+3) == NULL)   break;
			            					 
						strcpy(fxname[fxnb],myoptarg+3);
                        if ((int)strlen(fxname[fxnb]) < 5) break;
			           		           
			            sprintf(mycomd[fcnb],"%s%2.2X","b",0xFF & fkey[fxnb]);
						
						pfx = getmeta(fxname[fxnb],fxmeta[fxnb],(int)MAXMETA);
						if (pfx == NULL) break;

						reply[0]=fxname[fxnb][(int)strlen(fxname[fxnb])-4];
                        fxname[fxnb][(int)strlen(fxname[fxnb])-4]=0       ;
						hname(fxname[fxnb],fxmeta[fxnb],3+mycomd[fcnb]);
                        fxname[fxnb][(int)strlen(fxname[fxnb])]=reply[0];

				        strcat(mycomd[fcnb],"\r\n");
				        ncmd[fcnb]=1;
                        fcnb++ ;
                        sprintf(mycomd[fcnb],"%s%2.2X","r",0xFF & fkey[fxnb]);
                        strcat(mycomd[fcnb],"\r\n");
                        ncmd[fcnb]=1;
                        fcnb++ ;
				        fcomd=1;
                        fenc[fxnb]=0;
			            fdec[fxnb]=1;
						if (fxnb < (MAXFILE-1)) fxnb++;
						
				     }

			   else if (XSTRNCMP(myoptarg, "Enc", 3) == 0) 
					 {  
						if ( (myoptarg+3) == NULL) break;
						
						strcpy(fxname[fxnb],myoptarg+3);
				 
			            sprintf(mycomd[fcnb],"%s%2.2X","h",0xFF & fkey[fxnb]);
						hname2(fxname[fxnb],fxmeta[fxnb],3+mycomd[fcnb]);
				        strcat(mycomd[fcnb],"\r\n");
				        ncmd[fcnb]=1;
                        fcnb++ ;
                        fcomd=1 ;
                        fdech[fxnb]=0 ;
			            fench[fxnb]=1 ;
						if (fxnb < (MAXFILE-1)) fxnb++;
				     }
			   
			   else if (XSTRNCMP(myoptarg, "Dec", 3) == 0) 
					 {  
						if ( (myoptarg+3) == NULL)   break;
			            					 
						strcpy(fxname[fxnb],myoptarg+3);
                        if ((int)strlen(fxname[fxnb]) < 5) break;
			           		           
			            sprintf(mycomd[fcnb],"%s%2.2X","h",0xFF & fkey[fxnb]);
						
						pfx = getmeta(fxname[fxnb],fxmeta[fxnb],(int)MAXMETA);
						if (pfx == NULL) break;

						reply[0]=fxname[fxnb][(int)strlen(fxname[fxnb])-4];
                        fxname[fxnb][(int)strlen(fxname[fxnb])-4]=0       ;
						hname2(fxname[fxnb],fxmeta[fxnb],3+mycomd[fcnb]);
                        fxname[fxnb][(int)strlen(fxname[fxnb])]=reply[0];

				        strcat(mycomd[fcnb],"\r\n");
				        ncmd[fcnb]=1;
                        fcnb++ ;
                        fcomd=1;
                        fench[fxnb]=0;
			            fdech[fxnb]=1;
						if (fxnb < (MAXFILE-1)) fxnb++;
				     }


               else if (XSTRNCMP(myoptarg, "meta", 4) == 0) 
					 {  strcpy(fxmeta[fxnb],myoptarg+4);
			         }

               else if (XSTRNCMP(myoptarg, "fkey", 4) == 0) 
					 {  fkey[fxnb]= atoi(myoptarg+4);
			         }

			  else if ((XSTRNCMP(myoptarg, "#", 1) == 0) || (XSTRNCMP(myoptarg, "*", 1) == 0)) 
				{ strcpy(mycomd[fcnb],myoptarg+1);
				  strcat(mycomd[fcnb],"\r\n");
				  ncmd[fcnb]=1;
                  fcnb++ ;
				  fcomd=1;
				}
				
				else if (XSTRNCMP(myoptarg, "@", 1) == 0) 
				{ strcpy(mycomd[fcnb],myoptarg+4);
				  strcat(mycomd[fcnb],"\r\n");
                  *(myoptarg+4)=0;
                  ncmd[fcnb]=atoi(myoptarg+1);
                  fcnb++ ;
				  fcomd=1;
				}

                
				else if (XSTRNCMP(myoptarg, "banner", 2) == 0) 
				{ fbanner=1;}


               else {
                    //Usage();
				    printf("Unknown -H option %s\n",myoptarg);
                    return -1;
                    }
                break;

            case 'S' :
                sniHostName = myoptarg;
				ctx->sn=sniHostName   ;
                break;

            default:
				printf("Unknown option %s\n",myoptarg);
			    return -1 ;
        }
    }

return 0;
}	