/* grid.c */
/* Copyright (C) 2017-2022 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 *
 * This software is an implementation of the internet draft
 * https://tools.ietf.org/html/draft-urien-core-racs-00
 * "Remote APDU Call Secure (RACS)" by Pascal Urien.
 * The implementation was written so as to conform with this draft.
 * 
 * This software is free for non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution.
 * 
 * Copyright remains Pascal Urien's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Pascal Urien should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes RACS-Server software written by
 *     Pascal Urien (pascal.urien@gmail.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY PASCAL URIEN ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#define _CRT_SECURE_NO_DEPRECATE 1

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <malloc.h>

#ifndef WIN32
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
   #define DWORD long
#else
  #include <winsock.h>
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> 
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ripemd.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

//#define Printf printf
int FDEBUG=1   ; 
int VERBOSE2=1 ;
BIO       *conn[64];
SSL       *ssl[64] ;
SSL_CTX   *ctx[64] ;
#define CIPHER_LIST  "AES128-GCM-SHA256"

static char CADIR[128]      = "./";
static char CAFILE[128]     = {"./cert/clientroot.pem"};
static char CERTFILE[128]   = {"./cert/client.pem"};
static char KEYFILE[128]    = {"./cert/clientkey.pem"};
static char PASSWORD[128]   = {"pascal"};
extern char *cadir;
extern char *password;

extern int  indexs[200]                    ;
extern int  Get_Reader_Index_Abs(int id)   ;
extern int  gPrintf(int id,char *fmt, ... );

static int Ascii2bin(char *data_in,char *data_out);
static int isDigit(char c);

char gridserver[128]="tlsse.dyndns.org";
unsigned short gridport=7785;
int  maxslots=1        ;
int  startslot=1010    ;
char board[32]="Cube2" ;
int  NBSC=16           ;
int  slotid[512]  = {1010} ;
char atrgrid[128][64];
int  lenatrgrid[128] ;
char gridaid[64]="010203040500";

extern long DTM;
#define MAX_MSG 2048

int static testclient(char *uri);


int is_grid137(int num)
{ if (NBSC == 0)
  return 0 ;
  if ( (num>= 0) && (num<NBSC) )
	  return 1;
  return 0;
}

int DeconnectGridSc137(int nbCard, int * sc)
{   int idp;
    
    idp= indexs[Get_Reader_Index_Abs(nbCard-1)];

	SSL_shutdown(ssl[*sc]);
    SSL_clear(ssl[*sc])   ;
    
	if (FDEBUG) 
		gPrintf(idp,"%s","SSL Connection closed\n");
 
    SSL_free(ssl[*sc])    ;
    SSL_CTX_free(ctx[*sc]);

	return (0);
}



int InitializeGrid137()
{ if (maxslots == 0)
  { NBSC=0;
    return(NBSC);
  }

  return(NBSC);
}

#define int_error(msg)  handle_error(__FILE__, __LINE__, msg)
void handle_error(const char *file, int lineno, const char *msg);

static int pem_passwd_cb(char *buf,int size,int rwflag, void *passwd)
{ strcpy(buf,PASSWORD);
  return((int)strlen(buf));
}

SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;
	int err=0;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    //SSL_load_error_strings();      /* load all error messages */

    ctx = SSL_CTX_new(TLSv1_2_client_method());

    SSL_CTX_set_default_passwd_cb(ctx,pem_passwd_cb);

   if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
   { gPrintf(0,"%s\n","Error loading CA file and/or directory");
     int_error("Error");
   }

   if (SSL_CTX_set_default_verify_paths(ctx) != 1)
   { gPrintf(0,"%s\n","Error verify path");
     int_error("Error");
   }

   if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
   { gPrintf(0,"%s\n","Error loading client certificate from file");
     int_error("Error"); 
   }

   if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
   { gPrintf(0,"%s\n","Error loading client key from file");
     int_error("Error");
   }


   if(!SSL_CTX_check_private_key(ctx))
   { gPrintf(0,"%s\n","Error checking ");
     int_error("Error");
   }

    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    //SSL_CTX_set_verify_depth(ctx, 4);

    err =SSL_CTX_set_options(ctx,SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET | SSL_OP_TLS_ROLLBACK_BUG);
 

   if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
   { gPrintf(0,"%s\n","Error setting cipher list (no valid ciphers)");
     int_error("Error");
   }
 
	return ctx;
}

static int do_client_loop(SSL *ssl)
{
    int  err, nwritten;
    char buf[256]= "BEGIN\r\nEND\r\n";
	int len;

	len=(int)strlen(buf);
 
    for (;;)
    {
       
        for (nwritten = 0;  nwritten < len;  nwritten += err)
        {
            err = SSL_write(ssl, buf + nwritten, len - nwritten);
            if (err <= 0)
                return 0;
        }


       err = SSL_read(ssl, buf,(int)sizeof(buf)) ;
            if (err <= 0)
                return 0;
       buf[err]=0;
	   gPrintf(0,"%s",buf);
       break;

    }
	
    return 1;
}

 static int sendstring(char * buf, int sc)
{ int nwritten,err=0,len;

  len = (int)strlen(buf);
  
        for (nwritten = 0;  nwritten < len;  nwritten += err)
        {
            err = SSL_write(ssl[sc], buf + nwritten, len - nwritten);
            if (err <= 0) 
            { 
	         //if (FDEBUG) 
		     //gPrintf(0,"Error sending data to server\n");
             return(-1);
            }
		}

return nwritten;
}

static int parserracs(char *value, int valuesize, int num,int fCopy, int sc)
{ int err,nb=0,len=0,nba,i;
  char *token=NULL ;
  char c; 
  char seps[] = {" \r\n"};
  int state=0;
  char buf[20000];
  int bufsize=20000;
  int nl,nc,check=0;

  while(1)
  {
  
	err = SSL_read(ssl[sc], &buf[nb], bufsize- 1-nb);
    
	if (err <= 0) 
	  break ;

	buf[nb+err]=0;
	//if (VERBOSE2)
	//gPrintf(0,"%s",buf+nb);
	
	len=err;nb+=len;

	for(i=0;i<nb;i++)
	{ if (buf[i] == (char)'\n')
	  { c= buf[i+1]; buf[i+1]=0 ;
	    nba=0;
	    token = strtok(buf,seps);

		switch(state)
		{
		case 0:
			if (strcmp(token,"BEGIN") != 0)
				return -1;
			state=1;
			break;

		case 1:
             if ( token[0] != (char)'+' )
				 return -1;
			  
		     //token = strtok(NULL,seps); // ligne number
             token=strtok(token+1+strlen(token),seps);
			 if (token == NULL)
				 return -1;

			 nc= sscanf(token,"%d",&nl);
			 if (nc < 1)
				 return -1;

             check=1;

			 if (fCopy)
			 {
             //token = strtok(NULL,"\r\n");
             token=strtok(token+1+strlen(token),"\r\n");
			 if (token == NULL)
				 return -1 ;
			 
			 if (nl != num)
				 break;

			 if ((int)strlen(token) >= valuesize )
				 return -1;

			 strcpy(value,token);
			  }

			 state=3;
			

			 break;

            
		case 3:
            if (strcmp(token,"END") != 0)
				return -1;
			
			state=4;
			break;

		}


		buf[i+1]=c;
		if (nb != (i+1)) 
		memmove(buf,&buf[i+1],nb-1 -i-1 +1);
		nb = nb-i-1;
		i=0;

		if (state==4)
		{	if (check)   
		    { if (fCopy) return (int)strlen(value)  ;
			  else       return 0;
	        }
		    else         return -1   ;
		}

	  }

	}



}

return -1;

}



int ConnectGridSc137(int nbCard, int * sc)
{ char line[1024];
  char buf[1000];
  int err;
  int idp;

  *sc=nbCard-1;
 
  idp= indexs[Get_Reader_Index_Abs(nbCard-1)];
  ctx[*sc] = setup_client_ctx();
    
   if (!ctx[*sc])
	{ if (FDEBUG)
	  gPrintf(idp,"%s","Error creating OPENSSL CTX\n");
	  return -1;
	}

   sprintf(line,"%s:%u",gridserver,0xFFFF & gridport);
 
   conn[*sc] = BIO_new_connect(line);

    if (!conn[*sc])
	{  SSL_CTX_free(ctx[*sc]);
	   if (FDEBUG)
       gPrintf(idp,"Error creating connection BIO\n");
	   return -1;
	}
 
    if (BIO_do_connect(conn[*sc]) <= 0)
	{   BIO_free(conn[*sc]); 
		SSL_CTX_free(ctx[*sc]);
		if (FDEBUG) 
	    gPrintf(idp,"%s","Error connecting to remote machine\n");
	    return -1;
	}
 
    ssl[*sc] = SSL_new(ctx[*sc]);

    if (!ssl[*sc])
	{  BIO_free(conn[*sc]); 
	   SSL_CTX_free(ctx[*sc]);
	   if (FDEBUG)
	   gPrintf(idp,"%s","Error creating connection SSL_CTX\n");
	   return -1;
	}

    SSL_set_bio(ssl[*sc], conn[*sc], conn[*sc]);

    if (SSL_connect(ssl[*sc]) <= 0)
	{      SSL_shutdown(ssl[*sc]);
           SSL_clear(ssl[*sc])   ;
           SSL_free(ssl[*sc])    ; 
	       SSL_CTX_free(ctx[*sc]);
		   if (FDEBUG) 
	       gPrintf(idp,"%s","Error connecting SSL object\n");
	       return -1;
	}

    if (FDEBUG) 
		gPrintf(idp,"%s","SSL Connection opened\n");
   
	strcpy(buf,"BEGIN WINSCARD\r\n");
	sprintf(&buf[(int)strlen(buf)],"POWERON %d\r\n",slotid[*sc]);
	sprintf(&buf[(int)strlen(buf)],"END\r\n");

	err= sendstring(buf,*sc);
	if (err < 0)
	{   DeconnectGridSc137(nbCard,sc);
		return -1;
	}

	err= parserracs(buf,(int)sizeof(buf),1,0,*sc);
	if (err < 0)
	{   DeconnectGridSc137(nbCard,sc);
		return-1;
	}

	return 1;

}

 
//======================
// Usefull procedures
//======================
int isDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return(1);
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(1);
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return(1);
  return(0);
}

int Ascii2bin(char *Data_In,char *data_out)
{  	int deb=-1,fin=-1,i,j=0,nc,iCt=0,v,len;
    char c;	
	char data_in[MAX_MSG] ;
    
	len =(int)strlen(Data_In);

	strcpy(data_in,Data_In);

	for(i=0;i<len;i++)
	{ if      ( (deb == -1) && (isDigit(data_in[i])) )             {iCt=1;deb=i;}
      else if ( (deb != -1) && (iCt==1) && (isDigit(data_in[i])) ) {iCt=2;fin=i;}

      if (iCt == 2)
	  { c= data_in[fin+1];
	    data_in[deb+1]= data_in[fin];
		data_in[deb+2]= 0;
	    nc = sscanf(&data_in[deb],"%x",&v);
		data_in[fin+1]=c;

		v &= 0xFF;
		data_out[j++]= v ;
		deb=fin=-1;iCt=0;
	   }
    }



return(j);
}

//#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CIPHER_LIST  "AES128-GCM-SHA256"


   
/* err=init_OpenSSL();
   seed_prng();
   MutexSetup(NB_MUTEX);
   ...
   Mutex_cleanup(NB_MUTEX);

*/


//"127.0.0.1:443"
int testclient(char *uri)
{
    BIO     *conn;
    SSL     *ssl;
    SSL_CTX *ctx;
    FILE *f=NULL;
    SSL_SESSION * session=NULL;
	int err=0;

    ctx = setup_client_ctx();

	conn = BIO_new_connect(uri);

    if (!conn)
        int_error("Error creating connection BIO");
 
    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");
 
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, conn, conn);

   	//SSL_set_session(ssl,NULL);

	if (SSL_connect(ssl) <= 0)
	{ gPrintf(0,"Error connecting SSL object");
	  return -1;
	}

	gPrintf(0,"SSL Connection opened\n");

	if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    if (FDEBUG) gPrintf(0,"SSL Connection closed\n");
 
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

int SendGridSc137(int sc, char* APDU, DWORD APDUlen, char* Response, DWORD* Rlen, int nbCard, int port)
{	int  err;
	char  req[2048];
	char resp[2048];
	int i;  
	struct timeb timebuffer1;
    struct timeb timebuffer2;
    int t1,t2,dtm;
	int idp;

	sc=nbCard-1;

    idp= indexs[Get_Reader_Index_Abs(nbCard-1)];
	
	memset(req,0,sizeof(req));
    memset(resp,0,sizeof(resp));

	sprintf(req, "BEGIN WINSCARD\r\nAPDU %d ",slotid[sc]);
 
	for(i=0;i<(int)APDUlen;i++)
	sprintf(&req[(int)strlen(req)],"%02X",0xFF & (int)APDU[i]);
	//sprintf(&req[(int)strlen(req)]," MORE=61\r\nEND\r\n");
    sprintf(&req[(int)strlen(req)],"\r\nEND\r\n");
	
	if (VERBOSE2)
	{ if (FDEBUG) 
	    gPrintf(idp,"%s",req);
	}

    ftime(&timebuffer1);	
	
 	err= sendstring(req,sc);
	
	if (err < 0)
	{   DeconnectGridSc137(nbCard,&sc);
		return -1;
	}

	err= parserracs(resp,(int)sizeof(resp),1,1,sc);
	
	if (err <= 0)
	{   
		return -1;
	}

	ftime(&timebuffer2);	
   
    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
    t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
    dtm = (t2-t1);
    if (dtm <0) dtm += 3600000 ;

	DTM += dtm;

    if (VERBOSE2)
	{ if (FDEBUG) 
	     gPrintf(idp,">> %d ms\n",dtm);
	}

    *Rlen = Ascii2bin(resp, Response);
     return 1;//SCARD_S_SUCCESS;

}




