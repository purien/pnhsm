/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define _CRT_SECURE_NO_DEPRECATE 
#define _CRT_SECURE_NO_DEPRECATE

#ifdef WIN32
 #include <windows.h>
#else
#include <wintypes.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/timeb.h>
#include <time.h>
#include <malloc.h>
#include <sys/timeb.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
extern SSL_CTX *setup_client_ctx(void);

int DeconnectGridSc(int sc);
static int Ascii2bin(char *data_in,char *data_out);

#define Printf printf
int fdebug=1   ;
int verbose2=1 ;
int inuse[128] ;
BIO       *conn[128];
SSL       *ssl[128] ;
SSL_CTX   *ctx[128] ;
char      mySEID[128][128] ;

extern int tlspsk_open(int n);
extern int tlspsk_close(int n);
extern int tlspsk_cmd(int n,char *buf, int max);

int isinuse(int sc)
{ return (inuse[sc]);
}


int tobyte(wchar_t * szIn, char *buf)
{ int len,i;
  short v;

  len=(int)wcslen(szIn);

  for (i=0;i<len;i++)
  { v= szIn[i];
    buf[i] = (char)v;
  }

  buf[len]=0;
  return len;
}

char *GetKey(char *name)
{ static char line[1024];
  char *token;
  char sep[]= {(char)'/' };
  int len;

  strcpy(line,name);
  token = strtok(line,"/"); 

  if (token == NULL)
  return NULL;
 
  len= (int)strlen(token);

  token=strtok(token+1+strlen(token),"");
  if (token == NULL)
  return NULL;

 return token;
} 

char * GetKeyW(wchar_t * szReader)
{ char line[1024];
  tobyte(szReader,line);
  return GetKey(line);
}




/*
// server:port/KEY
// servet:port/SEN
int CheckGrid(char * name)
{ char *token;
  int len;

  token=GetKey(name);
  if (token == NULL)
	  return -1;

  // len= (int)strlen(token);
  // return 2;


 return 1;
 }

int CheckGridW(wchar_t * szReader)
{ char line[1024];
  tobyte(szReader,line);
  return CheckGrid(line);
} 

*/

int ConnectGridSc(int sc, char * szReader);

int ConnectGridScW(int sc, wchar_t * szReader)
{ char line[128];
  
  tobyte(szReader,line);
  return ConnectGridSc(sc, line);
}

static int DTM;

static int sendstring(char * buf, int sc)
{ int nwritten,err=0,len;

  len = (int)strlen(buf);
  
        for (nwritten = 0;  nwritten < len;  nwritten += err)
        {
            err = SSL_write(ssl[sc], buf + nwritten, len - nwritten);
            if (err <= 0) 
            { 
	         if (fdebug) 
		     Printf("Error sending data to server\n");
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
	if (verbose2)
	printf("%s",buf+nb);
	
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



int ConnectGridSc2(int sc, char * szReader)
{ char line[1024];
  char *token;
  char host[512];
  char buf[1000];
  int err;
  

  if (inuse[sc] != 0)
  return -1;

  strcpy(line,szReader);

  token = strtok(line,"/"); 

	if (token == NULL)
		return -1;

	strcpy(host,token);
  
    //token = strtok(NULL,"");
	token=strtok(token+1+strlen(token),"");
	if (token == NULL)
		 return -1;

	strcpy(mySEID[sc],token);
   
    ctx[sc] = setup_client_ctx();
    
	if (!ctx[sc])
	{  if (fdebug)
	    Printf("Error creating OPENSSL CTX\n");
	  return -1;
	}
 
    conn[sc] = BIO_new_connect(host);

    if (!conn[sc])
	{  SSL_CTX_free(ctx[sc]);
	   if (fdebug)
	    Printf("Error creating connection BIO\n");
	   return -1;
	}
 
    if (BIO_do_connect(conn[sc]) <= 0)
	{   BIO_free(conn[sc]); 
		SSL_CTX_free(ctx[sc]);
		if (fdebug) 
	      Printf("Error connecting to remote machine\n");
	    return -1;
	}
 
    ssl[sc] = SSL_new(ctx[sc]);

    if (!ssl[sc])
	{  BIO_free(conn[sc]); 
	   SSL_CTX_free(ctx[sc]);
	   if (fdebug)
	   Printf("Error creating connection SSL_CTX\n");
	  return -1;
	}

    SSL_set_bio(ssl[sc], conn[sc], conn[sc]);

   	//SSL_set_session(ssl[sc], NULL);


    if (SSL_connect(ssl[sc]) <= 0)
	{      SSL_shutdown(ssl[sc]);
           SSL_clear(ssl[sc])   ;
           SSL_free(ssl[sc])    ; 
	       SSL_CTX_free(ctx[sc]);
		   if (fdebug) 
	       Printf("Error connecting SSL object\n");
	    return -1;
	}

    if (fdebug) 
		Printf("SSL Connection opened\n");
   
	inuse[sc]=1;

	strcpy(buf,"BEGIN WINSCARD\r\n");
	sprintf(&buf[(int)strlen(buf)],"POWERON %s\r\n",mySEID[sc]);
	sprintf(&buf[(int)strlen(buf)],"END\r\n");

	err= sendstring(buf,sc);
	if (err < 0)
	{   DeconnectGridSc(sc);
		return -1;
	}

	err= parserracs(buf,(int)sizeof(buf),1,0,sc);
	if (err < 0)
	{   DeconnectGridSc(sc);
		return-1;
	}

	
	return 1;

}

int ConnectGridScW2(int sc, wchar_t * szReader)
{ char line[512];
  
  tobyte(szReader,line);
  return ConnectGridSc2(sc,line);
}
  
int DeconnectGridSc2(int sc)
{ 
	if (inuse[sc] == 1)
	{
    SSL_shutdown(ssl[sc]);
    SSL_clear(ssl[sc])   ;
    
	if (fdebug) 
		Printf("SSL Connection closed\n");
 
    SSL_free(ssl[sc])    ;
    SSL_CTX_free(ctx[sc]);

	inuse[sc]=0;

	}


  return (0);

}
  

int SendGridSc2(int sc, char* APDU, DWORD APDUlen, char* Response, DWORD* Rlen, int nbCard, int port)
{	int  err;
	char  req[2048];
	char resp[2048];
	int i;  
	struct timeb timebuffer1;
    struct timeb timebuffer2;
    int t1,t2,dtm;
	
	memset(req,0,sizeof(req));
    memset(resp,0,sizeof(resp));

	sprintf(req, "BEGIN WINSCARD\r\nAPDU %s ",mySEID[sc]);
 
	for(i=0;i<(int)APDUlen;i++)
	sprintf(&req[(int)strlen(req)],"%02X",0xFF & (int)APDU[i]);
	//sprintf(&req[(int)strlen(req)]," MORE=61\r\nEND\r\n");
    sprintf(&req[(int)strlen(req)],"\r\nEND\r\n");
	
	if (verbose2)
	{ if (fdebug) 
	    Printf("%s",req);
	}

    ftime(&timebuffer1);	
	
 	err= sendstring(req,sc);
	
	if (err < 0)
	{   DeconnectGridSc(sc);
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

    if (verbose2)
	{ if (fdebug) 
	     Printf(">> %d ms\n",dtm);
	}

    *Rlen = Ascii2bin(resp, Response);
     return 1;//SCARD_S_SUCCESS;

}



int ConnectGridSc(int sc, char * szReader)
{ char line[1024];
  char *token;
  char sn[128] ;
  char ip[512] ;
  char port[32];
  int err;
  char buf[128];
 

  if (inuse[sc] != 0)
	  return -1;

  strcpy(line,szReader);

  token = strtok(line,":"); 

	if (token == NULL)
		return -1;

	strcpy(ip,token);
    
	token = strtok(NULL,"/");

	if (token == NULL)
		return -1;

	strcpy(port,token);
	
	token = strtok(NULL,"");


	if (token == NULL)
		return -1;

	strcpy(sn,token);

    
    //err= Ascii2bin(thispsk[sc-1],MYPSK);

	////////////////////////////////
	err= tlspsk_open(sc-1);
	///////////////////////////////

    if (err < 0)
		return -1;

    if (fdebug) 
    Printf("TLS1.3 Connection Opened\n");
   
	inuse[sc]=1;

	strcpy(buf,"on\r\n");

	/////////////////////////////////////////
    err=tlspsk_cmd(sc-1,buf,(int)sizeof(buf));
    /////////////////////////////////////////

	if (err >= 0)
	{ if (strcmp(buf,"OK\r\n") != 0)
	  err=-1;
	}
	
	if (err < 0)
	{   DeconnectGridSc(sc);
		return -1;
	}

	
	return 1;

}

  
int DeconnectGridSc(int sc)
{ int err=0;

	if (inuse[sc] == 1)
	{ /////////////////////
	  err=tlspsk_close(sc-1);
  	  /////////////////////
	  inuse[sc]=0;
	}

  return (0);

}
  
int SendGridSc(int sc, char* APDU, DWORD APDUlen, char* Response, DWORD* Rlen, int nbCard, int port)
{	int  err;
	char  req[2048];
	int i;  
	struct timeb timebuffer1;
    struct timeb timebuffer2;
    int t1,t2,dtm;
	
	memset(req,0,sizeof(req));
    
	sprintf(req, "A ");
 
	for(i=0;i<(int)APDUlen;i++)
	sprintf(&req[(int)strlen(req)],"%02X",0xFF & (int)APDU[i]);
	sprintf(&req[(int)strlen(req)],"\r\n");
	
	if (verbose2)
	{ if (fdebug) 
	    Printf("%s",req);
	}

   ftime(&timebuffer1);

    /////////////////////////////////////////
    err=tlspsk_cmd(sc-1,req,(int)sizeof(req));
    /////////////////////////////////////////
	
 	if (err >= 0)
	{ if (strcmp(req,"ERROR\r\n") == 0)
	  err= -1;
	  else if (verbose2)
	  { if (fdebug) 
	    Printf("%s",req);
	  }
	  
	}
	
	if (err < 0)
	{   DeconnectGridSc(sc);
		return -1;
	}
	
	ftime(&timebuffer2);	
   
    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
    t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
    dtm = (t2-t1);
    if (dtm <0) dtm += 3600000 ;

	DTM += dtm;

    if (verbose2)
	{ if (fdebug)Printf(">> %d ms\n",dtm);
	} 

    *Rlen = Ascii2bin(req, Response);
     return 1;//SCARD_S_SUCCESS;
}

//======================
// Usefull procedures
//======================
static int isDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return(1);
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(1);
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return(1);
  return(0);
}

static int Ascii2bin(char *Data_In,char *data_out)
{  	int deb=-1,fin=-1,i,j=0,nc,iCt=0,v,len;
    char c;	
	char data_in[2048] ;
    
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

