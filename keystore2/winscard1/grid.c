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

int DeconnectGridSc(int sc);
static int Ascii2bin(char *data_in,char *data_out);

#define Printf printf
int fdebug=1  ;
int verbose2=1;
int  inuse[128];

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
int CheckGrid(char * name)
{ char line[1024];
  char *token;
  char sep[]= {(char)'/' };
  int len;

  strcpy(line,name);

  token = strtok(line,"/"); 

	if (token == NULL)
		return -1;
 
    len= (int)strlen(token);
	//if ((len >3) && (token[0]=='C') && (token[1]=='O') && (token[2]=='M') )
	//return 2;


     token=strtok(token+1+strlen(token),"");
	 if (token == NULL)
		 return -1;

 return 1;


} 
int CheckGridW(wchar_t * szReader)
{ char line[1024];
  char *token,len;
  

  tobyte(szReader,line);

  token = strtok(line,"/"); 

	if (token == NULL)
		return -1;

    len= (int)strlen(token);
	//if ((len >3) && (token[0]=='C') && (token[1]=='O') && (token[2]=='M') )
	//return 2;

     token=strtok(token+1+strlen(token),"");
	 if (token == NULL)
		 return -1;

 return 1;


} 
*/



int ConnectGridSc(int sc, char * szReader);
int ConnectGridScW(int sc, wchar_t * szReader)
{ char line[128];
  
  tobyte(szReader,line);
  return ConnectGridSc(sc, line);
}


int ConnectGridSc(int sc, char * szReader)
{ char line[1024];
  char *token;
  char sn[128];
  char ip[128];
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
  
static int DTM=0;
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

