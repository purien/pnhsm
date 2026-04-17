/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

// Identity module

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#ifdef WIN32
#include <windows.h>
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <wintypes.h>
#endif

#include <winscard.h>

#include <time.h>
#include <sys/timeb.h>
#include <memory.h>

#include "im.h"
#include "sim.h"

int fim=0 ;
int myhw=0;
int ftrace=1;
int fmono=0 ;
int init_sim=1 ;
int reset_sim=1;

#define Printf printf
int do_verbose=1;
int apdu_dtc=0;
int mtcl=1; //emulation sans contact


#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

SCARDCONTEXT hContext = (SCARDCONTEXT)NULL;
SCARDHANDLE hCard      =(SCARDCONTEXT)NULL;
DWORD dwScope= (DWORD)SCARD_SCOPE_SYSTEM;
DWORD dwState=0;
LPCVOID pvReserved1=  (LPCVOID) NULL;
LPCVOID pvReserved2=  (LPCVOID) NULL;
DWORD Ptcol=0;

int SC_open(char * reader);
int SC_close();

int TxAPDU(char * apdu);
int txAPDU(char * apdu,int asize, char * response, int* rsize);

char *pr[256];
int   Reader_Nb=0;
char  Reader_Buf[4096];
char *Reader = "SCM Microsystems Inc. SCR33x USB Smart Card Reader 0";



int IM_DetectAllReader()
{ DWORD dwReaders;
  char *pname=Reader_Buf;



#ifndef WIN32
dwReaders=sizeof(Reader_Buf);
SCardListReaders((IN SCARDCONTEXT)NULL,NULL,Reader_Buf,&dwReaders);
#else
dwReaders=sizeof(Reader_Buf);
SCardListReadersA((IN SCARDCONTEXT)NULL,NULL,Reader_Buf,&dwReaders);
#endif
  
  Reader_Nb=0;

  pr[0]=0;
  while(strlen(pname) != 0)
  {  pr[Reader_Nb] = pname;
	 Reader_Nb++;
     pname += (1+strlen(pname));
  }

  return(Reader_Nb);
  }

int IM_ClearKeyDH()
{char apdu[260];
  char response[258];
  int rsize;
  int err;
  
  apdu[0]= 0x00;
  apdu[1]= 0x81;
  apdu[2]= 0x00;
  apdu[3]= 0xFF;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  return 0;
  

}

int IM_GenkeyDH(char *pubkey)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;
  int index=0xFF;

  apdu[0]= 0x00;
  apdu[1]= 0x82;
  apdu[2]= 0x01;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;
  
  apdu[0]= 0x00;
  apdu[1]= 0x84;
  apdu[2]= 0x06;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  memmove(pubkey,response+2,65);

  return (0);
}

/*
int IM_Genkey(int index, char *pubkey)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00;
  apdu[1]= 0x81;
  apdu[2]= 0x00;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
 
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  apdu[0]= 0x00;
  apdu[1]= 0x89;
  apdu[2]= 0x00;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  apdu[0]= 0x00;
  apdu[1]= 0x82;
  apdu[2]= 0x00;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  
  apdu[0]= 0x00;
  apdu[1]= 0x84;
  apdu[2]= 0x06;
  apdu[3]= 0xFF & index;
  apdu[4]= 00;
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) );
  else return -1;

  memmove(pubkey,response+2,65);

  return (0);
}

*/


int IM_Random(int len, char *data)
{
char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00;
  apdu[1]= 0x8B;
  apdu[2]= 0x00;
  apdu[3]= 0x00;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(data,response,rsize-2);
      return len;
  }


  return(-1);
}


int IM_Finished(char *data,int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  if (myhw >= 100)
	  return SIM_Binder(data,len,key);

  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x00;
  apdu[3]= 0x0C;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


  return(-1);
}

int IM_Extract_DHE(char * dhe, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  if (myhw >= 100)
	  return SIM_Derive(dhe,len,key);


  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x00;
  apdu[3]= 0x0E;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],dhe,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


  return(-1);
}
 
//00 8A 00 01 41 04
int IM_ECDHE(int index, char *data, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00 ;
  apdu[1]= 0x8A ;
  if (index < 0){apdu[2]= 0x81 ; index=-index;}
  else           apdu[2]= 0x01 ;//0x00;
  apdu[3]= index & 0xFF;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


  return(-1);
}

// 00 84 06 01 00
int IM_ECDHE_PubK(int index,char *data, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00;
  apdu[1]= 0x84;
  apdu[2]= 0x06;
  apdu[3]= index & 0xFF;
  apdu[4]= 0xFF & (len+2);
  
  err= txAPDU(apdu,5,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response+2,rsize-4);
      return 0;
  }


  return(-1);
}




// 0085 000B 03 0020 00

int IM_Client_Early_Traffic(char * data, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x00;
  apdu[3]= 0x0B;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


  return(-1);
}

// 0085 010B 03

int IM_Client_Early_Exporter(char * data, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err;

  apdu[0]= 0x00;
  apdu[1]= 0x85;
  apdu[2]= 0x01;
  apdu[3]= 0x0B;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  memmove(key,response,rsize-2);
      return 0;
  }


  return(-1);
}

int IM_ECDSA(int index, char * data, int len, char *key)
{ char apdu[260];
  char response[258];
  int rsize;
  int err,len1,len2,ref;

  memset(key,0,80);

  apdu[0]= 0x00;
  apdu[1]= 0x80;
  apdu[2]= 0x00;
  apdu[3]= index & 0xFF ;
  apdu[4]= 0xFF & len;
  memmove(&apdu[5],data,len);

  err= txAPDU(apdu,5+len,response,&rsize);
  if (err<0) return err;

 

  if ( (rsize >=2) && (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
  {	  
       memmove(key,response+2,rsize-4);

	   return rsize-4;

	  //00 47 30 45 02 21 
	  ref=5;
	  len1 = 0xFF & response[ref] ;
	  if (len1 > 32) memmove(key,response+ref+1+len1-32,32);
	  else           memmove(key+(32-len1),response+ref+1,len1);

	  ref= 5+len1+2 ;
      len2 = 0xFF & response[ref];
	  if (len2 > 32) memmove(key+32,response+ref+1+len2-32,32);
	  else           memmove(key+32+(32-len2),response+ref+1,len2);
      
	  return 0;
  }


  return(-1);
}

int IM_test(char *pin,char *aid)
{
       int i,err;
       char key[128];
	   char nodata[]={0};
       char nodata2[]={0,32,0};

	   while(1)
	   {
	   err=IM_open(pin,aid);
	   if (err <0) {printf("IM_open error\n"); return err;}
       err=IM_Finished(nodata,sizeof(nodata),key);
       if (err <0) {printf("IM_Finished error\n"); break;}
       IM_Extract_DHE(nodata,sizeof(nodata),key);
       if (err <0) {printf("IM_Extract_DHE\n"); break ;}
       
	   if (myhw < 100)
	   {
        err= IM_Client_Early_Traffic(nodata2,sizeof(nodata2),key) ;
        err= IM_Client_Early_Exporter(nodata2,sizeof(nodata2),key);
        err=IM_ECDSA(0,key,32,key);
		if (err >=0)
		{ for(i=0;i<32;i++)  printf("%02X",key[i]&0xFF); printf("\n");
          for(i=32;i<64;i++) printf("%02X",key[i]&0xFF); printf("\n");
		}
	   }
	   break;
	   }
	   IM_close();

	   return err;
} 

int IM_init(char *myaid)
{ int n,i,err;
  char cmyaid[64];
  sprintf(cmyaid,"00A40400%02d%s",(int)strlen(myaid)/2,myaid);
   
  if (myhw != 0)

#ifndef WIN32
return SIM_init(serialport);
#else
return  SIM_init(comport);
#endif
  n= IM_DetectAllReader();
  if (n<=0) return -1;
  for(i=0;i<n;i++)
  { err= SC_open(pr[i]);
    if (err<0);
	else
	{ err=TxAPDU(cmyaid);
	  if (err>=0) 
	  {SC_close(); 
	   Reader = pr[i]; 
	   return 0;
	 }
      SC_close();
	}

  }
  return -1;
}

int IM_open(char * pin, char *myaid)
{ int err;
  char verify[128];
  char cmyaid[64];
  sprintf(cmyaid,"00A40400%02d%s",(int)strlen(myaid)/2,myaid);
       
  if (myhw != 0)
		return SIM_open(pin,myaid);
	
	err= SC_open(Reader);
	if (err<0) return err;

	err=TxAPDU(cmyaid);
    if (err<0) return err;

	if ((int)strlen(pin) == 4)
	sprintf(verify,"0020 0000 %02X %02X %02X %02X %02X", 0xFF & strlen(pin),0xFF&pin[0],0xFF&pin[1],0xFF&pin[2],0xFF&pin[3]);
	else
	sprintf(verify,"0020 0001 %02X %02X %02X %02X %02X %02X %02X %02X %02X", 0xFF & strlen(pin),0xFF&pin[0],0xFF&pin[1],0xFF&pin[2],0xFF&pin[3],\
	        0xFF&pin[4],0xFF&pin[5],0xFF&pin[6],0xFF&pin[7]);

	
	err=TxAPDU(verify);
    if (err<0) return err;

	return (0);

}

int IM_end()
{ if (myhw != 0)
		return SIM_close(1);

	SC_close();
	return 0;
}

int IM_close()
{   
	if (myhw != 0)
		return SIM_close(0);

	SC_close();
	return 0;
}

int IM_send(char *in,int lenin, char*out, int *lenout,char P1)
{ char apdu[260];
  char response[258];
  int remain, rsize, err, len,cfirst=1,clast=0,ptr=0,ptri=0;

  remain = lenin;
  *lenout=0;
  
  while(1)
  { 
	if (remain <=0)  return -1;

	apdu[0]= 0x00;
    apdu[1]= 0xD8;
    apdu[2]= P1;
    apdu[3]= 0x00;
    
	if (cfirst) { apdu[3]=1; cfirst=0;}//0xFF & len;
	if  (remain <=240){len=remain; clast=1; apdu[3] |= 2; remain=0;}
	else { len = 240; remain -= len;}
    
	apdu[4]= 0xFF & len ;

    memmove(&apdu[5],in+ptr,len);

    err= txAPDU(apdu,5+len,response,&rsize);
	ptr+= len;

    if (err<0)     return -1;
	if (rsize <2)  return -1;

	if ( (rsize > 2) && !clast ) return -1;
    
	if (rsize > 2 )
	{ memmove(out+ptri,response,rsize-2);
	  ptri+= (rsize-2);
	  *lenout=ptri;
	}
	
    if ( (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
	{ if (!clast) continue ;
	  else        return 0 ;
	}

	else if (response[rsize-2]==(char)0x9F) 
	{   if (!clast) return -1;
		len = 0xFF & response[rsize-1];
		break;
	}
    else  if (response[rsize-2]==(char)0x90) 
	{ if (!clast)  return -1;
	  else         return 0xFF & response[rsize-1] ;
	}

	else
	return -1;
  }

  while(1)
  {
    apdu[0]= 0x00;
    apdu[1]= 0xC0;
    apdu[2]= 0x00;
    apdu[3]= 0x00 ;
    apdu[4]= 0xFF & len ;

    err= txAPDU(apdu,5,response,&rsize);
    if (err<0)     return -1;
	if (rsize <2)  return -1;
	
	if (rsize >2)
	{  memmove(out+ptri,response,rsize-2);
	   ptri+= (rsize-2);
      *lenout=ptri;
	}

    if ( (response[rsize-2]==(char)0x90) && (response[rsize-1]==(char)0x00) )
	{ return 0 ;
	}

	else if (response[rsize-2]==(char)0x9F) 
	{   len = 0xFF & response[rsize-1];
	}

	else  if (response[rsize-2]==(char)0x90) 
	return 0xFF & response[rsize-1] ;

	else
	return -1;

  }

  return 0;
}

int SC_close()
{
LONG stat;
if (hCard != (SCARDHANDLE)NULL) 
{ stat =  SCardDisconnect(hCard,(DWORD)SCARD_LEAVE_CARD); 
  hCard = (SCARDHANDLE)NULL ; 
}
if (hContext != (SCARDHANDLE)NULL)
{
stat =  SCardReleaseContext(hContext) ;
hContext=(SCARDHANDLE)NULL ; 
}
return(0);
}


int SC_open(char * reader)
{
  LONG stat;
  BYTE Atr[260];
  DWORD  Atrlen;
  int i;
  BYTE myreader[512];
  DWORD size=512;

  stat = SCardEstablishContext(dwScope,pvReserved1,pvReserved2,&hContext);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 
  
  #ifdef WIN32
  stat = SCardConnectA(hContext,reader,
	                 (DWORD)SCARD_SHARE_SHARED,
                     //(DWORD)SCARD_SHARE_EXCLUSIVE,
	                 (DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
					 &hCard,
					 &Ptcol);
  #else
  stat = SCardConnect(hContext,reader,
	                 (DWORD)SCARD_SHARE_SHARED,
                     //(DWORD)SCARD_SHARE_EXCLUSIVE,
	                 (DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
					 &hCard,
					 &Ptcol);

  #endif

  
  if (stat != SCARD_S_SUCCESS)
  { 
	hCard = (SCARDHANDLE)NULL;
	//if (do_verbose) 
	//Printf("No smartcard or reader %s not connected !!!\n", reader);
	return -1;
  }

  else
  {
   Atrlen= (DWORD)sizeof(Atr);
#ifdef WIN32
   //stat = SCardState(hCard,(LPDWORD)&dwState,(LPDWORD)&Ptcol,(LPBYTE)Atr,(LPDWORD)&Atrlen);
   stat = SCardStatus(hCard,myreader,&size,(LPDWORD)&dwState,(LPDWORD)&Ptcol,(LPBYTE)Atr,(LPDWORD)&Atrlen);
#else
   stat = SCardStatus(hCard,myreader,&size,(LPDWORD)&dwState,(LPDWORD)&Ptcol,(LPBYTE)Atr,(LPDWORD)&Atrlen);
#endif


   if ((stat != SCARD_S_SUCCESS) || (dwState == SCARD_ABSENT))
   {   stat =  SCardDisconnect(hCard,(DWORD)SCARD_LEAVE_CARD) ; 
	   stat =  SCardReleaseContext(hContext);
	   return -1;
   }
	
   if (do_verbose) 
   {
   Printf("Atr: ");
	for (i=0;i<(int)Atrlen;i++)
		Printf("%2.2X ",0xFF & Atr[i]);
    Printf("\n");
   }
   
  }

  return 0;


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
	char *data_in = NULL;
    
	len =(int) strlen(Data_In);
	data_in = malloc(1+len);
	if (data_in == NULL) { *data_out=0;return(0);}

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

		v &= 0xFF;data_out[j++]= v ;
		deb=fin=-1;iCt=0;
	   }
    }

	free(data_in);

return(j);
}


#define PSIZE 16

#define IOCTL_CCID_ESCAPE SCARD_CTL_CODE(3500)

LONG asend
( IN LPCBYTE request,
  IN DWORD Asize,
  IN OUT LPSCARD_IO_REQUEST pioRecvPci,
  OUT LPBYTE Response,
  IN OUT LPDWORD pRsize)
{ LONG v;
  int i,max;
  char CLA;
  struct timeb timebuffer1;
  struct timeb timebuffer2;
  int t1,t2,dtm ;

  char request2[5];

  max= *pRsize;
  CLA= request[0];

if (do_verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)Asize;i++)
  {	   if (ftrace ==0)
       { if ( (i!=0) && (i%PSIZE == 0) ) Printf("\n    ");
         Printf("%2.2X ",0xff & request[i]);
       }
       else
       Printf("%2.2X",0xff & request[i]);
  }
  Printf("\n");
}


ftime(&timebuffer1);
//if      ( Ptcol == 0) v=SCardControl (hCard,IOCTL_CCID_ESCAPE,request,Asize,Response,*pRsize,pRsize);
if ( Ptcol == 1)      v=SCardTransmit(hCard,SCARD_PCI_T0, request,Asize,pioRecvPci,Response,pRsize);
else if ( Ptcol == 2) v=SCardTransmit(hCard,SCARD_PCI_T1, request,Asize,pioRecvPci,Response,pRsize); 
else                  v=SCardTransmit(hCard,SCARD_PCI_RAW,request,Asize,pioRecvPci,Response,pRsize);         
ftime(&timebuffer2);

t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;
apdu_dtc += dtm;

if (do_verbose)
{ Printf("Rx: ");
  if (v == SCARD_S_SUCCESS )
  {
  for(i=0;i<(int)*pRsize;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & Response[i]);
  }
  }
  Printf(" [%d ms]\n", dtm);
}

if ( (*pRsize == 2) && (Response[0]==(char)0x61) && mtcl)
{
request2[0]= CLA;
request2[1]=(char)0xC0;
request2[2]=(char)0;
request2[3]=(char)0;
request2[4]=Response[1];
Asize=5;

*pRsize=max;

if (do_verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)Asize;i++)
  {	   if (ftrace == 0)
       { if ( (i!=0) && (i%PSIZE == 0) ) Printf("\n    ");
         Printf("%2.2X ",0xff & request2[i]);
       }
       else
       Printf("%2.2X",0xff & request2[i]);
  }
  Printf("\n");
}

ftime(&timebuffer1);
//if      ( Ptcol == 0) v=SCardControl (hCard,IOCTL_CCID_ESCAPE,request2,Asize,Response,*pRsize,pRsize);
if ( Ptcol == 1)      v=SCardTransmit(hCard,SCARD_PCI_T0, request2,Asize,pioRecvPci,Response,pRsize);
else if ( Ptcol == 2) v=SCardTransmit(hCard,SCARD_PCI_T1, request2,Asize,pioRecvPci,Response,pRsize); 
else                  v=SCardTransmit(hCard,SCARD_PCI_RAW,request2,Asize,pioRecvPci,Response,pRsize);         
ftime(&timebuffer2);

t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
dtm = (t2-t1);
if (dtm <0) dtm += 3600000 ;
apdu_dtc += dtm;

if (do_verbose)
{ Printf("Rx: ");
  if (v == SCARD_S_SUCCESS )
  {
  for(i=0;i<(int)*pRsize;i++)
  {	  if ( (i!=0) && (i%PSIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & Response[i]);
  }
  }
  Printf(" [%d ms]\n", dtm);
}

}


return(v);

}

int TxAPDU(char * apdu)
{ char buf[900],out[260];
  char Response[260]    ;
  DWORD len,Rsize=260  ;
  LONG stat;
  int asize=260;

  strcpy(buf,apdu);
  len=  Ascii2bin(buf,out);

  if (myhw == 0)
  stat = asend(out,len,NULL,Response,&Rsize);
  else
  { stat= SIM_txAPDU(out,len,Response,&asize,0);
    Rsize= asize;
  }

  
  if (stat != SCARD_S_SUCCESS)
  return -1 ;
  
  if( (Rsize >=2) && (Response[Rsize-2] == (char)0x90) && (Response[Rsize-1]== (char)0x00) )
	  return 0;
  
  return -1;
}

int txAPDU(char * apdu,int asize, char * response, int* rsize)
{ 
  LONG stat;
  DWORD RSIZE=258 ;
  int size=258;
 
  if (myhw == 0)
  stat =asend(apdu,asize,NULL,response,&RSIZE);
  else
  { stat= SIM_txAPDU(apdu,asize,response,&size,0);
    RSIZE= size;
  }
    
  if (stat != SCARD_S_SUCCESS)
  return -1 ;
  
  *rsize=RSIZE;

  return 0 ;
 
}
