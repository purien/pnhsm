/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#ifdef WIN32
#include <windows.h>
#else
#include <wintypes.h>
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>


#include <time.h>
#include <memory.h>
#include <sys/timeb.h>
#include <time.h>

#include <winscard.h>

#ifdef  WIN32
#define WIN_API       WINAPI
#define WINSCARD_API  WINSCARDAPI
#else
#define IN
#define OUT
#define WIN_API           
#define WINSCARD_API PCSC_API
#define LPWSTR   LPDWORD
#define LPCWSTR  LPDWORD
#endif


const SCARD_IO_REQUEST g_rgSCardT0Pci, g_rgSCardT1Pci, g_rgSCardRawPci;
// Just make sure we don't accidentally use the wrong global variable...
#define g_rgSCardT0Pci   DONT_USE_ME_g_rgSCardT0Pci
#undef  SCARD_PCI_T0
#define SCARD_PCI_T0     DONT_USE_ME_SCARD_PCI_T0
#define g_rgSCardT1Pci   DONT_USE_ME_g_rgSCardT1Pci
#undef  SCARD_PCI_T1
#define SCARD_PCI_T1     DONT_USE_ME_SCARD_PCI_T1
#define g_rgSCardTRawPci DONT_USE_ME_g_rgSCardTRawPci
#undef  SCARD_PCI_RAW
#define SCARD_PCI_RAW    DONT_USE_ME_SCARD_PCI_RAW

#include "grid.h"
#define Printf printf

extern int inuse[];
extern int fdebug ;
int nbseid=0;
char my_seid[64][1024];
static int  my_type[64];

DWORD thisptcol    = SCARD_PROTOCOL_T1;
static char    Reader_String[4096]  ;
static wchar_t Reader_String_w[4096];

extern char * iniseid(int n);

int emptyline(char *line)
{ char line2[2048],*token;
  
  strcpy(line2,line);
 
  token = strtok(line2," \r\n"); 
  if (token == NULL)  // par exemple 20 20 20 CR LF retourne NULL
	  return 1;

  if (*token == (char)'/')
	  return 1;

  if (*token == (char)'*')
     return 1;

	 return 0;


}


int largc[64];
char* largv[64][512];
char lcline[64][2048];

char cardconfig[512]="cardconfig.txt";

int ReadOpt()
{ FILE *f=NULL;
  char line[2048],line2[2048],*token=NULL,*opt=NULL;
  int k=0;
  char *myseid=NULL;
 
  f = fopen(cardconfig,"rt");

     if (f!= NULL)
	 { 	 
	 for(;;)
	 {
     if (fgets(line,1024,f)== NULL)  break;  // 0x0A=LF is included
	 if (line[(int)strlen(line)-1] == '\n' ) line[(int)strlen(line)-1]=0;
     if (emptyline(line)==1) continue; // comment or empty line

	 strcpy(line2,line);
 
     token  = strtok(line," \r\n") ; 
     	
	 if (token == NULL) continue ;
     opt=token;
	
     token=strtok(token+1+strlen(token)," \r\n");
     
	 if (token == NULL) break ;

     if ((strcmp(opt,"cmd")==0) || (strcmp(opt,"psk")==0))
	 { strcpy(lcline[k],line2);
	   token = strtok(lcline[k]," \r\n"); 
       largv[k][largc[k]]= token;
	   // token = strtok(NULL," \r\n") ;  
	   largc[k]=0;
     while(1)
	 {
     token = strtok(NULL," \r\n") ; 
	 if (token != NULL)
	 { largc[k]++;
	   largv[k][largc[k]]= token;
   	 }
	 else 
	 {   myseid=iniseid(k);
	     strcpy(my_seid[k],myseid);
		 my_type[k]=1;
		 k++;
		 break ;
	 }
	 }
	 }
	 else if (strcmp(opt,"racs")==0)
	 { token = strtok(line2," \r\n"); 
	   token = strtok(NULL," \r\n") ; 
	   if (token != NULL) 
	   { strcpy(my_seid[k],token);
	     my_type[k]=2;
		 k++;
	   }
   	 }
 
	 } // End For

	fclose(f);
	nbseid=k;
	 }

	if (k>0) return(0);

	return -1;


}
#ifdef WIN32
int testapi()
{
  DWORD dwReaders;
  SCARDCONTEXT hContext=(SCARDCONTEXT)NULL  ;
  SCARDHANDLE hCard    =(SCARDCONTEXT)NULL  ;
  DWORD dwScope= (DWORD)SCARD_SCOPE_SYSTEM  ;
  DWORD dwState,dwActiveProtocol,dwProtocol            ;
  LPCVOID pvReserved1=  (LPCVOID) NULL      ;
  LPCVOID pvReserved2=  (LPCVOID) NULL      ;
  LONG stat;
  char Atr[256];
  DWORD AtrLen;
  char  Reader_String[4096];
  wchar_t Reader_String_w[4096];
  char select[]= {(char)0x00,(char)0xA4,(char)0x04,(char)0x00,(char)0x06,(char)0x01,(char)0x02,(char)0x03,(char)0x04,(char)0x08,(char)0x00 };
  char RecvBuffer[1000];

  DWORD Recv;
  
  Reader_String[0]=0;
  Reader_String_w[0]=0;

  dwReaders= sizeof (Reader_String);
  

  // ####################################
  // Etape 0 Liste des lecteurs Installés
  // ####################################
  
  stat= SCardListReadersW((IN SCARDCONTEXT)NULL,(IN LPCWSTR)NULL,Reader_String_w,&dwReaders);
  if (stat != SCARD_S_SUCCESS) return -1;
  stat= SCardListReadersA((IN SCARDCONTEXT)NULL,(IN LPCTSTR)NULL,Reader_String,&dwReaders);
  if (stat != SCARD_S_SUCCESS) return -1;


  hContext=(SCARDCONTEXT)NULL ;
  stat = SCardEstablishContext(dwScope,pvReserved1,pvReserved2,&hContext);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 


  hCard=(SCARDCONTEXT)NULL ;
  
  /*
  stat = SCardConnectW(hContext,Reader_String_w,
	                 (DWORD)SCARD_SHARE_SHARED,
	                 (DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
					 &hCard,
					 &dwActiveProtocol);
  
  */
  stat = SCardConnectA(hContext,Reader_String,
	                 (DWORD)SCARD_SHARE_SHARED,
	                 (DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
					 &hCard,
					 &dwActiveProtocol);
  
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  AtrLen=sizeof(Atr);
  stat = SCardState(hCard,&dwState,&dwActiveProtocol,Atr,&AtrLen);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  stat= SCardListReadersW((IN SCARDCONTEXT)NULL,(IN LPCWSTR)NULL,NULL,&dwReaders);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  stat= SCardStatusW(hCard,Reader_String_w,&dwReaders,&dwState,&dwProtocol,Atr,&AtrLen);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 
  
  stat= SCardListReadersA((IN SCARDCONTEXT)NULL,(IN LPCSTR)NULL,NULL,&dwReaders);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  stat= SCardStatusA(hCard,Reader_String,&dwReaders,&dwState,&dwProtocol,Atr,&AtrLen);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 
 
  Recv= (int)sizeof(RecvBuffer);
  stat= SCardTransmit(hCard,NULL,select,11,NULL,RecvBuffer,&Recv);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  if (hCard != (SCARDCONTEXT)NULL) 
  { SCardDisconnect(hCard,(DWORD)SCARD_LEAVE_CARD) ;
    if (fdebug) printf("TESTAPI OK\n");
  }

  hCard=(SCARDCONTEXT)NULL ;

  stat= SCardReleaseContext(hContext);


 return 0;
}
#else
int testapi()
{
  DWORD dwReaders;
  SCARDCONTEXT hContext=(SCARDCONTEXT)NULL  ;
  SCARDHANDLE hCard    =(SCARDCONTEXT)NULL  ;
  DWORD dwScope= (DWORD)SCARD_SCOPE_SYSTEM  ;
  DWORD dwState,dwActiveProtocol,dwProtocol ;
  LPCVOID pvReserved1=  (LPCVOID) NULL      ;
  LPCVOID pvReserved2=  (LPCVOID) NULL      ;
  LONG stat;
  DWORD Atr[256];
  int AtrLen;
  char  Reader_String[4096];
  wchar_t Reader_String_w[4096];
  char select[]= {(char)0x00,(char)0xA4,(char)0x04,(char)0x00,(char)0x06,(char)0x01,(char)0x02,(char)0x03,(char)0x04,(char)0x08,(char)0x00 };
  char RecvBuffer[1000];

  DWORD Recv;
  
  Reader_String[0]=0;
  Reader_String_w[0]=0;

  dwReaders= sizeof (Reader_String);
  

  // ####################################
  // Etape 0 Liste des lecteurs Installés
  // ####################################
  
 
  stat= SCardListReaders((IN SCARDCONTEXT)NULL,(IN LPCTSTR)NULL,Reader_String,&dwReaders);
  if (stat != SCARD_S_SUCCESS) return -1;


  hContext=(SCARDCONTEXT)NULL ;
  stat = SCardEstablishContext(dwScope,pvReserved1,pvReserved2,&hContext);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 


  hCard=(SCARDCONTEXT)NULL ;
  
  stat = SCardConnect(hContext,Reader_String,
	                 (DWORD)SCARD_SHARE_SHARED,
	                 (DWORD)(SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1),
					 &hCard,
					 &dwActiveProtocol);
   
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  /*
  AtrLen=sizeof(Atr);
  stat = SCardState(hCard,&dwState,&dwActiveProtocol,Atr,&AtrLen);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 
  */

  stat= SCardListReaders((IN SCARDCONTEXT)NULL,(IN LPCWSTR)NULL,NULL,&dwReaders);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  stat= SCardStatus(hCard,Reader_String,&dwReaders,&dwState,&dwProtocol,Atr,&AtrLen);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 
 
  Recv= (int)sizeof(RecvBuffer);
  stat= SCardTransmit(hCard,NULL,select,11,NULL,RecvBuffer,&Recv);
  if (stat  != SCARD_S_SUCCESS)
  return(-1); 

  if (hCard != (SCARDCONTEXT)NULL) 
  { SCardDisconnect(hCard,(DWORD)SCARD_LEAVE_CARD) ;
    if (fdebug) printf("TESTAPI OK\n");
  }

  hCard=(SCARDCONTEXT)NULL ;

  stat= SCardReleaseContext(hContext);


 return 0;
}
#endif



int isGridSc(LPSCARDHANDLE phCard)
{

	if ((int)*phCard <= 0)
		return -1;

	if ( ((int)*phCard >= (int)1024) && ((int)*phCard < (int)2048) )
	return (int)((int)*phCard - (int)1024 + (int)1 );

	return -1;

}

int isGridSc2(LPSCARDHANDLE phCard)
{

	if ((int)*phCard <= 0)
		return -1;

	if ( ((int)*phCard >= (int)2048) && ((int)*phCard < (int)3072) )
	return (int)((int)*phCard - (int)2048 + (int)1 );

	return -1;

}


int GetGridSc(char* szReader)
{  int i;

   for(i=0;i<nbseid;i++)
   {
	   if (strcmp(my_seid[i],szReader) == 0)
		   return i+1;
   }

   return -1;

}

extern tobyte(wchar_t * szIn, char *buf);

int GetGridScW(wchar_t * szReader)
{ int i; 
  char reader[128];

   tobyte(szReader, reader);

   for(i=0;i<nbseid;i++)
   {
	   if (strcmp(my_seid[i],reader) == 0)
		   return i+1;
   }

   return -1;

}

extern int myrnd_init(); 
extern int startTCPIP();
extern int stopTCPIP() ;

extern int init_OpenSSL(void);
extern void seed_prng(void);
extern int incTCPIP() ;
int initthis()
{ int err;
	err=ReadOpt() ;
    myrnd_init()  ; 
    return(err)   ;
}

int closethis()
{
stopTCPIP() ;
return (0)  ;
}

WINSCARD_API LONG WIN_API
SCardEstablishContext(
    IN  DWORD dwScope,
    IN  LPCVOID pvReserved1,
    IN  LPCVOID pvReserved2,
    OUT LPSCARDCONTEXT phContext)
{   int err=0;
    static unsigned long context = 1;
	LONG stat   = SCARD_S_SUCCESS;

	if (nbseid == 0)
    err=initthis(); 
 
    *phContext   = context;


if (fdebug)
Printf("SCardEstablishContext\n");
	//stat = SCardEstablishContext(dwScope,pvReserved1,pvReserved2,phContext);

	if (err <0) return -1;

    err=myrnd_init(); 
    //err=startTCPIP();
    init_OpenSSL();
    seed_prng()   ;
    incTCPIP()    ;

return stat;
}


WINSCARD_API LONG WIN_API
SCardReleaseContext(
IN      SCARDCONTEXT hContext)
{ int err;
  LONG stat= SCARD_S_SUCCESS;

  //stat= SCardReleaseContext(hContext);
if (hContext != (SCARDCONTEXT)NULL)
{
if (fdebug)
Printf("SCardReleaseContext\n");
err=stopTCPIP();
}

return stat;
}



#ifdef WIN32
WINSCARD_API LONG WIN_API
SCardListReadersA(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR mszGroups,
    OUT     LPSTR mszReaders,
    IN OUT  LPDWORD pcchReaders	)
#else
PCSC_API LONG SCardListReaders(
	    SCARDCONTEXT hContext,
		LPCSTR mszGroups,
		LPSTR mszReaders,
		LPDWORD pcchReaders)
#endif
{ 

LONG stat= SCARD_S_SUCCESS;
DWORD ptr=0;
int i,err;
LPSTR mszReaders2= NULL ;

if (fdebug)
Printf("SCardListReadersA\n");

if (mszReaders == NULL) mszReaders2=Reader_String;
else                    mszReaders2=mszReaders;

if (nbseid == 0)
{ err=initthis();
  if (err <0) return stat;
}

for (i=0;i<nbseid;i++)
{
sprintf(mszReaders2+ptr,"%s",my_seid[i]);
ptr += (int)strlen(my_seid[i]) + 1 ;
}

*(mszReaders2+ptr)=0;
ptr+=1;


//*pcchReaders = *pcchReaders - ptr;
*pcchReaders = ptr;

//stat = SCardListReadersA(hContext,mszGroups,mszReaders+ptr,pcchReaders);


return stat;

}

WINSCARD_API LONG WIN_API
SCardListReadersW(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR mszGroups,
    OUT     LPWSTR mszReaders,
    IN OUT  LPDWORD pcchReaders	)
{ 
LONG stat = SCARD_S_SUCCESS;
DWORD ptr=0;
int i,j,err;//result
LPWSTR mszReaders2=NULL;

if (fdebug)
Printf("SCardListReadersW\n");

if (mszReaders == NULL) mszReaders2=Reader_String_w;
else                    mszReaders2=mszReaders;

if (nbseid == 0)
{ err=initthis();
  if (err <0) return stat;
}

for(i=0;i<nbseid;i++)
{
//result = MultiByteToWideChar(CP_OEMCP, 0, my_seid[i], -1, mszReaders2+ptr/2 , (int)strlen(my_seid[i]) + 1);
for(j=0;j<(int)strlen(my_seid[i]);j++)
*((mszReaders2+ptr/2)+j) = (wchar_t)(0xFF & my_seid[i][j]);
*((mszReaders2+ptr/2)+j)=0;

ptr += 2* ((int)strlen(my_seid[i]) + 1); 
}

*(mszReaders2+ptr/2)=0;
ptr+=2;

//if (mszReaders == NULL) *pcchReaders
//*pcchReaders = *pcchReaders - ptr;

*pcchReaders = ptr/2;

return stat;

}


static int DTM=0;

WINSCARD_API LONG WIN_API SCardTransmit(
    IN SCARDHANDLE hCard,
    IN LPCSCARD_IO_REQUEST pioSendPci,
    IN LPCBYTE pbSendBuffer,
    IN DWORD cbSendLength,
    IN OUT LPSCARD_IO_REQUEST pioRecvPci,
    OUT LPBYTE pbRecvBuffer,
    IN OUT LPDWORD pcbRecvLength)

{  LONG stat= SCARD_S_SUCCESS;
   int nb,err; 
   struct timeb timebuffer1;
   struct timeb timebuffer2;
   int t1=0,t2=0,dtm=0;
   BYTE more[] = {(BYTE)0x00, (BYTE)0xC0, (BYTE)0x00, (BYTE)0x00,(BYTE)0x00};
   int todo=1 ;
   DWORD len;

if (fdebug)
Printf("SCardTransmit\n");


  len = *pcbRecvLength;

   while(todo)
   {  
	   dtm=0 ;
	   todo=0;

  
   nb= isGridSc2(&hCard);
   if (nb >0)
   {
        ftime(&timebuffer1);
	    err=SendGridSc2(nb,(char *)pbSendBuffer,cbSendLength,(char *)pbRecvBuffer,pcbRecvLength,nb,0);
        ftime(&timebuffer2);

	   if (err <0)  
		   return -1;
   }

   else
   {
   nb = isGridSc(&hCard);
   if (nb <= 0)
   {
    return -1;
   }

   else
   {   ftime(&timebuffer1);
	   err = SendGridSc(nb,(char *)pbSendBuffer,cbSendLength,(char *)pbRecvBuffer,pcbRecvLength,nb,0);
       ftime(&timebuffer2);

	   if (err <0)
		   return -1;
   }
   }


    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
    t2 =  (int)((timebuffer2.time % 3600)*1000) +   (int)timebuffer2.millitm   ;
    dtm = (t2-t1);
    
	if (dtm <0) 
		dtm += 3600000 ;

	DTM+= dtm;
    //if (fdebug) Printf(">> %d ms\n",dtm);

   }
   
 
   
   return stat;
  

}
// extern int SerialApdu(HANDLE handle,char *req, int rlen, char *resp, int *plen);

static char more[]= {(char)0xA0,(char)0xC0,(char)0x00,(char)0x00,(char)00};


//extern int inuse[128];

#ifdef WIN32
WINSCARD_API LONG WIN_API
SCardConnectA(
    IN      SCARDCONTEXT hContext,
    IN      LPCSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol)
#else
PCSC_API LONG SCardConnect(SCARDCONTEXT hContext,
		LPCSTR szReader,
		DWORD dwShareMode,
		DWORD dwPreferredProtocols,
		LPSCARDHANDLE phCard,
		LPDWORD pdwActiveProtocol)
#endif
{  LONG stat= SCARD_S_SUCCESS;
   int nb=-1,err=0;
   
   *phCard = 0;

if (fdebug)
Printf("SCardConnectA\n");

   //nb = CheckGrid((char*)szReader);//>=1
   nb= GetGridSc((char*)szReader);
   if (nb <= 0) return -1;
   nb= my_type[nb-1];

   if (nb == 2)
   { 
    nb= GetGridSc((char*)szReader); // >=1
    if (nb <= 0) 
	 return -1;
     err= ConnectGridSc2(nb,(char*)szReader);
	 if (err <= 0) return -1;
     
     *phCard = (SCARDHANDLE)(2048+nb-1);
     *pdwActiveProtocol=thisptcol; 
    }

   else if (nb >0) // 1
   { nb= GetGridSc((char*)szReader);
     if (nb <= 0) 
		 return -1;
	 err= ConnectGridSc(nb,(char*)szReader);
	 if (err< 0) 
		 return -1;

     *phCard = (SCARDHANDLE)(1024+nb-1)   ;
     *pdwActiveProtocol=thisptcol;
   }

   else
	   stat= -1; 
 
return(stat);
}

extern int tobyte(wchar_t * szIn, char *buf);


WINSCARD_API LONG WIN_API
SCardConnectW(
    IN      SCARDCONTEXT hContext,
    IN      LPCWSTR szReader,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    OUT     LPSCARDHANDLE phCard,
    OUT     LPDWORD pdwActiveProtocol)

{  LONG stat= SCARD_S_SUCCESS;
   int nb=-1,err=0;
   char name[512];
   *phCard = 0;

if (fdebug)
Printf("SCardConnectW\n");


   //nb = CheckGridW((wchar_t*)szReader);
   nb= GetGridScW((wchar_t*)szReader);
   if (nb <= 0) return -1;
   nb= my_type[nb-1];

  if (nb == 2)
   { 
     nb= GetGridScW((wchar_t*)szReader);
     if (nb <= 0) 
		 return -1;

     tobyte((wchar_t *)szReader,name);
	 err=ConnectGridSc2(nb,name);
     if (err <= 0) return -1;
     
     *phCard = (SCARDHANDLE)(2048+nb-1)   ;
     *pdwActiveProtocol=thisptcol;//SCARD_PROTOCOL_T0 ;
      inuse[nb]=1;
	  return stat;
   }




   if (nb >0)
   { nb= GetGridScW((wchar_t*)szReader);
     if (nb <= 0) return -1;
	 
     err= ConnectGridScW(nb,(wchar_t *)szReader);
	 if (err<=0) 
		 return -1;

     *phCard = (SCARDHANDLE)(1024+nb-1)   ;
     *pdwActiveProtocol=thisptcol;
   }

   else
	   stat= -1;
      
return(stat);
}


WINSCARD_API LONG WIN_API
SCardReconnect(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwShareMode,
    IN      DWORD dwPreferredProtocols,
    IN      DWORD dwInitialization,
    OUT     LPDWORD pdwActiveProtocol)
{ LONG stat = SCARD_S_SUCCESS ;
  int nb=-1;

if (fdebug)
Printf("SCardREConnect\n");


  nb= isGridSc2(&hCard);
  if (nb >0)
  { 
	*pdwActiveProtocol=thisptcol;
    return stat;
  }
  
  nb= isGridSc(&hCard);
  if (nb <=0)  stat= -1;
  else *pdwActiveProtocol=thisptcol;
  //SCardReconnect(hCard,dwShareMode,dwPreferredProtocols,dwInitialization,pdwActiveProtocol);

return stat ;
}


WINSCARD_API LONG WIN_API
SCardDisconnect(
    IN      SCARDHANDLE hCard,
    IN      DWORD dwDisposition)
{ 
LONG stat=SCARD_S_SUCCESS;
int nb;

if (fdebug)
Printf("ScardDisconnect\n");


nb= isGridSc2(&hCard);
if (nb >0)
{ DeconnectGridSc2(nb);
  return stat;
}

nb= isGridSc(&hCard);

if ( nb <= 0 )
stat= -1; 

else
DeconnectGridSc(nb);

return stat;
}

static char atr[18]  = {(char)0x3B,(char)0x07,(char)'C',(char)'O',(char)'M',(char)'X',(char)'0', (char)'0',(char)'0',(char)0};
static char atr2[18] = {(char)0x3B,(char)0x07,(char)'R',(char)'A',(char)'C',(char)'S',(char)'0', (char)'0',(char)'0',(char)0};

#ifdef WIN32
WINSCARD_API LONG WIN_API
SCardState(
    IN SCARDHANDLE hCard,
    OUT LPDWORD pdwState,
    OUT LPDWORD pdwProtocol,
    OUT LPBYTE pbAtr,
    OUT LPDWORD pcbAtrLen)
{
	LONG stat = -1;
	int nb;
	char *sn;

    if (fdebug)
    Printf("ScardState\n");
    
	*pdwState  = SCARD_ABSENT ;
 	nb= isGridSc2(&hCard)     ;
	if (nb > 0)
	{ 	
  	if (isinuse(nb)!=1 )          
	{ *pdwState  = SCARD_ABSENT    ;
	   stat=-1;
	   return stat ;
	}
    sprintf(&atr2[6],"%03d",nb);
	*pcbAtrLen=9;

    *pdwState  = SCARD_STATE_PRESENT ; 
	 stat      = SCARD_S_SUCCESS     ;
     *pdwProtocol =  thisptcol       ;
	  memmove(pbAtr,atr2,(int)*pcbAtrLen);
	  return stat;
	}

	nb= isGridSc(&hCard);
    if (nb <= 0)
    stat = -1;
	
	else
	{ 
	sn= GetKey(my_seid[nb-1]) ;
    sprintf(&atr[6],"%03d",nb);
	*pcbAtrLen=9; 
	memmove(pbAtr,atr,*pcbAtrLen);

	if (sn == NULL);
	else if (strlen(sn) > 15);
   	else
    { *pcbAtrLen=2+(int)strlen(sn); 
       pbAtr[0]= 0x3B;
	   pbAtr[1]= (BYTE)(0xFF  & strlen(sn));
       memmove(pbAtr+2,sn,(int)strlen(sn));
	}

    if (isinuse(nb)==1)
	{ *pdwState  = SCARD_STATE_PRESENT ; 
	   stat      = SCARD_S_SUCCESS ;
      *pdwProtocol =  thisptcol   ;
	}

	else           
	{ *pdwState  = SCARD_ABSENT    ;
	  stat=-1;
	}
           
	}


return stat ;
}
#endif

/*
extern WINSCARDAPI LONG WINAPI
SCardGetAttrib(
    IN SCARDHANDLE hCard,
    IN DWORD dwAttrId,
    OUT LPBYTE pbAttr,
    IN OUT LPDWORD pcbAttrLen);
	*/


WINSCARD_API LONG WIN_API
SCardGetAttrib(
    IN SCARDHANDLE hCard,
    IN DWORD dwAttrId,
    OUT LPBYTE pbAttr,
    IN OUT LPDWORD pcbAttrLen)
{
LONG stat= -1;

if (fdebug)
Printf("SCardGetAttrib\n");
    
return stat  ;

}

#ifdef WIN32
WINSCARD_API LONG WIN_API SCardStatusA(
  SCARDHANDLE hCard,
  LPSTR       mszReaderNames,
  LPDWORD     pcchReaderLen,
  LPDWORD     pdwState,
  LPDWORD     pdwProtocol,
  LPBYTE      pbAtr,
  LPDWORD     pcbAtrLen
)
#else
PCSC_API LONG SCardStatus(SCARDHANDLE hCard,
		LPSTR mszReaderNames,
		LPDWORD pcchReaderLen,
		LPDWORD pdwState,
		LPDWORD pdwProtocol,
		LPBYTE pbAtr,
		LPDWORD pcbAtrLen)
#endif

{ 

	LONG stat = -1;
	int nb;
	char *sn;

if (fdebug)
Printf("SCardStatusA\n");
    

	*pdwState  = SCARD_ABSENT ;
    nb= isGridSc2(&hCard);
    
	if (nb >0)
	{
   
	if (inuse[nb] != 1)
	{  *pdwState  = SCARD_ABSENT;
	    stat=-1;
		return stat;
	}
          
  	  sprintf(&atr2[6],"%03d",nb);

      *pdwState  = SCARD_STATE_PRESENT ; 
	   stat      = SCARD_S_SUCCESS     ;
      *pdwProtocol =  thisptcol        ;
	  *pcbAtrLen   = 9 ;
	   memmove(pbAtr,atr2,(int)*pcbAtrLen);
       
	  sprintf(mszReaderNames,"%s",my_seid[nb-1])        ;
      *pcchReaderLen = (DWORD)strlen(my_seid[nb-1]) + 1 ;
	  return stat;
	}


	nb= isGridSc(&hCard);

    if (nb <= 0)
    stat = -1;
	
	else
	{ 
	sn= GetKey(my_seid[nb-1]);
    sprintf(&atr[6],"%03d",nb);
	*pcbAtrLen=9; 
    memmove(pbAtr,atr,(int)*pcbAtrLen);
	
	if (sn == NULL);
	else if (strlen(sn) > 15);
   	else
    { *pcbAtrLen= 2+(int)strlen(sn);
       pbAtr[0]= 0x3B;
	   pbAtr[1]= (BYTE)(0xFF  & strlen(sn));
       memmove(pbAtr+2,sn,(int)strlen(sn)) ;
	}


    if (isinuse(nb)==1)
	{ *pdwState  = SCARD_STATE_PRESENT ; 
	   stat      = SCARD_S_SUCCESS ;
      *pdwProtocol =  thisptcol   ;
      
	  sprintf(mszReaderNames,"%s",my_seid[nb-1]) ;
      *pcchReaderLen = (DWORD)strlen(my_seid[nb-1]) + 1 ;
	}

 	else           
	{	
		*pdwState  = SCARD_ABSENT    ;
	    stat=-1;
	}
           


	}



return stat ;



}

// wcslen
#ifdef WIN32
WINSCARD_API LONG WIN_API  SCardStatusW(
  SCARDHANDLE hCard,
  LPWSTR      mszReaderNames,
  LPDWORD     pcchReaderLen,
  LPDWORD     pdwState,
  LPDWORD     pdwProtocol,
  LPBYTE      pbAtr,
  LPDWORD     pcbAtrLen
)
{
LONG stat = -1;
int nb,i,j,ptr=0;//result
char *sn;

if (fdebug)
Printf("SCardStatusW\n");

*pdwState  = SCARD_ABSENT ;

  nb= isGridSc2(&hCard);
    
  if (nb >0)
  {
	if (inuse[nb] != 1)
	{  *pdwState  = SCARD_ABSENT;
	    stat=-1;
		return stat;
	}
       sprintf(&atr2[6],"%03d",nb);
       *pcbAtrLen= 9;

      *pcchReaderLen = 1 + *pcchReaderLen ;
	  *pdwState  = SCARD_STATE_PRESENT ; 
	   stat      = SCARD_S_SUCCESS ;
      *pdwProtocol =  thisptcol    ;
	   memmove(pbAtr,atr2,(int)*pcbAtrLen);

       i=nb-1;
       //result = MultiByteToWideChar(CP_OEMCP, 0, my_seid[i], -1, mszReaderNames+ptr/2 , (int)strlen(my_seid[i]) + 1);
       for(j=0;j<(int)strlen(my_seid[i]);j++)
       *((mszReaderNames+ptr/2)+j) = (wchar_t)(0xFF & my_seid[i][j]);
       *((mszReaderNames+ptr/2)+j)=0;

	   
	   ptr += 2* ((int)strlen(my_seid[i]) + 1); 
       *(mszReaderNames+ptr/2)=0;
       *pcchReaderLen = 1+ ptr/2 ;

	   return stat;
    }



nb= isGridSc(&hCard);

    if (nb <= 0) stat = -1;
	
	else
	{ 
	sn= GetKey(my_seid[nb-1]);
    sprintf(&atr[6],"%03d",nb);
	*pcbAtrLen=9; 
    memmove(pbAtr,atr,(int)*pcbAtrLen);
	
	if (sn == NULL);
	else if (strlen(sn) > 15);
   	else
    {  *pcbAtrLen= 2+(int)strlen(sn);
       pbAtr[0]= 0x3B;
	   pbAtr[1]= (BYTE)(0xFF  & strlen(sn));
       memmove(pbAtr+2,sn,(int)strlen(sn)) ;
	}

    if (isinuse(nb)==1)
	{ *pcchReaderLen = 1 + *pcchReaderLen ;
	  *pdwState  = SCARD_STATE_PRESENT ; 
	   stat      = SCARD_S_SUCCESS ;
      *pdwProtocol =  thisptcol   ;

	  i=nb-1;
       //result = MultiByteToWideChar(CP_OEMCP, 0, my_seid[i], -1, mszReaderNames+ptr/2 , (int)strlen(my_seid[i]) + 1);
       ptr += 2* ((int)strlen(my_seid[i]) + 1); 
       *(mszReaderNames+ptr/2)=0;
       *pcchReaderLen = 1+ ptr/2 ;
	}

	else           
	{	
		*pdwState  = SCARD_ABSENT    ;
	    stat=-1;
	}
           


	}



return stat ;
}
#endif
