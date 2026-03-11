/* 
 * Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#ifdef WIN32
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#endif

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/timeb.h>
#include <time.h>
#include <string.h>


#ifndef WIN32
   #include <sys/types.h>
   #include <sys/socket.h>
   #include <sys/poll.h>
   #include <sys/ioctl.h>
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <netdb.h>
   #define INVALID_SOCKET -1
   #define SOCKET int
#else
#include <winsock.h>
#endif

#include "net.h"

#define Printf printf
char   default_IP[]= "127.0.0.1";

SOCKET myserver =INVALID_SOCKET;
SOCKET myclient =INVALID_SOCKET;

int NetRecv(char *buf,int max,int atimeout)
{ int err,len,pt=0,fdata=0,more=1,state=0,remain=5;
  char ptcol,vhigh,vlow;
  struct timeval timeout;
  int s=(int)myclient   ;

  #ifndef WIN32
  struct pollfd fds[1];
  #else
  fd_set a_fd_set;
  #endif

  if (myclient == INVALID_SOCKET) return(-1);
  
  if (atimeout == 0) atimeout=5;

  timeout.tv_sec  = atimeout  ; // seconds
  timeout.tv_usec = 0  ;


  while(more)
  { fdata=0;

 	 #ifndef WIN32
	 memset(fds, 0 , sizeof(fds));
     fds[0].fd = s ;
	 fds[0].events = POLLIN;
 	 #else
	 FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;
	 #endif


     #ifndef WIN32
	 err = poll(fds,1, 1000*(int)timeout.tv_sec);
	 if (err< 0)  ;  //return -1;
	 if (err == 0);  // timeout
	 else if(fds[0].revents != POLLIN) ; //return -1;
	 else  if (fds[0].fd == s) fdata=1 ; //data received
	 else ;// return -1;
	 #else
     FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;
     err = select (1+s,&a_fd_set,NULL,NULL,&timeout);
     if (err < 0) ; //return -1;
     if (FD_ISSET(s, &a_fd_set)) fdata=1; //data received
     else ; //timeout
     #endif

	 

	 if (fdata == 0) //timeout or error
	 {  
     #ifdef WIN32
	 FD_ZERO(&a_fd_set) ;
     #endif
	 DeconnectServer(s); 
	 return -1 ;
     }

     err = recv(s,buf+pt,remain,0);
     if (err <= 0) { DeconnectServer(s); return -1 ; }

	 if (state ==0)
	 {  pt+= err    ;
	    remain-= err;
	    if (remain ==0)
		{
		ptcol= buf[0];
        vhigh= buf[1];
        vlow=  buf[2];
        len  =  (buf[3]<<8) & 0xFF00;
        len |=   buf[4] & 0xFF;
		state=1;
		remain=len;
		}
	  }
	 
	 else
	 { pt+= err    ;
	   remain-= err;
	   if (remain == 0)
       break;
	 }

  }

  #ifdef WIN32
  FD_ZERO(&a_fd_set) ;
  #endif

 return 5+len;
}

int NetRecv2(char *buf,int max,int timeout)
{ int err,len,pt=0;
  char ptcol,vhigh,vlow;

  if (myclient == INVALID_SOCKET) return(-1);

  err = recv(myclient,buf,5,0);

  if (err <= 0) { close_client(); return -1 ; }
 
  ptcol= buf[pt++];
  vhigh= buf[pt++];
  vlow=  buf[pt++];
  
  len  =  (buf[pt++]<<8) & 0xFF00;
  len |=   buf[pt++] & 0xFF;

   err = recv(myclient,buf+5,len,0);

  if (err <= 0) { close_client(); return -1 ; }
  
  return 5+len;



}

int NetSend(char *buf, int size)
{ int err,offset=0,more=1;
 
  if (myclient == INVALID_SOCKET) return -1 ;
  
  while (more)
  { err = send(myclient,((char *)buf)+offset,size-offset,0) ;
  if (err <= 0) { close_client();return -1 ;}
	offset+= err ;
	if (offset == size) more=0;
  }
  
  return 0 ;
}



int server_init(unsigned short port)
{  int err   ;
   struct sockaddr_in sin     ;          
   
       
 myserver = socket(PF_INET,SOCK_STREAM,0); 
 sin.sin_family = AF_INET   ;  
 sin.sin_port = htons(port) ;  
 sin.sin_addr.s_addr =  inet_addr("127.0.0.1") ;  
 
 err = bind (myserver, (struct sockaddr*)&sin, sizeof (sin));
 if (err != 0)  {myserver=INVALID_SOCKET ; 
                 Printf("Error, Server daemon !!!\n");
                 return 0;
                 }

 err = listen(myserver,5);
 
 if (err != 0)
	 return -1;
  
 return 0;
 }

int close_client()
{
  if (myclient == INVALID_SOCKET) 
	  return -1;

  shutdown(myclient,2)   ;
#ifdef WIN32
closesocket(myclient)  ;
#else
close(myclient);
#endif

  myclient = INVALID_SOCKET ;
  return 0;
}

int close_server()
{
  if (myserver == INVALID_SOCKET) 
	  return -1;
#ifdef WIN32
  closesocket(myserver);
#else
  close(myserver);
#endif
  myserver= INVALID_SOCKET ; 
  return 0;
}

int server_wait()
{  int len;
   char *s=NULL;
   struct sockaddr_in csin     ;          
    
   if (myserver == INVALID_SOCKET) 
   return -1;
  
   myclient = INVALID_SOCKET ;

   while(myclient == INVALID_SOCKET)
   {
   Printf("\nServer TLS13 Ready...\n");
   len       =  sizeof (csin) ;
   myclient  =  accept (myserver,(struct sockaddr*)&csin, &len); 

   if (myclient != INVALID_SOCKET) 
	   break;
   }
 
   s = inet_ntoa(csin.sin_addr);
   printf("Connexion from: %s\n", s);

 return 0;

}

int startTCPIP()
{
#ifdef WIN32
 int err; 
 WSADATA wsaData;
 WORD wVersionRequested = MAKEWORD(1,1) ;
 
 err = WSAStartup(wVersionRequested,&wsaData );
 if ( err != 0 ) return(-1);
 #endif

 
 return(0);

}   

int stopTCPIP()
{
#ifdef WIN32
 WSACleanup(); 
#endif
 return 0;

}

int SetConnectAddress(struct sockaddr_in *sin,unsigned short port,char *host)
{ 
 struct hostent *phe ;
	 
 sin->sin_family      = AF_INET         ;
 sin->sin_port        = htons(port)     ;
 sin->sin_addr.s_addr = inet_addr (host);
 
 if (sin->sin_addr.s_addr == INADDR_NONE)
 {
	  phe = gethostbyname (host);
	  if (phe == NULL) return(0);
      
      else     
      memcpy(&(sin->sin_addr),phe->h_addr,4);
	  
	  if (sin->sin_addr.s_addr == INADDR_NONE)
	  return(0); 
	  
 }


return(1);
 
}

int ConnectServer(char * Server, unsigned short Port)
{
	struct sockaddr_in sin,csin   ; 
	int  err, namelen;
	int client;  
	
	
    client = (int) socket (AF_INET,SOCK_STREAM,0); 
 
	csin.sin_family = AF_INET   ;  
    csin.sin_port   = 0 ;  
    csin.sin_addr.s_addr =  INADDR_ANY;  
 
    err = bind (client,(struct sockaddr *) &csin, sizeof (csin));	
	if (err != 0)
	{ printf("Socket Bind Error !!!\n");
	  return 0;
	}

    namelen = sizeof(csin);
    err = getsockname(client, (struct sockaddr *) &csin, &namelen);
 
    sin.sin_family = AF_INET   ;  
    sin.sin_port = htons(Port) ;  
    sin.sin_addr.s_addr =  inet_addr(default_IP) ;


   if (!SetConnectAddress(&sin,(unsigned short)Port,Server))
   {
	   printf("DNS error for Server...\n");
	   return -1;
   }

    err= connect(client,(struct sockaddr *) &sin,sizeof(struct sockaddr) );

	if (err != 0)
	{ printf("Connection to Server Failed !!!\n");
	  return 0;
	}

   // printf("Connected\n");
    
    return client;

}


int DeconnectServer(int client)
{ 
  shutdown(client,2) ;
  #ifndef WIN32
  close(client);
  #else
  closesocket(client);
  #endif

  return (0);

}
  
int __netrecv(char *buf,int s, int max, int atimeout)
{ int err,len,pt=0,fdata=0,more=1,state=0,remain=5;
  char ptcol,vhigh,vlow;
  struct timeval timeout;
  fd_set a_fd_set;

  if (atimeout == 0) atimeout=5;

  timeout.tv_sec  = atimeout  ; // seconds
  timeout.tv_usec = 0  ;

  while(more)
  { fdata=0;

     FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;

     err = select (1+s,&a_fd_set,NULL,NULL,&timeout);
     if (err < 0) ; //return -1;
     if (FD_ISSET(s, &a_fd_set)) fdata=1; //data received
     else ; //timeout

	 if (fdata == 0) //timeout or error
	 {  
     FD_ZERO(&a_fd_set) ;
     DeconnectServer(s); 
	 return -1 ;
     }

     err = recv(s,buf+pt,remain,0);
     if (err <= 0) { DeconnectServer(s); return -1 ; }

	 if (state ==0)
	 {  pt+= err    ;
	    remain-= err;
	    if (remain ==0)
		{
		ptcol= buf[0];
        vhigh= buf[1];
        vlow=  buf[2];
        len  =  (buf[3]<<8) & 0xFF00;
        len |=   buf[4] & 0xFF;
		state=1;
		remain=len;
		}
	  }
	 
	 else
	 { pt+= err    ;
	   remain-= err;
	   if (remain == 0)
       break;
	 }

  }

  FD_ZERO(&a_fd_set) ;
  

 return 5+len;

}


int ___netrecv(char *buf,int s, int max, int atimeout)
{ int err,len,pt=0,fdata=0,more=1,state=0,remain=5;
  char ptcol,vhigh,vlow;
  struct timeval timeout;
  fd_set a_fd_set;

  #ifndef WIN32
  struct pollfd fds[1];
  #endif
  
  if (atimeout == 0) atimeout=5;

  timeout.tv_sec  = atimeout  ; // seconds
  timeout.tv_usec = 0  ;


  while(more)
  { fdata=0;

     FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;

     err = select (1+s,&a_fd_set,NULL,NULL,&timeout);
     if (err < 0) ; //return -1;
     if (FD_ISSET(s, &a_fd_set)) fdata=1; //data received
     else ; //timeout

	 #ifndef WIN32
	 memset(fds, 0 , sizeof(fds));
     fds[0].fd = s ;
	 fds[0].events = POLLIN;
 	 #else
	 FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;
	 #endif


     #ifndef WIN32
	 err = poll(fds,1, 1000*(int)timeout.tv_sec);
	 if (err< 0)  ;  //return -1;
	 if (err == 0);  // timeout
	 else if(fds[0].revents != POLLIN) ; //return -1;
	 else  if (fds[0].fd == s) fdata=1 ; //data received
	 else ;// return -1;
	 #else
     err = select (1+s,&a_fd_set,NULL,NULL,&timeout);
     if (err < 0) ; //return -1;
     if (FD_ISSET(s, &a_fd_set)) fdata=1; //data received
     else ; //timeout
     #endif

	 

	 if (fdata == 0) //timeout or error
	 {  
     #ifdef WIN32
	 FD_ZERO(&a_fd_set) ;
     #endif
	 DeconnectServer(s); 
	 return -1 ;
     }

     err = recv(s,buf+pt,remain,0);
     if (err <= 0) { DeconnectServer(s); return -1 ; }

	 if (state ==0)
	 {  pt+= err    ;
	    remain-= err;
	    if (remain ==0)
		{
		ptcol= buf[0];
        vhigh= buf[1];
        vlow=  buf[2];
        len  =  (buf[3]<<8) & 0xFF00;
        len |=   buf[4] & 0xFF;
		state=1;
		remain=len;
		}
	  }
	 
	 else
	 { pt+= err    ;
	   remain-= err;
	   if (remain == 0)
       break;
	 }

  }

  #ifdef WIN32
  FD_ZERO(&a_fd_set) ;
  #endif

 return 5+len;

}



int netrecv(char *buf,int s, int max, int atimeout)
{ int err,len,pt=0,fdata=0,more=1,state=0,remain=5;
  char ptcol,vhigh,vlow;
  struct timeval timeout;
 

  #ifndef WIN32
  struct pollfd fds[1];
  #else
  fd_set a_fd_set;
  #endif
  
  if (atimeout == 0) atimeout=5;

  timeout.tv_sec  = atimeout  ; // seconds
  timeout.tv_usec = 0  ;


  while(more)
  { fdata=0;

 	 #ifndef WIN32
	 memset(fds, 0 , sizeof(fds));
     fds[0].fd = s ;
	 fds[0].events = POLLIN;
 	 #else
	 FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;
	 #endif


     #ifndef WIN32
	 err = poll(fds,1, 1000*(int)timeout.tv_sec);
	 if (err< 0)  ;  //return -1;
	 if (err == 0);  // timeout
	 else if(fds[0].revents != POLLIN) ; //return -1;
	 else  if (fds[0].fd == s) fdata=1 ; //data received
	 else ;// return -1;
	 #else
     FD_ZERO(&a_fd_set)    ;
     FD_SET(s,&a_fd_set)   ;
     err = select (1+s,&a_fd_set,NULL,NULL,&timeout);
     if (err < 0) ; //return -1;
     if (FD_ISSET(s, &a_fd_set)) fdata=1; //data received
     else ; //timeout
     #endif

	 

	 if (fdata == 0) //timeout or error
	 {  
     #ifdef WIN32
	 FD_ZERO(&a_fd_set) ;
     #endif
	 DeconnectServer(s); 
	 return -1 ;
     }

     err = recv(s,buf+pt,remain,0);
     if (err <= 0) { DeconnectServer(s); return -1 ; }

	 if (state ==0)
	 {  pt+= err    ;
	    remain-= err;
	    if (remain ==0)
		{
		ptcol= buf[0];
        vhigh= buf[1];
        vlow=  buf[2];
        len  =  (buf[3]<<8) & 0xFF00;
        len |=   buf[4] & 0xFF;
		state=1;
		remain=len;
		}
	  }
	 
	 else
	 { pt+= err    ;
	   remain-= err;
	   if (remain == 0)
       break;
	 }

  }

  #ifdef WIN32
  FD_ZERO(&a_fd_set) ;
  #endif

 return 5+len;

}

int netsend(char *buf, int size, int s)
{ int err,offset=0,more=1;
 
  while (more)
  { err = send(s,((char *)buf)+offset,size-offset,0) ;
  if (err <= 0) { DeconnectServer(s); return -1 ;}
	offset+= err ;
	if (offset == size) more=0;
  }
  
  return 0 ;
}

