/* 
 * Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include "param.h"
#include "sim.h"
#include "util.h"

int mybaud=19200;
int comport=8;
char serialport[512]= "/dev/ttyACM0";// "/dev/ttyUSB0";
static int fd=-1 ;
int verbose=1    ;

extern int fmono;
#define Printf printf
#define AMSGSIZE 10000
static char msgbuffer[AMSGSIZE];
#define Printf printf
#define ASIZE 16
#define MYTIMEOUT     6000
#define TIMEOUT_RESET 1000
int RESETWAITTIME=1000;
// #define X_MODE
// #define SERIALPORTDEBUG 

static int SerialTxError=0,SerialRxError=0;
static display_at=1;

//https://stackoverflow.com/questions/25996171/linux-blocking-vs-non-blocking-serial-read
//https://stackoverflow.com/questions/57152937/canonical-mode-linux-serial-port/57155531#57155531

#ifndef WIN32
#include <stdio.h>   
#include <unistd.h>  
#include <fcntl.h>
#include <errno.h>  
#include <termios.h> 
#include <string.h> 
#include <sys/ioctl.h>
#include <stdint.h>
#include <time.h>
#include <sys/timeb.h>

// arduino-serial-lib -- simple library for reading/writing serial ports
// 2006-2013, Tod E. Kurt, http://todbot.com/blog/



int serialport_init(const char* serialport, int baud)
{
    struct termios toptions;
        
    //fd = open(serialport, O_RDWR | O_NOCTTY | O_NDELAY);
    fd = open(serialport, O_RDWR | O_NONBLOCK );
    
    if (fd == -1)  
    {
        perror("serialport_init: Unable to open port ");
        return -1;
    }

    // init=> DTR=Ov RTS=0v

 
    if (tcgetattr(fd, &toptions) < 0) {
        printf("serialport_init: Couldn't get term attributes");
        return -1;
    }
    speed_t brate = baud; // let you override switch below if needed
    switch(baud) {
    case 4800:   brate=B4800;   break;
    case 9600:   brate=B9600;   break;
#ifdef B14400
    case 14400:  brate=B14400;  break;
#endif
    case 19200:  brate=B19200;  break;
#ifdef B28800
    case 28800:  brate=B28800;  break;
#endif
    case 38400:  brate=B38400;  break;
    case 57600:  brate=B57600;  break;
    case 115200: brate=B115200; break;
    }
    cfsetispeed(&toptions, brate);
    cfsetospeed(&toptions, brate);

    // 8N1
    toptions.c_cflag &= ~PARENB;
    toptions.c_cflag &= ~CSTOPB;
    toptions.c_cflag &= ~CSIZE;
    toptions.c_cflag |= CS8;
    // no flow control
    toptions.c_cflag &= ~CRTSCTS;

    //toptions.c_cflag &= ~HUPCL; // disable hang-up-on-close to avoid reset

    toptions.c_cflag |= CREAD | CLOCAL;  // turn on READ & ignore ctrl lines
    toptions.c_iflag &= ~(IXON | IXOFF | IXANY); // turn off s/w flow ctrl

    toptions.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG); // make raw
    toptions.c_oflag &= ~OPOST; // make raw

    toptions.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytes
    toptions.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
    toptions.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed


    // see: http://unixwiz.net/techtips/termios-vmin-vtime.html
    toptions.c_cc[VMIN]  = 0;
    toptions.c_cc[VTIME] = 0;
    //toptions.c_cc[VTIME] = 20;
    
    tcsetattr(fd, TCSANOW, &toptions);
    if( tcsetattr(fd, TCSAFLUSH, &toptions) < 0) {
        printf("init_serialport: Couldn't set term attributes");
        return -1;
   }

/*
  struct termios tty;
  tty.c_cflag &= ~PARENB; // Clear parity bit, disabling parity (most common)
  tty.c_cflag &= ~CSTOPB; // Clear stop field, only one stop bit used in communication (most common)
  tty.c_cflag &= ~CSIZE; // Clear all bits that set the data size
  tty.c_cflag |= CS8; // 8 bits per byte (most common)
  tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control (most common)
  tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)
  tty.c_lflag &= ~ICANON;
  tty.c_lflag &= ~ECHO; // Disable echo
  tty.c_lflag &= ~ECHOE; // Disable erasure
  tty.c_lflag &= ~ECHONL; // Disable new-line echo
  tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
  tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
  tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytes
  tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
  tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
  // tty.c_oflag &= ~OXTABS; // Prevent conversion of tabs to spaces (NOT PRESENT ON LINUX)
  // tty.c_oflag &= ~ONOEOT; // Prevent removal of C-d chars (0x004) in output (NOT PRESENT ON LINUX)
  tty.c_cc[VTIME] = 10;    // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
  tty.c_cc[VMIN] = 0;
  // Set in/out baud rate to be 9600
  cfsetispeed(&tty, B9600);
  cfsetospeed(&tty, B9600);

  // Save tty settings, also checking for error
  if (tcsetattr(serial_port, TCSANOW, &tty) != 0) 
  { printf("Error %i from tcsetattr: %s\n", errno, strerror(errno));
      return 1;
  }
*/



  if (verbose) printf("%s is open baud=%d\n",serialport,baud);
   
  return 0;
}

int serialport_ctl(int pin, int state)
{ int iflags = 0;
  if (pin == 0)
  { iflags = TIOCM_DTR; 
    if (state == 0) ioctl(fd, TIOCMBIC, &iflags);    // turn off DTR=>5V
    else            ioctl(fd, TIOCMBIS, &iflags);    // turn off DTR=>0v
  }
  else
  { iflags = TIOCM_RTS; 
    if (state == 0) ioctl(fd, TIOCMBIC, &iflags);    // turn off RTS=>5v
    else            ioctl(fd, TIOCMBIS, &iflags);    // turn off RTS=>0v
  }

return 0;
}


int serialport_close()
{
    return close( fd );
}


int serialport_writebyte(uint8_t b)
{
    int n = write(fd,&b,1);
    if( n!=1)    return -1;
    return 0;
}


int serialport_write(char* str)
{ int i;
    int len = strlen(str);
    
#ifndef SERIALPORTDEBUG 
   int n = write(fd, str, len);
   if( n!=len ) 
   {
        printf("serialport_write: couldn't write whole string\n");
        return -1;
   }
   return 0;
 #else
    
  for(i=0;i<len;i++)
  { 
#ifdef SERIALPORTDEBUG  
printf("len= %d b= %2.2X\n",len, str[i]  &0xFF); 
#endif

    int n = serialport_writebyte(str[i]);
    if( n!=0)
    { printf("serialport_write: couldn't write whole string\n"); 
      return -1;
    }

  }


    return 0;
#endif
}


int serialport_read_until(char* buf, char until, int buf_max, int timeout)
{
#ifdef SERIALPORTDEBUG
printf("until: %2.2X, timeout=%d\n", 0xFF & until,timeout);
#endif
 
    char b[1];  // read expects an array, so we give it a 1-byte array
    int i=0;
    do { 
        int n = read(fd, b, 1);  // read a char at a time
        
        if( n==-1) return -1;    // couldn't read
        if( n==0 ) {
            usleep( 1 * 1000 );  // wait 1 msec try again
            timeout--;
            if( timeout ==0 ){ 
#ifdef SERIALPORTDEBUG
printf("RXTIMEOUT\n") ;
#endif
return -2;}
            continue;
        }
#ifdef SERIALPORTDEBUG  
    if      (b[0] == (char)0x0D) printf("serialport_read_until: CR\n");
    else if (b[0] == (char)0x0A) printf("serialport_read_until: LF\n");
    else printf("serialport_read_until: i=%d, n= %d b='%c' b= %2.2X \n",i,n,b[0],b[0]&0xFF); // debug
#endif
        buf[i] = b[0]; 
        i++;
        
    }

while( ((char)b[0] != (char)until) && (i < buf_max) && (timeout>0) );

#ifdef SERIALPORTDEBUG
if (timeout <= 0) printf("timeout\n");
else              printf("%2.2X detected\n",0xFF & until);
#endif

buf[i] = 0;  // null terminate the string
return i  ;
}

int serialport_read(char* buf, int nb, int timeout)
{
 
    char b[1];  // read expects an array, so we give it a 1-byte array
    int i=0;
    do { 
        int n = read(fd, b, 1);  // read a char at a time
        if( n==-1) return -1;    // couldn't read
        if( n==0 ) {
            usleep( 1 * 1000 );  // wait 1 msec try again
            timeout--;
            if( timeout ==0 ){ 
#ifdef SERIALPORTDEBUG
printf("RXTIMEOUT\n") ;
#endif
return -2;}
            continue;
        }
#ifdef SERIALPORTDEBUG 
if      (b[0] == (char)0x0D)      printf("serialport_read CR\n");
else if (b[0] == (char)0x0A)      printf("serialport_read LF\n");
else printf("serialport_read: i=%d, n= %d b='%c' b= %2.2X \n",i,n,b[0],b[0]&0xFF); // debug
#endif
        buf[i] = b[0]; 
        i++;

       }

while( (i < nb) && (timeout>0) );

return i  ;
}




int serialport_flush()
{ int err;  
    sleep(2); //required to make flush work, for some reason
    err=tcflush(fd,TCIOFLUSH);
    return err;
}


int TxCmd(char *cmd,int timeout,int add_crlf,int no_resp)
{  char buf1[128] ;
   int len=0,n=0  ;  
   int atimeout=0 ;

   if (!add_crlf) sprintf(buf1,"%s",cmd)    ;
   else           sprintf(buf1,"%s\r\n",cmd);
   
   if (verbose) if (display_at==1) Printf(">%s", buf1); 
   n=serialport_write(buf1);
   if (n<0) return -1;
   
   if (timeout != 0)
   atimeout= timeout;
   else
   atimeout=MYTIMEOUT;
   
   if (no_resp==1)
   return 1;

   //n= ReadBlock3(hcom,msgbuffer,&len);
    len=serialport_read_until(msgbuffer,(char)'\n',((int)sizeof(msgbuffer))-1,atimeout);
   
   if (len <=0)
   return -1;
   
   msgbuffer[len]=0 ;
   if (verbose) printf("<%s",msgbuffer)  ;
   
   return len;

}



int SIM_Reset()
{ 
int status,i,n=5,len=0;
char buf[1]={0};

if (verbose) printf("SIM_Reset %d\n",reset_sim);
 
if (fmono & reset_sim)
{//status = EscapeCommFunction(hcom, CLRDTR);
 //status = EscapeCommFunction(hcom, CLRRTS);
 serialport_ctl(0,0);
 serialport_ctl(1,0);
 usleep(1000);
 //status = EscapeCommFunction(hcom, SETRTS);
 serialport_ctl(1,1);
 usleep(1000);
 //status = EscapeCommFunction(hcom, CLRRTS);
 serialport_ctl(1,0);

 usleep(1000 *RESETWAITTIME);
 serialport_flush();

}
else if (reset_sim)
{
//status = EscapeCommFunction(hcom, CLRDTR);
serialport_ctl(0,0);
usleep(10000);
//status = EscapeCommFunction(hcom, SETDTR);
serialport_ctl(0,1);
usleep(1000*RESETWAITTIME);
//status = EscapeCommFunction(hcom, CLRDTR);
serialport_ctl(0,0);
usleep(1000);
serialport_flush();

}
else // do nothing
{
//serialport_ctl(0,0);
//serialport_ctl(1,0);
usleep(1000*RESETWAITTIME);
serialport_flush()   ;
}


if (myhw == 144)
{ len=TxCmd("syn\r\n",TIMEOUT_RESET,0,0); 
  for(i=0;i<n;i++)
  { 
  if (( len>0) && (strcmp(msgbuffer,"ERROR syn\r\n")==0) ) i=n+1;
  else 
  { //err= ReadBlock3(hcom,msgbuffer,&len,TIMEOUT_RESET);
    len=serialport_read_until(msgbuffer,(char)'\n',((int)sizeof(msgbuffer))-1,TIMEOUT_RESET);
    if (len >0)msgbuffer[len]=0 ;
    if ((len >0) && verbose)
	{ if (msgbuffer[len-1] == '\n') printf("<%s",msgbuffer);
	  else                          printf("<%s\n",msgbuffer);
	}
  }
}
}
else
{
for(i=0;i<n;i++)
{ TxCmd("\r\n",TIMEOUT_RESET,0,0); 
  if ( (strcmp(msgbuffer,"Ready\r\n")==0) || (strcmp(msgbuffer,"ERROR\r\n") ==0)  || (strcmp(msgbuffer,"ERROR No Command!\r\n") ==0) || (strcmp(msgbuffer,"!\r\n") ==0))
  i=n+1;
}
}

if (i == n)
return -1;


return 0;
}



int SIM_init(char *name)
{ int err;
  err=serialport_init(name,mybaud);
  if (err <0) return -1;

   SIM_Reset();
   
   TxCmd("off",0,1,0);
   if (strcmp(msgbuffer,"OK\r\n") != 0)
   return -1;

return 0;
}

int SIM_close(int all)
{ TxCmd("off\r\n",0,0,0);
  if (all)
  serialport_close();
  return 0;
}

int SIM_open(char *pin, char *myaid)
{ char buf[128];
  int k=0;
  char cmyaid[64];

  if (myhw >= 100)
  { if (myhw == 144) sprintf(buf,"%s\r\n","user");
    else sprintf(buf,"user %s\r\n",pin);
    TxCmd(buf,0,0,0);
    if (strcmp(msgbuffer,"OK\r\n") != 0)
    return -1;
	return 0 ;
  }

  sprintf(cmyaid,"00A40400%02d%s",(int)strlen(myaid)/2,myaid);
   
TxCmd("on",0,1,0);
if (strcmp(msgbuffer,"OK\r\n") != 0)
return -1;

sprintf(buf,"A %s",cmyaid);
TxCmd(buf,0,1,0); 

if (strcmp(msgbuffer,"9000\r\n") != 0)
return -1;
sprintf(buf,"A 00200000%02X%02X%02X%02X%02X", 0xFF & strlen(pin),0xFF&pin[0],0xFF&pin[1],0xFF&pin[2],0xFF&pin[3]);
TxCmd(buf,0,1,0); 
if (strcmp(msgbuffer,"9000\r\n") != 0)
return -1;

return 0;
}

#ifndef X_MODE

int SIM_txAPDU(char * s_apdu,int s_asize, char *s_response, int* s_rsize,int f_resp)
{ char apdu[600];
  char response[600];
  int rsize, err;
  int i;

  struct timeb timebuffer1;
  struct timeb timebuffer2;
  int t1,t2,dtm ;

  *s_rsize = 0;

if (verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)s_asize;i++)
  {	   if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
       Printf("%2.2X ",0xff & s_apdu[i]);
  }
  Printf("\n");
}

    strcpy(apdu,"A ");
    for (i=0;i<(int)s_asize;i++)
    sprintf(apdu+2+(2*i),"%2.2X", 0xFF & s_apdu[i]);
    strcat(apdu,"\r\n");

    ftime(&timebuffer1);
    err=TxCmd(apdu,0,0,0); 
    ftime(&timebuffer2);

    if (err <0) return -1;


     t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
     t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
     dtm = (t2-t1);
     if (dtm <0) dtm += 3600000 ;

	 

if (verbose)
{ Printf("Rx: ");
  
  for(i=0;i<rsize;i++)
  {	  if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & s_response[i]);
  }
  Printf(" [%d ms]\n", dtm);
}

    *s_rsize= Ascii2bin(msgbuffer,s_response);
	return 0;
}

#else

int SIM_txAPDU(char * s_apdu,int s_asize, char *s_response, int* s_rsize,int f_resp)
{ char apdu[512];
  char response[512];
  int rsize, err;
  int i;

  struct timeb timebuffer1;
  struct timeb timebuffer2;
  int t1,t2,dtm ;


  *s_rsize = 0;

if (verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)s_asize;i++)
  {	   if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
       Printf("%2.2X ",0xff & s_apdu[i]);
  }
  Printf("\n");
}


    if (f_resp == 1) apdu[0]=(char)'X';
	else apdu[0]=(char)'x';
	
	apdu[1]= 0xFF & (s_asize>>8);
	apdu[2]= 0xFF & s_asize ;
	apdu[3]= s_apdu[0];
    apdu[4]= s_apdu[1];
    apdu[5]= s_apdu[2];
    apdu[6]= s_apdu[3];
    apdu[7]= s_apdu[4];

    memmove(&apdu[8],s_apdu+5,(size_t)(s_asize-5));


    ftime(&timebuffer1);
	//err = (int)SendBlock(hcom,apdu,3+s_asize);
      err = write(fd,apdu,3+s_asize);
     
	if (err != (3 + s_asize)) return -1;

    //err= (int)ReadBlock(hcom,3,response);
    err=serialport_read(response,3,MYTIMEOUT);

	if (err != 3)
		return -1;
    if (response[0] == (char)0xFF)
		return -1;
	rsize = 0xFF00 & (response[1]<<8);
	rsize |= (int)(0xFF & response[2]);

    //err= (int)ReadBlock(hcom,rsize,s_response);
    err=serialport_read(response,rsize,MYTIMEOUT);

    
	 ftime(&timebuffer2);
     t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
     t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
     dtm = (t2-t1);
     if (dtm <0) dtm += 3600000 ;

	if (err != rsize)
		return -1;

    *s_rsize= rsize;

if (verbose)
{ Printf("Rx: ");
  
  for(i=0;i<rsize;i++)
  {	  if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & s_response[i]);
  }
  Printf(" [%d ms]\n", dtm);
}

	return 0;
}

#endif


int SIM_Derive(char * dhe, int len, char *key)
{ char buf[128] ;
  int i,err;

  strcpy(buf,"derive ");
  for(i=0;i<len;i++) sprintf(buf+7+2*i,"%2.2X",0xFF & dhe[i]);
  strcat(buf,"\r\n");
  TxCmd(buf,0,0,0);
  if (strcmp(msgbuffer,"ERROR\r\n") == 0)
  return -1;
  err= Ascii2bin(msgbuffer,key);
  if (err != 32) return -1;
  return 0;
}

int SIM_Binder(char *data, int len, char *key)
{ char buf[128] ;
  int i,err;

  strcpy(buf,"binder ");
  for(i=0;i<len;i++) sprintf(buf+7+2*i,"%2.2X",0xFF & data[i]);
  strcat(buf,"\r\n");
  TxCmd(buf,0,0,0);
  if (strcmp(msgbuffer,"ERROR\r\n") == 0)
  return -1;
  err= Ascii2bin(msgbuffer,key);
  if (err != 32) return -1;
  return 0;
  
}

#else
#include <windows.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <mmsystem.h>
#include <tchar.h>
#include <time.h>
#include <sys/timeb.h>

COMMPROP CommProp;
DCB myDCB;
COMMTIMEOUTS myCTO;
HANDLE hcom=  INVALID_HANDLE_VALUE;
 
HANDLE SetupSerial(LPCTSTR Comm,int BAUDRATE, DCB * myDCB, COMMTIMEOUTS * myCTO, int RxTimeout, int TxTimeout);
DWORD SendBlock(HANDLE handle, LPSTR block, DWORD BytesToWrite);
int TxCmd3(HANDLE hcom,char *cmd, int timeout, int add_lf, int no_resp);
DWORD ReadBlock3( HANDLE handle, LPBYTE block, LPDWORD bytesRead,int timeout);

int SIM_Reset()
{ 
int status,i,n=5;
BOOL ret=0;
int err,len;
 
if (fmono & reset_sim)
{status = EscapeCommFunction(hcom, CLRDTR);
 status = EscapeCommFunction(hcom, CLRRTS);
 Sleep(10);
 status = EscapeCommFunction(hcom, SETRTS);
 Sleep(1);
 status = EscapeCommFunction(hcom, CLRRTS); //RESET
 Sleep(RESETWAITTIME);
 ret=FlushFileBuffers(hcom);
 ret=PurgeComm(hcom,PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
} 
else if (reset_sim)
{ //DTR=RTS=0V
status = EscapeCommFunction(hcom, CLRDTR); //5V
Sleep(10);
status = EscapeCommFunction(hcom, SETDTR);//RESET START HERE //0V
Sleep(RESETWAITTIME);
status = EscapeCommFunction(hcom, CLRDTR); //5V
//Sleep(RESETWAITTIME);
ret=FlushFileBuffers(hcom);
ret=PurgeComm(hcom,PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
}
else
{ //if ( (myhw == 144) || ( (myhw & 0x10) == 0x10) );
  Sleep(RESETWAITTIME);
  ret=FlushFileBuffers(hcom);
  ret=PurgeComm(hcom,PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
}


if (myhw == 144)
{ err=TxCmd3(hcom,"syn\r\n",TIMEOUT_RESET,0,0); 
  for(i=0;i<n;i++)
  { 
  if (( err == 1) && (strcmp(msgbuffer,"ERROR syn\r\n")==0) ) i=n+1;
  else 
  { err= ReadBlock3(hcom,msgbuffer,&len,TIMEOUT_RESET);
    if ((err ==1) && verbose)
	{ if (msgbuffer[len-1] == '\n') printf("<%s",msgbuffer);
	  else                          printf("<%s\n",msgbuffer);
	}
  }
}
}
else
{
for(i=0;i<n;i++)
{ TxCmd3(hcom,"\r\n",TIMEOUT_RESET,0,0); 
  if ( (strcmp(msgbuffer,"Ready\r\n")==0) || (strcmp(msgbuffer,"ERROR\r\n") ==0)  || (strcmp(msgbuffer,"ERROR No Command!\r\n") ==0) || (strcmp(msgbuffer,"!\r\n") ==0))
  i=n+1;
}
}

if (i == n)
return -1;


return 0;
}

#ifndef X_MODE

int SIM_txAPDU(char * s_apdu,int s_asize, char *s_response, int* s_rsize,int f_resp)
{ char apdu[600];
  //char response[600];
  int rsize=0, err;
  int i;

  struct timeb timebuffer1;
  struct timeb timebuffer2;
  int t1,t2,dtm ;

  *s_rsize = 0;

if (verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)s_asize;i++)
  {	   if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
       Printf("%2.2X ",0xff & s_apdu[i]);
  }
  Printf("\n");
}

    strcpy(apdu,"A ");
    for (i=0;i<(int)s_asize;i++)
    sprintf(apdu+2+(2*i),"%2.2X", 0xFF & s_apdu[i]);
    strcat(apdu,"\r\n");

    ftime(&timebuffer1);
    err=TxCmd3(hcom,apdu,0,0,0); 
    ftime(&timebuffer2);

    if (err <0) return -1;


     t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
     t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
     dtm = (t2-t1);
     if (dtm <0) dtm += 3600000 ;

	 

if (verbose)
{ Printf("Rx: ");
  
  for(i=0;i<rsize;i++)
  {	  if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & s_response[i]);
  }
  Printf(" [%d ms]\n", dtm);
}

    *s_rsize= Ascii2bin(msgbuffer,s_response);
	return 0;
}

#else

int SIM_txAPDU(char * s_apdu,int s_asize, char *s_response, int* s_rsize,int f_resp)
{ char apdu[512];
  char response[512];
  int rsize, err;
  int i;

  struct _timeb timebuffer1;
  struct _timeb timebuffer2;
  int t1,t2,dtm ;


  *s_rsize = 0;

if (verbose)
{ Printf("Tx: ");
  for(i=0;i<(int)s_asize;i++)
  {	   if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
       Printf("%2.2X ",0xff & s_apdu[i]);
  }
  Printf("\n");
}


    if (f_resp == 1) apdu[0]=(char)'X';
	else apdu[0]=(char)'x';
	
	apdu[1]= 0xFF & (s_asize>>8);
	apdu[2]= 0xFF & s_asize ;
	apdu[3]= s_apdu[0];
    apdu[4]= s_apdu[1];
    apdu[5]= s_apdu[2];
    apdu[6]= s_apdu[3];
    apdu[7]= s_apdu[4];

    memmove(&apdu[8],s_apdu+5,(size_t)(s_asize-5));


    _ftime(&timebuffer1);
	err = (int)SendBlock(hcom,apdu,3+s_asize);
  
	if (err != (3 + s_asize)) return -1;

    err= (int)ReadBlock(hcom,3,response);
	if (err != 3)
		return -1;
    if (response[0] == (char)0xFF)
		return -1;
	rsize = 0xFF00 & (response[1]<<8);
	rsize |= (int)(0xFF & response[2]);
    err= (int)ReadBlock(hcom,rsize,s_response);
    
	_ftime(&timebuffer2);
     t1 =  (int)(timebuffer1.time % 3600)*1000 +   timebuffer1.millitm   ;
     t2 =  (int)(timebuffer2.time % 3600)*1000 +   timebuffer2.millitm   ;
     dtm = (t2-t1);
     if (dtm <0) dtm += 3600000 ;

	if (err != rsize)
		return -1;

    *s_rsize= rsize;

if (verbose)
{ Printf("Rx: ");
  
  for(i=0;i<rsize;i++)
  {	  if ( (i!=0) && (i%ASIZE == 0) ) Printf("\n    ");
      Printf("%2.2X ",0xff & s_response[i]);
  }
  Printf(" [%d ms]\n", dtm);
}

	return 0;
}

#endif

int SIM_init(int comport)
{ char portname[128];
  //BOOL ret;

   if (comport <= 9)
   strcpy(portname,"COM");
   else
   strcpy(portname,"\\\\.\\COM");
   sprintf(portname+strlen(portname),"%d",comport);
 
   hcom= SetupSerial(portname,mybaud,&myDCB,&myCTO,1,0);
   
  /*
  if ( (myhw & 0x10) == 0x10)
  { Sleep(RESETWAITTIME);
    ret=FlushFileBuffers(hcom);
    ret=PurgeComm(hcom,PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);
  }
  */

   SIM_Reset();

   TxCmd3(hcom,"off\r\n",0,0,0);
   if (strcmp(msgbuffer,"OK\r\n") != 0)
   return -1;

   return 0;
}

int SIM_Derive(char * dhe, int len, char *key)
{ char buf[128] ;
  int i,err;

  strcpy(buf,"derive ");
  for(i=0;i<len;i++) sprintf(buf+7+2*i,"%2.2X",0xFF & dhe[i]);
  strcat(buf,"\r\n");
  TxCmd3(hcom,buf,0,0,0);
  if (strcmp(msgbuffer,"ERROR\r\n") == 0)
  return -1;
  err= Ascii2bin(msgbuffer,key);
  if (err != 32) return -1;
  return 0;
}

int SIM_Binder(char *data, int len, char *key)
{ char buf[128] ;
  int i,err;

  strcpy(buf,"binder ");
  for(i=0;i<len;i++) sprintf(buf+7+2*i,"%2.2X",0xFF & data[i]);
  strcat(buf,"\r\n");
  TxCmd3(hcom,buf,0,0,0);
  if (strcmp(msgbuffer,"ERROR\r\n") == 0)
  return -1;
  err= Ascii2bin(msgbuffer,key);
  if (err != 32) return -1;
  return 0;
  
}

int SIM_open(char *pin, char *myaid)
{ char buf[128];
  int k=0;
  char cmyaid[64];

  if (myhw >= 100)
  { if (myhw == 144) sprintf(buf,"%s\r\n","user")  ;
    else             sprintf(buf,"user %s\r\n",pin);
    TxCmd3(hcom,buf,0,0,0);
    if (strcmp(msgbuffer,"OK\r\n") != 0)
    return -1;
	return 0 ;
  }

  sprintf(cmyaid,"00A40400%02d%s",(int)strlen(myaid)/2,myaid);
   
TxCmd3(hcom,"on\r\n",0,0,0);
if (strcmp(msgbuffer,"OK\r\n") != 0)
return -1;

sprintf(buf,"A %s",cmyaid);
TxCmd3(hcom,buf,0,1,0); 

if (strcmp(msgbuffer,"9000\r\n") != 0)
return -1;
sprintf(buf,"A 00200000%02X%02X%02X%02X%02X", 0xFF & strlen(pin),0xFF&pin[0],0xFF&pin[1],0xFF&pin[2],0xFF&pin[3]);
TxCmd3(hcom,buf,0,1,0); 
if (strcmp(msgbuffer,"9000\r\n") != 0)
return -1;

return 0;
}

int SIM_close(int all)
{   
	TxCmd3(hcom,"off\r\n",0,0,0);

	if (all)
	{ if (hcom !=  INVALID_HANDLE_VALUE)
	  CloseHandle(hcom);
      hcom=  INVALID_HANDLE_VALUE;
	}
	return 0;
}


int get_ms()
{   
    int t1;
    struct timeb timebuffer1;
    ftime(&timebuffer1);
    t1 =  (int)((timebuffer1.time % 3600)*1000) +   (int)timebuffer1.millitm   ;
    return t1;
}



HANDLE SetupSerial(LPCTSTR Comm,int BAUDRATE, DCB * myDCB, COMMTIMEOUTS * myCTO, int RxTimeout, int TxTimeout)
{
HANDLE handle=NULL ;

//To specify a COM port number greater than 9, use the following syntax: "\\.\COM10". 
//This syntax works for all port numbers and hardware that allows COM port numbers to be specified.

handle = CreateFileA(Comm,
						  GENERIC_WRITE |GENERIC_READ, 
						  0, 
						  NULL,
						  OPEN_EXISTING, 
						  FILE_ATTRIBUTE_NORMAL,//FILE_FLAG_OVERLAPPED
						  NULL );


    if(handle == INVALID_HANDLE_VALUE){
     
     Printf("Open Serial Port Error !!! %d\n",GetLastError()); 
	 return INVALID_HANDLE_VALUE ;
     }
	

	if(!SetupComm(handle , AMSGSIZE,AMSGSIZE) ) 	
	{ Printf("SetupComm Serial Port Error !!! %d\n",GetLastError()); 
	  CloseHandle(handle) ; 
	  return INVALID_HANDLE_VALUE ; 
	}
										
memset(myDCB,0,sizeof(DCB)) ;
myDCB->DCBlength=sizeof(DCB);

if (!GetCommState(handle, myDCB)) 
{
Printf("GetCommState Serial Port Error !!! %d\n",GetLastError()); 
CloseHandle(handle) ; 
return INVALID_HANDLE_VALUE ;
}

myDCB->BaudRate= BAUDRATE ;
myDCB->ByteSize=8;
myDCB->StopBits=ONESTOPBIT;
myDCB->Parity=NOPARITY;

if(!SetCommState(handle, myDCB))
{
Printf("SetSerial Serial Port Error !!! %d\n",GetLastError()); 
CloseHandle(handle) ; 
return INVALID_HANDLE_VALUE ;
}

memset(myCTO,0,sizeof(COMMTIMEOUTS));

// https://msdn.microsoft.com/en-us/library/aa909018.aspx
/*

ReadIntervalTimeout
Specifies the maximum acceptable time, in milliseconds, to elapse between the arrival of two characters on the communication line.

In Windows Embedded CE, during a ReadFile operation, the time period begins immediately.

If the interval between the arrivals of two characters exceeds the time amount specified in ReadIntervalTimeout, the ReadFile operation is completed and buffered data is returned.

A value of zero indicates that interval timeouts are not used.

ReadTotalTimeoutMultiplier
Specifies the multiplier, in milliseconds, used to calculate the total timeout period for read operations.

For each read operation, this value is multiplied by the requested number of bytes to be read.

ReadTotalTimeoutConstant
Specifies the constant, in milliseconds, used to calculate the total timeout period for read operations.

For each read operation, this value is added to the product of the ReadTotalTimeoutMultiplier member 
and the requested number of bytes.

A value of zero for the ReadTotalTimeoutMultiplier and ReadTotalTimeoutConstant members 
indicates that total timeouts are not used for read operations.

WriteTotalTimeoutMultiplier
Specifies the multiplier, in milliseconds, used to calculate the total timeout period for write operations.

For each write operation, this value is multiplied by the number of bytes to be written.

WriteTotalTimeoutConstant
Specifies the constant, in milliseconds, used to calculate the total timeout period for write operations.

For each write operation, this value is added to the product of the WriteTotalTimeoutMultiplier member 
and the number of bytes to be written.

A value of zero for the WriteTotalTimeoutMultiplier and WriteTotalTimeoutConstant members indicates 
that total timeouts are not used for write operations.
*/

myCTO->ReadIntervalTimeout=0; // timeout entre 2 caractères reçus 0=not used
myCTO->ReadTotalTimeoutConstant= (DWORD)RxTimeout ; // Rx Timeout
myCTO->ReadTotalTimeoutMultiplier=0;
myCTO->WriteTotalTimeoutConstant= (DWORD)TxTimeout; // Tx Timeout
myCTO->WriteTotalTimeoutMultiplier=0; 

if(!SetCommTimeouts(handle, myCTO))
{ 
Printf("SetCommTileouts Serial Port Error !!! %d\n",GetLastError()); 
CloseHandle(handle) ; 
return INVALID_HANDLE_VALUE;
} 	 
	
FlushFileBuffers(handle);
PurgeComm(hcom,PURGE_RXABORT | PURGE_RXCLEAR | PURGE_TXABORT | PURGE_TXCLEAR);

return(handle);
};  

//_______________________________________________________________________
// this function return in success the no of bytes being sent to the 
// given handle, and return NULL in case of error

DWORD SendBlock(HANDLE handle, LPSTR block, DWORD BytesToWrite)
{
DWORD		lpBytesWritten=0 ;

		if( !WriteFile( handle, block, BytesToWrite, &lpBytesWritten, NULL) ) 
		{   Printf("Serial Error Write %d !!!\n", GetLastError());
			SerialTxError++; return (0) ; }
			 	
		else return(lpBytesWritten) ;
};




DWORD ReadBlock3( HANDLE handle, LPBYTE block, LPDWORD bytesRead,int timeout)
{ DWORD ptr=0    ;
  DWORD nb       ;
  int p=0;
  int t0=0,t1=0;
  
  t0 = get_ms();
 
  *bytesRead=0;

        while(1)
		{
		nb=0;
		if( !ReadFile(handle, block+ptr, 1, &nb, NULL) ) 
		{   if (GetLastError() != ERROR_IO_PENDING) // 997
			{ Printf("Serial Error Read %d !!!\n", GetLastError());
			  SerialRxError++; 
			  return (0) ; 
		    }
		   
		}
		else
		{   if (nb)
		    { (*bytesRead)++;
		       ptr++;
			  if ( (*(block+ptr-1)) == (char)'\r') 
			  {	  p++;
			  }
		      if ( (*(block+ptr-1)) == (char)'\n')
			  {   p++;
				  break;
			  }
		    }
		    else
			{	t1= get_ms();
		        if ((t1-t0)>timeout)
					break;
		    }
			
		}
		}

  
     	if (nb == 0)
		{ if (verbose == 1)
		  {  Printf("RxTimeout %d ms\n",t1-t0);
		  }
		  return 100 ;
		}
        
		*(block+ptr)=0;

		return(1) ;
}


int TxCmd3(HANDLE hcom,char *cmd, int timeout, int add_crlf, int no_resp)
{  char buf1[1024] ;
   int len=0,n,atimeout=0;

   if (!add_crlf) sprintf(buf1,"%s",cmd);
   else           sprintf(buf1,"%s\r\n",cmd);
   
   if (verbose) if (display_at==1) Printf(">%s", buf1); 
   n= SendBlock(hcom,buf1,(DWORD)strlen(buf1));
   
   if (timeout == 0)
   atimeout= MYTIMEOUT;
   else
   atimeout= timeout;

   if (no_resp==1)
	   return 1;

   n= ReadBlock3(hcom,msgbuffer,&len,atimeout);
   
   if (n==0)
	   return n;
   
   msgbuffer[len]=0 ;
   if (verbose) 
   { if (msgbuffer[len-1]  == '\n')printf("<%s",msgbuffer)    ;
     else                          printf("<%s\n",msgbuffer)  ;
   }
	   
   return n;

}

#endif

/*
#ifdef WIN32
int SIM_init(int comport){return -1};
#else
int SIM_init(char *name){return -1};
#endif
int SIM_close(int all){return -1;}
int SIM_open(char *pin, char *aid){return -1;}
int SIM_txAPDU(char * apdu,int asize, char * response, int* rsize, int fresp)
{return -1;}
int SIM_Derive(char * dhe, int len, char *key){return -1;}
int SIM_Binder(char *data, int len, char *key){return -1;}
*/
