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


#include "util.h"

void myPrintf(char *str, char  *vli, int size)
{ int i, v;
  char buf[128],c ;

  if (size <= 0)    return ;
  
  sprintf(buf, "%s ", str);
  printf("%s\n",buf);
  buf[0] = 0;
  for (i = 0; i < size; ++i)
  { c = *(vli+i);
    v = (int)c  ;
    v &= 0xFF;
    sprintf(buf + strlen(buf), "%02X",v);
    if (i % 32 == 31)
    { printf("%s\n",buf);
      buf[0] = 0;
    }
  }

  i--;
  if ((i % 32) != 31)
     printf("%s\n",buf);
}

int isDigit(char c)
{ if (((int)c >= (int)'0') && ((int)c<= (int)'9')) return(1);
  if (((int)c >= (int)'A') && ((int)c<= (int)'F')) return(1);
  if (((int)c >= (int)'a') && ((int)c<= (int)'f')) return(1);
  return(0);
}

int Ascii2bin(char *Data_In,char *data_out)
{  	int deb=-1,fin=-1,i,j=0,nc,iCt=0,v,len;
    char c;	
	char *data_in = NULL;
	int wildcard=0;
	
	len =(int) strlen(Data_In);
    data_in = malloc(1+len)   ;
	if (data_in == NULL) { *data_out=0;return(0);}
	strcpy(data_in,Data_In)   ;

	for(i=0;i<len;i++)
	{ if      ( (deb == -1) && (data_in[i] == (char)'%') )          wildcard=1; 
	  else if ( (deb == -1) && (isDigit(data_in[i])) )             {iCt=1;deb=i;}
      else if ( (deb != -1) && (iCt==1) && (isDigit(data_in[i])) ) {iCt=2;fin=i;}
	  else wildcard=0;

      if (iCt == 2)
	  { c= data_in[fin+1];
	    data_in[deb+1]= data_in[fin];
		data_in[deb+2]= 0;
	    nc = sscanf(&data_in[deb],"%x",&v);
		data_in[fin+1]=c;

		//if (wildcard) 
		//	v = 0xFF & sc_wildcard[(int)(0xFF & v)];
		// else 
		v &= 0xFF;
		
		data_out[j++]= v ;
		wildcard=0;
		deb=fin=-1;iCt=0;
	   }
    }

	free(data_in);

return(j);
}

