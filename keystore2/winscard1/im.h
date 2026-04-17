/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#define IM_RANDOM
extern int fim ;
extern int myhw;
extern int comport;
extern char serialport[512];
extern int init_sim ;
extern int reset_sim;
extern int fmono;
extern int ftrace;
extern int IM_open(char * pin, char *aid);
extern int IM_close();
extern int IM_Finished(char *data,int len, char *key);
extern int IM_Extract_DHE(char * dhe, int len, char *key);
extern int IM_Client_Early_Traffic(char * data, int len, char *key);
extern int IM_Client_Early_Exporter(char * data, int len, char *key);
extern int IM_ECDSA(int index, char * data, int len, char *key);
extern int IM_ECDHE(int index,char *data, int len, char *key);
extern int IM_ECDHE_PubK(int index,char *data, int len, char *key);
extern int IM_Random(int len, char *data);
extern int IM_test();
extern int IM_init(char *aid);
extern int IM_end();
extern int IM_send(char *in,int lenin, char*out, int *lenout,char P1);
extern int IM_GenkeyDH(char *pubkey);
extern int IM_ClearKeyDH();
