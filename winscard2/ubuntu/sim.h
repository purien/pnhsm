/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#ifdef WIN32
extern int SIM_init(int comport);
#else
extern int SIM_init(char *name);
#endif
extern int SIM_close(int all);
extern int SIM_open(char *pin, char *aid);
extern int SIM_txAPDU(char * apdu,int asize, char * response, int* rsize, int fresp);
extern int SIM_Derive(char * dhe, int len, char *key);
extern int SIM_Binder(char *data, int len, char *key);
extern int mybaud;
extern int init_sim ;
extern int reset_sim;
extern int myhw;