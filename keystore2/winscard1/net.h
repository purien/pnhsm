/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

extern int stopTCPIP();
extern int startTCPIP();
extern int server_wait();
extern int close_server();
extern int close_client();
extern int server_init(unsigned short port);
extern int NetSend(char *buf, int size);
extern int NetRecv(char *buf,int max,int timeout);
extern int ConnectServer(char * Server, unsigned short Port);
extern int DeconnectServer(int client);
extern int netrecv(char *buf,int s,int max,int timeout);
extern int netsend(char *buf, int size, int s);