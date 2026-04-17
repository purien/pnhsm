/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

int InitializeGrid();
int SendGridSc(int sc, char* APDU, DWORD APDUlen, char* Response, DWORD* Rlen, int nbCard, int port);
int ConnectGridScW(int sc, wchar_t * szReader);
int ConnectGridSc(int sc, char * szReader) ;
int DeconnectGridSc(int sc);
//int CheckGridW(wchar_t * szReader);
//int CheckGrid(char *    szReader);
int isinuse(int sc);
char * GetKey(char * szReader);
char * GetKeyW(wchar_t * szReader);
