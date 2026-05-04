#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> 
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/ripemd.h>
#include <openssl/opensslv.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "common2.h"

#define Printf printf
extern int fdebug; 

//#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CIPHER_LIST  "AES128-GCM-SHA256"

#define CADIR NULL
char CAFILE[128]     = {"root.pem"};
char CERTFILE[128]   = {"client.pem"};
char KEYFILE[128]    = {"clientkey.pem"};
char PASSWORD[128]   = {"pascal"};
   
/* err=init_OpenSSL();
   seed_prng();
   MutexSetup(NB_MUTEX);
   ...
   Mutex_cleanup(NB_MUTEX);

*/


static int pem_passwd_cb(char *buf,int size,int rwflag, void *passwd)
{ strcpy(buf,PASSWORD);
  return((int)strlen(buf));
}

SSL_CTX *setup_client_ctx(void)
{
    SSL_CTX *ctx;
	int err=0;

    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    //SSL_load_error_strings();      /* load all error messages */

    ctx = SSL_CTX_new(TLSv1_2_client_method());

    SSL_CTX_set_default_passwd_cb(ctx,pem_passwd_cb);

   if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
   int_error("Error loading CA file and/or directory");

   if (SSL_CTX_set_default_verify_paths(ctx) != 1)
   int_error("Error loading default CA file and/or directory");

   if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
   int_error("Error loading certificate from file");

   if (SSL_CTX_use_PrivateKey_file(ctx, KEYFILE, SSL_FILETYPE_PEM) != 1)
   int_error("Error loading private key from file");

   if(!SSL_CTX_check_private_key(ctx)) {
   int_error("Private key does not match the certificate public keyn");   }


    //SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    //SSL_CTX_set_verify_depth(ctx, 4);

    err =SSL_CTX_set_options(ctx,SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TICKET | SSL_OP_TLS_ROLLBACK_BUG);
 

    if (SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
    int_error("Error setting cipher list (no valid ciphers)");

	return ctx;
}

int do_client_loop(SSL *ssl)
{
    int  err, nwritten;
    char buf[256]= "BEGIN\r\nEND\r\n";
	int len;

	len=(int)strlen(buf);
 
    for (;;)
    {
       
        for (nwritten = 0;  nwritten < len;  nwritten += err)
        {
            err = SSL_write(ssl, buf + nwritten, len - nwritten);
            if (err <= 0)
                return 0;
        }


       err = SSL_read(ssl, buf,(int)sizeof(buf)) ;
            if (err <= 0)
                return 0;
       buf[err]=0;
	   printf("%s",buf);
       break;

    }
	
    return 1;
}

 int testclient(char *uri);


THREAD_CC client_thread(void *arg)
{ testclient((char*)arg);
  return 0;
}

//"127.0.0.1:443"
int testclient(char *uri)
{
    BIO     *conn;
    SSL     *ssl;
    SSL_CTX *ctx;
    FILE *f=NULL;
    SSL_SESSION * session=NULL;
	int err=0;

    init_OpenSSL();
    seed_prng()   ;
    ctx = setup_client_ctx();

	conn = BIO_new_connect(uri);

    if (!conn)
        int_error("Error creating connection BIO");
 
    if (BIO_do_connect(conn) <= 0)
        int_error("Error connecting to remote machine");
 
    ssl = SSL_new(ctx);
    SSL_set_bio(ssl, conn, conn);

   	//SSL_set_session(ssl,NULL);


    if (SSL_connect(ssl) <= 0)
	{ printf("Error connecting SSL object");
	  return -1;
	}

	Printf("SSL Connection opened\n");

	if (do_client_loop(ssl))
        SSL_shutdown(ssl);
    else
        SSL_clear(ssl);
    if (fdebug) Printf("SSL Connection closed\n");
 
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}

