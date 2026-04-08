/* Copyright (C) 2026 Pascal Urien (pascal.urien@gmail.com)
 * All rights reserved.
 */

#include <openssl/evp.h>

int err(int x,char *label)
{ printf("%s\n",label);
  return -1;
}
int ccm_encrypt(unsigned char *plaintext, int text_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *nonce,
                unsigned char *out_p,
                unsigned char *tag)

{
 int nonce_len= 12           ;
 int tag_len=16;
 int size_len = 15 - nonce_len;
 // int aad_len = 5;
 // int text_len= sizeof(plaintext);
int out_len = aad_len + text_len + tag_len;

EVP_CIPHER_CTX *ctx;
int irv;

/* configuration */
ctx = EVP_CIPHER_CTX_new();
if (ctx == NULL)
err(1, "EVP_CIPHER_CTX_new");

if (EVP_EncryptInit(ctx, EVP_aes_128_ccm(), NULL, NULL) != 1)
return err(1, "EVP_EncryptInit(NULL)");

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_L,
    size_len, NULL) <= 0)
return err(1, "EVP_CTRL_CCM_SET_L(%d)", size_len);

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG,
    tag_len, NULL) <= 0)
return err(1, "EVP_CTRL_CCM_SET_TAG(%d)", tag_len);

/* process input data */
if (EVP_EncryptInit(ctx, NULL, key, nonce) != 1)
return(1, "EVP_EncryptInit(key, nonce)");

if (EVP_EncryptUpdate(ctx, NULL, &irv, NULL, text_len) != 1)
err(1, "EVP_EncryptUpdate(len = %d)", text_len);

if (irv != text_len)
errx(1, "text length: want %d, got %d", text_len, irv);

irv = -1;
if (EVP_EncryptUpdate(ctx, NULL, &irv, aad, aad_len) != 1)
return err(1, "EVP_EncryptUpdate(AAD)");

irv = -1;
if (EVP_EncryptUpdate(ctx, out_p, &irv, plaintext, text_len) != 1)
err(1, "EVP_EncryptUpdate(plaintext)");
if (irv != text_len)
{ printf("text_len: want %d, got %d", text_len, irv);
  return -1;
}

/*
 * EVP_EncryptFinal(3) doesn't really do anything for CCM.
 * Call it anyway to stay closer to normal EVP_Encrypt*(3) idioms,
 * to match what the OpenSSL Wiki suggests since 2013, and to ease
 * later migration of the code to a different AEAD algorithm.
 */
irv = -1;
if (EVP_EncryptFinal(ctx, out_p, &irv) != 1)
err(1, "EVP_EncryptFinal");
if (irv != 0)
{ printf("final_len: want 0, got %d", irv);
  return -1;
}
/* check output data */

if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG,
    tag_len, out_p) <= 0)
return err(1, "EVP_CTRL_CCM_GET_TAG");

return 0;
}