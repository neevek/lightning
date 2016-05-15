#ifndef ENCRYPT_H_
#define ENCRYPT_H_
#include <openssl/evp.h>

typedef enum {
  AES_256_CBC,
} CipherAlgorithm;

typedef struct {
  EVP_CIPHER_CTX *evp_cipher_ctx; 
  const EVP_CIPHER *cipher;
  unsigned char *key;
  int key_len;
  unsigned char *iv;
  int8_t iv_len;
} CipherCtx;

void cipher_global_init();
int rand_bytes(unsigned char *buf, int num);
int cipher_ctx_init(CipherCtx *ctx, const char *cipher_name, const char *passwd);
void cipher_ctx_destroy(CipherCtx *ctx);
char *encrypt(CipherCtx *ctx, char *buf, int len, int *enc_len);
char *decrypt(CipherCtx *ctx, char *buf, int len, int *dec_len);

#endif /* end of include guard: ENCRYPT_H_ */
