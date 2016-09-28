#ifndef ENCRYPT_H_
#define ENCRYPT_H_
#include <openssl/evp.h>

#define INOUT
#define MAX_IV_LEN EVP_MAX_IV_LENGTH
#define CIPHER_INIT_BUFSIZ 8192

#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif

typedef enum {
  AES_256_CBC,
} CipherAlgorithm;

typedef struct {
  EVP_CIPHER_CTX *evp_cipher_ctx; 
  const EVP_CIPHER *cipher;
  unsigned char *key;
  int key_len;
} CipherCtx;

void cipher_global_init();
int rand_bytes(unsigned char *buf, int num);
int cipher_ctx_init(CipherCtx *ctx, const char *cipher_name, const char *passwd);
void cipher_ctx_destroy(CipherCtx *ctx);
char *stream_encrypt(CipherCtx *ctx, char *buf, INOUT int *len, int inplace);
char *stream_decrypt(CipherCtx *ctx, char *buf, INOUT int *len, int inplace);

#endif /* end of include guard: ENCRYPT_H_ */
