#include "encrypt.h"
#include <openssl/rand.h>
#include <openssl/err.h>
#include <assert.h>
#include "log/log.h"
#include "alloc.h"

void cipher_global_init() {
  OpenSSL_add_all_algorithms();
}

int rand_bytes(unsigned char *buf, int num) {
  return RAND_bytes(buf, num);
}

int cipher_ctx_init(CipherCtx *ctx, const char *cipher_name, 
    const char *passwd) {
  assert(ctx && cipher_name);

  const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
  if (cipher == NULL) {
    LOG_E("cipher not found: %s", cipher_name);
    return -1;
  }

  ctx->key_len = EVP_CIPHER_key_length(cipher);
  ctx->key = lmalloc(ctx->key_len);
  if (!EVP_BytesToKey(cipher, EVP_md5(), NULL, 
        (const unsigned char *)passwd, strlen(passwd), 1, ctx->key, NULL)) {
    LOG_E("EVP_BytesToKey failed");
    free(ctx->key);
    return -1;
  }

  ctx->cipher = cipher;
  ctx->evp_cipher_ctx = NULL;
  return 0;
}

char *stream_encrypt(CipherCtx *ctx, char *buf, INOUT int *len, int inplace) {
  assert(ctx && buf);

  int ilen = *len;

  static int cipher_buf_len = 0;
  static unsigned char *cipher_buf = NULL;
  if (cipher_buf_len < ilen) {
    cipher_buf_len = max(CIPHER_INIT_BUFSIZ, ilen) + EVP_MAX_IV_LENGTH;
    cipher_buf = lrealloc(cipher_buf, cipher_buf_len);
  }

  int iv_len = 0;
  if (ctx->evp_cipher_ctx == NULL) {
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
    iv_len = EVP_CIPHER_iv_length(ctx->cipher);
    unsigned char *iv = NULL;
    if (iv_len > 0) {
      RAND_bytes(cipher_buf, iv_len);
      iv = cipher_buf;
    }

    // set the cipher, the key and the IV on the cipher context
    EVP_CipherInit_ex(ctx->evp_cipher_ctx, ctx->cipher, NULL, NULL, NULL, 1);
    EVP_CIPHER_CTX_set_key_length(ctx->evp_cipher_ctx, ctx->key_len);
    EVP_CipherInit_ex(ctx->evp_cipher_ctx, NULL, NULL, ctx->key, iv, 1);
  }

  int out = 0;
  if (!EVP_CipherUpdate(ctx->evp_cipher_ctx, cipher_buf + iv_len, &out, 
        (unsigned char *)buf, ilen)) {
    LOG_E("EVP_CipherUpdate failed");
    return NULL;
  }
  *len = iv_len + out;

  char *pbuf;
  if (inplace) {
    pbuf = buf;
  } else {
    pbuf = lmalloc(*len);
  }

  memcpy(pbuf, cipher_buf, *len);
  return (char *)pbuf;
}

char *stream_decrypt(CipherCtx *ctx, char *buf, INOUT int *len, int inplace) {
  assert(ctx && buf);

  int ilen = *len;

  static int decipher_buf_len = 0;
  static unsigned char *decipher_buf = NULL;
  if (decipher_buf_len < ilen) {
    decipher_buf_len = max(CIPHER_INIT_BUFSIZ, ilen) + EVP_MAX_IV_LENGTH;
    decipher_buf = lrealloc(decipher_buf, decipher_buf_len);
  }

  int iv_len = 0;
  if (ctx->evp_cipher_ctx == NULL) {
    ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
    unsigned char *iv = NULL;
    iv_len = EVP_CIPHER_iv_length(ctx->cipher);
    if (iv_len > 0) {
      iv = (unsigned char *)buf;
    }

    // set the cipher, the key and the IV on the cipher context
    EVP_CipherInit_ex(ctx->evp_cipher_ctx, ctx->cipher, NULL, NULL, NULL, 0);
    EVP_CIPHER_CTX_set_key_length(ctx->evp_cipher_ctx, ctx->key_len);
    EVP_CipherInit_ex(ctx->evp_cipher_ctx, NULL, NULL, ctx->key, iv, 0);
  }

  int olen = 0;
  if (!EVP_CipherUpdate(ctx->evp_cipher_ctx, decipher_buf, &olen, 
        (unsigned char *)buf + iv_len, ilen - iv_len)) {
    LOG_E("EVP_CipherUpdate failed");
    return NULL;
  }

  char *pbuf;
  if (inplace) {
    pbuf = buf;
  } else {
    pbuf = lmalloc(olen);
  }

  *len = olen;
  memcpy(pbuf, decipher_buf, olen);
  return pbuf;
}

void cipher_ctx_destroy(CipherCtx *ctx) {
  assert(ctx);

  if (ctx->evp_cipher_ctx) {
    EVP_CIPHER_CTX_cleanup(ctx->evp_cipher_ctx);
    EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
  }
  free((void *)ctx->key);
}

#ifdef DEBUG_ENCRYPT

int main(int argc, const char *argv[]) {
  cipher_global_init();

  const char *key = "AAAABBBBAAAABBBB123";
  CipherCtx ctx_e;
  if (cipher_ctx_init(&ctx_e, "aes-256-cfb", key) < 0) {
    fprintf(stderr, "can find aes-256-cfb");
    abort();
  }

  CipherCtx ctx_d;
  if (cipher_ctx_init(&ctx_d, "aes-256-cfb", key) < 0) {
    fprintf(stderr, "can find aes-256-cfb");
    abort();
  }

  char buf[] = "HelloWorld!";
  char buf2[] = "something new";
  char buf3[] = "Hey OpenSSL";

  int len = sizeof(buf);
  printf("before: %d\n", len);
  char *cipher_buf = stream_encrypt(&ctx_e, buf, &len, 0);
  printf("orig: %d\n", len);
  char *orig_buf= stream_decrypt(&ctx_d, cipher_buf, &len, 0);
  printf("declen: %d\n", len);
  printf("dec: %s\n", orig_buf);

  len = sizeof(buf2);
  printf("before: %d\n", len);
  cipher_buf = stream_encrypt(&ctx_e, buf2, &len, 0);
  printf("orig: %d\n", len);
  orig_buf= stream_decrypt(&ctx_d, cipher_buf, &len, 0);
  printf("declen: %d\n", len);
  printf("dec: %s\n", orig_buf);

  len = sizeof(buf3);
  printf("before: %d\n", len);
  cipher_buf = stream_encrypt(&ctx_e, buf3, &len, 0);
  printf("orig: %d\n", len);
  orig_buf= stream_decrypt(&ctx_d, cipher_buf, &len, 0);
  printf("declen: %d\n", len);
  printf("dec: %s\n", orig_buf);

  char *str = strdup("this is a long string!!!");
  int slen = strlen(str) + 1;  // including terminating null
  str = stream_encrypt(&ctx_e, str, &slen, 1);
  str = stream_decrypt(&ctx_d, str, &slen, 1);
  printf("dec: %s\n", str);
  free(str);

  cipher_ctx_destroy(&ctx_e);
  cipher_ctx_destroy(&ctx_d);
  return 0;
}

#endif
