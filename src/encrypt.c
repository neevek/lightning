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
        (const unsigned char *)ctx->key, ctx->key_len, 1, ctx->key, NULL)) {
    LOG_E("EVP_BytesToKey failed");
    free(ctx->key);
    return -1;
  }

  ctx->cipher = cipher;
  ctx->evp_cipher_ctx = EVP_CIPHER_CTX_new();
  ctx->iv_len = -1;
  return 0;
}

char *encrypt(CipherCtx *ctx, char *buf, int len, int *cbuf_len) {
  assert(ctx && buf);

  *cbuf_len = 0;
  unsigned char *cipher_buf = NULL;
  if (ctx->iv_len == -1) {
    ctx->iv_len = EVP_CIPHER_iv_length(ctx->cipher);
    if (ctx->iv_len > 0) {
      printf("enc iv_len: %d\n", ctx->iv_len);
      ctx->iv = lmalloc(ctx->iv_len);
      RAND_bytes(ctx->iv, ctx->iv_len);

      cipher_buf = lmalloc(len + ctx->iv_len);
      memcpy(cipher_buf, ctx->iv, ctx->iv_len);
      *cbuf_len += ctx->iv_len;
    }
  }

  // set the cipher, the key and the IV on the cipher context
  EVP_CipherInit_ex(ctx->evp_cipher_ctx, ctx->cipher, NULL, NULL, NULL, 1);
  EVP_CIPHER_CTX_set_key_length(ctx->evp_cipher_ctx, ctx->key_len);
  EVP_CipherInit_ex(ctx->evp_cipher_ctx, NULL, NULL, ctx->key, ctx->iv, 1);

  if (cipher_buf) {
    cipher_buf = lrealloc(cipher_buf, len + ctx->iv_len + 
        EVP_CIPHER_CTX_block_size(ctx->evp_cipher_ctx));
  } else {
    cipher_buf = lmalloc(len + EVP_CIPHER_CTX_block_size(ctx->evp_cipher_ctx));
  }

  int out = 0;
  if (!EVP_CipherUpdate(ctx->evp_cipher_ctx, cipher_buf + *cbuf_len, &out, 
        (unsigned char *)buf, len)) {
    LOG_E("EVP_CipherUpdate failed");
    free(cipher_buf);
    return NULL;
  }
  *cbuf_len += out;

  out = 0;
  if (!EVP_CipherFinal_ex(ctx->evp_cipher_ctx, cipher_buf + *cbuf_len, &out)) {
    LOG_E("EVP_CipherFinal_ex failed");
    free(cipher_buf);
    return NULL;
  }
  *cbuf_len += out;

  return (char *)cipher_buf;
}

char *decrypt(CipherCtx *ctx, char *buf, int len, int *dbuf_len) {
  assert(ctx && buf);

  if (ctx->iv_len == -1) {
    ctx->iv_len = EVP_CIPHER_iv_length(ctx->cipher);
    printf("dec iv_len: %d\n", ctx->iv_len);
    if (len < ctx->iv_len) {
      LOG_E("length of IV is too small");
      return NULL;
    }

    if (ctx->iv_len > 0) {
      ctx->iv = lmalloc(ctx->iv_len);
      memcpy(ctx->iv, buf, ctx->iv_len);
      buf += ctx->iv_len;
      len -= ctx->iv_len;
    }
  }

  // set the cipher, the key and the IV on the cipher context
  EVP_CipherInit_ex(ctx->evp_cipher_ctx, ctx->cipher, NULL, NULL, NULL, 0);
  EVP_CIPHER_CTX_set_key_length(ctx->evp_cipher_ctx, ctx->key_len);
  EVP_CipherInit_ex(ctx->evp_cipher_ctx, NULL, NULL, ctx->key, ctx->iv, 0);

  *dbuf_len = 0;
  unsigned char *decipher_buf = 
    lmalloc(len + EVP_CIPHER_CTX_block_size(ctx->evp_cipher_ctx));

  int out = 0;
  if (!EVP_CipherUpdate(ctx->evp_cipher_ctx, decipher_buf, &out, 
        (unsigned char *)buf, len)) {
    LOG_E("EVP_CipherUpdate failed");
    free(decipher_buf);
    return NULL;
  }
  *dbuf_len += out;

  out = 0;
  if (!EVP_CipherFinal_ex(ctx->evp_cipher_ctx, decipher_buf + *dbuf_len, &out)) {
    LOG_E("EVP_CipherFinal_ex failed");
    free(decipher_buf);
    return NULL;
  }
  *dbuf_len += out;

  return (char *)decipher_buf;
}

void cipher_ctx_destroy(CipherCtx *ctx) {
  assert(ctx);

  if (ctx->evp_cipher_ctx) {
    EVP_CIPHER_CTX_cleanup(ctx->evp_cipher_ctx);
    EVP_CIPHER_CTX_free(ctx->evp_cipher_ctx);
  }
  free((void *)ctx->key);
  free((void *)ctx->iv);
}


int main(int argc, const char *argv[]) {
  cipher_global_init();

  const char *key = "AAAABBBBAAAABBBB123";
  CipherCtx ctx_e;
  if (cipher_ctx_init(&ctx_e, "aes-256-cbc", key) < 0) {
    fprintf(stderr, "can find aes-256-cbc");
    abort();
  }

  CipherCtx ctx_d;
  if (cipher_ctx_init(&ctx_d, "aes-256-cbc", key) < 0) {
    fprintf(stderr, "can find aes-256-cbc");
    abort();
  }

  char buf[] = "HelloWorld!";
  char buf2[] = "somethign new";
  char buf3[] = "Hey OpenSSL";

  int out_len = 0;
  char *cipher_buf = encrypt(&ctx_e, buf, sizeof(buf), &out_len);
  printf("orig: %d\n", out_len);
  char *orig_buf= decrypt(&ctx_d, cipher_buf, out_len, &out_len);
  printf("declen: %d\n", out_len);
  printf("dec: %s\n", orig_buf);

  out_len = 0;
  cipher_buf = encrypt(&ctx_e, buf2, sizeof(buf2), &out_len);
  printf("orig: %d\n", out_len);
  orig_buf= decrypt(&ctx_d, cipher_buf, out_len, &out_len);
  printf("declen: %d\n", out_len);
  printf("dec: %s\n", orig_buf);

  out_len = 0;
  cipher_buf = encrypt(&ctx_e, buf3, sizeof(buf3), &out_len);
  printf("orig: %d\n", out_len);
  orig_buf= decrypt(&ctx_d, cipher_buf, out_len, &out_len);
  printf("declen: %d\n", out_len);
  printf("dec: %s\n", orig_buf);

  cipher_ctx_destroy(&ctx_e);
  cipher_ctx_destroy(&ctx_d);
  return 0;
}
