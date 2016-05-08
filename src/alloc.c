#include "alloc.h"
#include <stdio.h>
#include <string.h>

void *lmalloc(size_t size) {
  void *p = malloc(size);
  memset(p, 0, size);
  if (!p) {
    fprintf(stderr, "malloc failed for: %lu\n", size);
    exit(1);
  }

  return p;
}

void *lrealloc(void *p, size_t size) {
  void *p2 = realloc(p, size);
  if (!p2) {
    fprintf(stderr, "realloc failed for: %lu\n", size);
    exit(1);
  }

  return p2;
}
