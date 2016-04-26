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
