#include <stdlib.h>

#define container_of(ptr, type, field) \
  ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))

#define CHECK(exp) \
do { \
  if (!exp) { \
    fprintf(stderr, "Error occured on [%s:%d] %s()\n", __FILE__, \
        __LINE__, __FUNCTION__); \
    exit(1); \
  } \
} while (0)

