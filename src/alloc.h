#ifndef ALLOC_H_
#define ALLOC_H_
#include <stdlib.h>

void *lmalloc(size_t size);
void *lrealloc(void *p, size_t size);

#endif /* end of include guard: ALLOC_H_ */
