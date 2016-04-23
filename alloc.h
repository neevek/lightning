void *lmalloc(size_t size) {
  void *p = malloc(size);
  if (!p) {
    fprintf(stderr, "malloc failed for: %lu\n", size);
    exit(1);
  }

  return p;
}
