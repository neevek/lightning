#ifndef HASHMAP_H_
#define HASHMAP_H_

typedef void (*on_entry_removed_cb)(const char *key, void *value);
struct Entry;
typedef struct HashMap {
  struct Entry **entries_;
  on_entry_removed_cb on_entry_removed_;
  int threashold_;
  float load_factor_;
  int capacity_;
  int size_;
} HashMap;

typedef struct {
  struct Entry *entry_;
  int current_index_;
} KeyIterator;

void hashmap_init(HashMap *hashmap, on_entry_removed_cb on_entry_removed);
void hashmap_destroy(HashMap *hashmap);
void hashmap_put(HashMap *hashmap, const char *key, void *value);
void *hashmap_get(HashMap *hashmap, const char *key);
void hashmap_remove(HashMap *hashmap, const char *key);
int hashmap_contains_key(HashMap *hashmap, const char *key);
int hashmap_size(HashMap *hashmap);
int hashmap_capacity(HashMap *hashmap);
KeyIterator hashmap_key_iterator(HashMap *hashmap);
const char *hashmap_next_key(HashMap *hashmap, KeyIterator *it);

#endif /* end of include guard: HASHMAP_H_ */
