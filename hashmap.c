#include "hashmap.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>

#define DEFAULT_INITIAL_CAPACITY 16
#define DEFAULT_LOAD_FACTOR 0.75f

typedef struct Entry {
  const char *key_;
  void *data_;
  struct Entry *next_;
  int hash_;
} Entry;

static int entry_key_hash(const char *key);
static int key_hash(int h);
static int index_for_hash(int hash, int count);
static void add_entry(HashMap *hashmap, int hash, const char *key, 
    void *value, int index);
static void resize(HashMap *hashmap, int new_capacity);

void hashmap_init(HashMap *hashmap, on_entry_removed_cb on_entry_removed) {
  assert(hashmap != NULL);

  hashmap->size_ = 0;
  memset(hashmap, 0, sizeof(HashMap));

  hashmap->load_factor_ = DEFAULT_LOAD_FACTOR;
  hashmap->capacity_ = DEFAULT_INITIAL_CAPACITY;
  hashmap->threashold_ = hashmap->load_factor_ * hashmap->capacity_;
  hashmap->on_entry_removed_ = on_entry_removed;
  hashmap->entries_ = malloc(sizeof(Entry *) * hashmap->capacity_);
  memset(hashmap->entries_, 0, sizeof(Entry *) * hashmap->capacity_);
}

void *hashmap_get(HashMap *hashmap, const char *key) {
  assert(hashmap != NULL);
  assert(key != NULL);

  int h = entry_key_hash(key);
  int hash = key_hash(h);
  int index = index_for_hash(hash, hashmap->capacity_);

  for (Entry *entry = hashmap->entries_[index]; entry; entry = entry->next_) {
    if (strcmp(entry->key_, key) == 0) {
      return entry->data_;
    }
  }

  return NULL;
}

void hashmap_remove(HashMap *hashmap, const char *key) {
  assert(hashmap != NULL);
  assert(key != NULL);

  int h = entry_key_hash(key);
  int hash = key_hash(h);
  int index = index_for_hash(hash, hashmap->capacity_);
  Entry *prev = NULL;
  for (Entry *entry = hashmap->entries_[index]; entry; entry = entry->next_) {
    if (hash == entry->hash_ || strcmp(entry->key_, key) == 0) {
      if (prev) {
        prev->next_ = entry->next_;
      } else {
        hashmap->entries_[index] = entry->next_;
      }
      if (hashmap->on_entry_removed_) {
        hashmap->on_entry_removed_(entry->key_, entry->data_);
      }
      free((char *)entry->key_);
      free(entry);
    }

    prev = entry;
  }
}

int hashmap_contains_key(HashMap *hashmap, const char *key) {
  return hashmap_get(hashmap, key) != NULL;
}

void hashmap_put(HashMap *hashmap, const char *key, void *value) {
  assert(hashmap != NULL);
  assert(key != NULL);

  int h = entry_key_hash(key);
  int hash = key_hash(h);
  int index = index_for_hash(hash, hashmap->capacity_);
  for (Entry *entry = hashmap->entries_[index]; entry; entry = entry->next_) {
    if (hash == entry->hash_ || strcmp(entry->key_, key) == 0) {
      void *old_data = entry->data_;
      if (value == old_data) {
        return;
      }
      if (hashmap->on_entry_removed_) {
        hashmap->on_entry_removed_(entry->key_, old_data);
      }
      entry->data_ = value;
      return;
    }
  }

  add_entry(hashmap, hash, key, value, index);
}

void hashmap_destroy(HashMap *hashmap) {
  assert(hashmap != NULL);

  for (int i = 0; i < hashmap->capacity_; ++i) {
    Entry *entry = hashmap->entries_[i];
    while (entry) {
      Entry *next = entry->next_;
      if (hashmap->on_entry_removed_) {
        hashmap->on_entry_removed_(entry->key_, entry->data_);
      }
      free((char *)entry->key_);
      free(entry);
      entry = next;
    }
  }

  free(hashmap->entries_);
  memset(hashmap, 0, sizeof(HashMap));
}

int hashmap_size(HashMap *hashmap) {
  assert(hashmap != NULL);
  return hashmap->size_;
}

int hashmap_capacity(HashMap *hashmap) {
  assert(hashmap != NULL);
  return hashmap->capacity_;
}

void add_entry(HashMap *hashmap, int hash, const char *key, 
    void *value, int index) {
  Entry *entry = malloc(sizeof(Entry));
  entry->key_ = strdup(key);
  entry->hash_ = hash;
  entry->data_ = value;

  entry->next_ = hashmap->entries_[index];
  hashmap->entries_[index] = entry;

  if (entry->next_)
  printf("key: %s, has collision\n", key);

  ++hashmap->size_;
  if (hashmap->size_ >= hashmap->threashold_) {
    resize(hashmap, hashmap->capacity_ * 2);
  }
}

int index_for_hash(int hash, int count) {
  return hash & (count - 1);
}

int key_hash(int h) {
    h ^= (h >> 20) ^ (h >> 12);
    return h ^ (h >> 7) ^ (h >> 4);
}

int entry_key_hash(const char *key) {
  int h = 0;
  int index = 0;
  int len = strlen(key);
  for (int i = 0; i < len; ++i) {
    h = 31 * h + *(key+i);
  }
  return h;
}

void resize(HashMap *hashmap, int new_capacity) {
  assert(hashmap != NULL);

  if (hashmap->capacity_ == INT_MAX) {
    hashmap->threashold_ = INT_MAX;
    return;
  }

  int old_capacity = hashmap->capacity_;
  hashmap->capacity_ = new_capacity;
  hashmap->entries_ = realloc(hashmap->entries_, sizeof(Entry *) * new_capacity);
  memset(hashmap->entries_ + old_capacity, 0, sizeof(Entry *) * old_capacity);

  for (int i = 0; i < old_capacity; ++i) {
    Entry *entry = hashmap->entries_[i];
    if (entry) {
      hashmap->entries_[i] = NULL;
      do {
        Entry *next = entry->next_;
        int index = index_for_hash(entry->hash_, new_capacity);
        entry->next_ = hashmap->entries_[index];
        hashmap->entries_[index] = entry;
        entry = next;
      } while (entry);
    }
  }

  hashmap->threashold_ = new_capacity * hashmap->load_factor_;
  printf("new capacity: %d\n", new_capacity);
}

