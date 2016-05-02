#include "list.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

void list_init(List *list) {
  assert(list);
  list->size_ = 0;
  memset(list, 0, sizeof(List));
}

void list_destroy(List *list, void(*cb)(void *data)) {
  assert(list);
  Node *node = list->head_;
  while (node) {
    Node *cur_node = node;

    if (cb) {
      cb(node->data_);
    }
    node = node->next_;

    free(cur_node);
  }

  memset(list, 0, sizeof(List));
}

void list_add_head(List *list, void *data) {
  assert(list);

  Node *node = malloc(sizeof(Node));
  node->data_ = data;
  node->next_ = list->head_;
  list->head_ = node;

  if (list->tail_ == NULL) {
    list->tail_ = node;
  }

  ++list->size_;
}

void list_add_tail(List *list, void *data) {
  assert(list);

  Node *node = malloc(sizeof(Node));
  node->data_ = data;
  node->next_ = NULL;
  if (list->tail_) {
    list->tail_->next_ = node;
  }
  list->tail_ = node;

  if (list->head_ == NULL) {
    list->head_ = node;
  }

  ++list->size_;
}

void *list_head(List *list) {
  assert(list);
  Node *head = list->head_;
  return head ? head->data_ : NULL;
}

void *list_tail(List *list) {
  assert(list);
  Node *tail = list->tail_;
  return tail ? tail->data_ : NULL;
}

void *list_remove_head(List *list) {
  assert(list);

  void *data = NULL;
  Node *head = list->head_;
  if (head) {
    data = head->data_;
    list->head_ = head->next_;
    free(head);
    --list->size_;
    if (list->size_ == 0) {
      list->tail_ = NULL;
    }
  }

  return data;
}

void *list_remove_tail(List *list) {
  assert(!"list_remove_tail not implemented");
  return NULL;
}

int list_size(List *list) {
  assert(list);
  return list->size_;
}

Iterator list_iterator(List *list) {
  assert(list);
  return (Iterator){ list->head_ };
}

void *list_next(Iterator *it) {
  assert(it);
  Node *node = it->node_;
  if (node) {
    it->node_ = node->next_;
  } else {
    it->node_ = NULL;
  }
  return node ? node->data_ : NULL;
}
