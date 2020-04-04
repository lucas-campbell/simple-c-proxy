/* 
 * MinHeap.c
 */
#include <stdlib.h>
#include "MinHeap.h"

struct MinHeap {
   int size; 
   void **elems;
};

MinHeap MinHeap_new()
{
    MinHeap heap = malloc(sizeof(*heap));
    heap->size = 0;
    return heap;
}

void insert(MinHeap heap, void *elem, int cmp(const void *x, const void *y));
bool isEmpty(MinHeap heap);
void *pop(MinHeap heap);
void *peek(MinHeap heap);
