/* 
 * MinHeap.h
 */

#ifndef MINHEAP_INCLUDED
#define MINHEAP_INCLUDED

#include <stdbool.h>
#define HEAP_CAPACITY 10

typedef struct MinHeap {
   int size; 
   void *elems[HEAP_CAPACITY];
} *MinHeap;

//can only create empty starting heap
MinHeap MinHeap_new(); 
void MinHeap_insert(MinHeap heap, void *elem,
                    int cmp(const void *x, const void *y));
bool MinHeap_isEmpty(MinHeap heap);
int MinHeap_size(MinHeap heap);
void *MinHeap_pop(MinHeap heap);
void *MinHeap_peek(MinHeap heap);
void MinHeap_clear(MinHeap heap);
void MinHeap_free(MinHeap *heap_p);
#endif // MINHEAP_INCLUDED
