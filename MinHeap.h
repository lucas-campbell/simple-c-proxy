/* 
 * MinHeap.h
 */

#ifndef _MINHEAP_INCLUDED_
#define _MINHEAP_INCLUDED_

#include <stdbool.h>

typedef struct MinHeap* MinHeap;

//can only create empty starting heap
MinHeap MinHeap_new(); 
void insert(MinHeap heap, void *elem, int cmp(const void *x, const void *y));
bool isEmpty(MinHeap heap);
void *pop(MinHeap heap);
void *peek(MinHeap heap);
#endif // _MINHEAP_INCLUDED_
