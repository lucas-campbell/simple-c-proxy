/* 
 * MinHeap.c
 */
#include <stdlib.h>
#include <string.h>

#include "MinHeap.h"

////////// Internal Funcs //////////
void MinHeap_heapify(MinHeap heap, int i,
                     int cmp(const void *x, const void *y))
{

}

void *parent(MinHeap heap, int i)
{
    if (i == 0) {
        return NULL;
    }
    else {
        return (heap->elems)[i / 2];
    }
}

void *leftChild(MinHeap heap, int i)
{
    int left = 2*i + 1;
    if (left < heap->size - 1)
    {
        return (heap->elems)[left];
    }
    else return NULL;
}

void *rightChild(MinHeap heap, int i)
{
    int right = 2*i + 2;
    if (right < heap->size - 1)
    {
        return (heap->elems)[right];
    }
    else return NULL;
}

int default_cmp(const void *x, const void *y)
{
    return x - y;
}
////////////////////////////////////

MinHeap MinHeap_new()
{
    MinHeap heap = malloc(sizeof(*heap));
    heap->size = 0;
    return heap;
}

int MinHeap_size(MinHeap heap)
{
    return heap->size;
}

bool MinHeap_isEmpty(MinHeap heap)
{
    return heap->size == 0;
}

void MinHeap_insert(MinHeap heap, void *elem,
                    int cmp(const void *x, const void *y))
{
    int (*cmp_func)(const void *, const void *);
    cmp_func = cmp ? cmp : default_cmp;
    if (MinHeap_isEmpty(heap))
    {
        //heap = realloc(heap, sizeof(*heap) + sizeof(elem));
        heap->size = 1;
    }
    /* To add an element to a heap we must perform an up-heap operation
     * (also known as bubble-up, percolate-up, sift-up, trickle-up, swim-up,
     * heapify-up, or cascade-up), by following this algorithm:

    1. Add the element to the bottom level of the heap at the most left.
    2. Compare the added element with its parent; if they are in the correct
    order, stop.
    3. If not, swap the element with its parent and return to the
    previous step.
     */
    else {
        int index_of_added = heap->size++;
        (heap->elems)[index_of_added] = elem;
        // if parent is greater, need to swap bc min heap
        while ((*cmp_func)(parent(heap, index_of_added), elem) > 0) {
            // swap elem with its parent
            int index_of_parent = index_of_added / 2;
            void *temp = (heap->elems)[index_of_parent];
            (heap->elems)[index_of_parent] = elem;
            (heap->elems)[index_of_added] = temp;

            index_of_added = index_of_parent;
            if (index_of_added == 0)
                break;
            }
    }
}

void *MinHeap_pop(MinHeap heap);
void *MinHeap_peek(MinHeap heap);

void MinHeap_clear(MinHeap heap)
{
    memset(heap, 0, sizeof(void *) * HEAP_CAPACITY);
    heap->size = 0;
}

void MinHeap_free(MinHeap *heap_p)
{
    free(*heap_p);
    return;
}
