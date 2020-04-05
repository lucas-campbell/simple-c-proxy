#include <stdlib.h>
#include <stdio.h>
#include "MinHeap.h"
#include <stdbool.h>

int main()
{
    bool ok = true;

    printf("new: ");
    MinHeap m = MinHeap_new();
    ok &= (m != NULL && sizeof(*m) == sizeof(struct MinHeap));
    printf("%s", ok ? "OK\n" : "FAIL\n");
    printf("sizeof(struct MinHeap): %lu\n", sizeof(struct MinHeap));
    printf("sizeof(*m): %lu\n", sizeof(*m));

    printf("isEmpty w/ empty heap: ");
    ok &= MinHeap_isEmpty(m);
    printf("%s", ok ? "OK\n" : "FAIL\n");

    printf("inserting...");
    struct car {int x; char c;} bing;
    struct car *bong = &bing;
    MinHeap_insert(m, bong, NULL);
    ok &= m->size == 1;
    printf("%s", ok ? "OK\n" : "FAIL\n");

    printf("freeing: ");
    MinHeap_free(&m);
    printf("OK\n");
    return 0;
}
