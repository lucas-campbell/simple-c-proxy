#ifndef CACHE_INCLUDED
#define CACHE_INCLUDED

#include <stdlib.h>
#include <stdio.h>

typedef struct Val_T {
    size_t header_size;
    size_t content_len;
    void *object;
} *Val_T;

typedef struct KV_Pair_T {
    int priority; //lowest priority (1) == most recently requested,
                  //highest priority (capacity) == least recently requested
    unsigned long hash_val;
    time_t put_date;
    time_t expiration_date;
    Val_T val;
} *KV_Pair_T;

typedef struct Cache_T {
    int capacity;
    int curr_size;
    KV_Pair_T *kv_pairs;
} *Cache_T;

/* Allocate memory for and return a new cache of specified size */
Cache_T Cache_new(int capacity);

/* Free memory associated with a Cache */
void Cache_free(Cache_T cache);

/* Insert key-value pair into Cache, overwriting pervious value for that key,
 * if any. If Cache is full, kicks out some previous item according to:
 * 1) Stale values
 * 2) Least recently requested item in Cache
 */
void Cache_put(Cache_T cache, KV_Pair_T kv);

/* Return  pointer to key-value pair struct associated with a hash in the Cache.
 * Reports a value DNE (or stale) by returning NULL */
KV_Pair_T Cache_get(Cache_T cache, unsigned long key_hash);

/* Removes from cache and decrements necessary priorities of other kvps */
void Cache_remove(Cache_T cache, unsigned long key_hash);

/* Prints contents of Cache */
void Cache_print(Cache_T cache);

#endif //CACHE_INCLUDED
