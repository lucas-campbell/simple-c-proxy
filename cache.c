#include "cache.h"

#include "utils.h"
#include <time.h>

Cache_T Cache_new(int capacity)
{
    // calculate & allocate correct memory for cache
    Cache_T cache = malloc(sizeof(struct Cache_T));
    cache->capacity = capacity;
    // Each KV pair will be malloc'd as it is created
    cache->kv_pairs = calloc((size_t)capacity, sizeof(KV_Pair_T));

    return cache;
}

void Cache_free(Cache_T cache)
{
    int capacity = cache->capacity;
    for (int i = 0; i < capacity; i++) {
        check_and_free((cache->kv_pairs[i])->val->object);
        check_and_free((cache->kv_pairs[i])->val);
        check_and_free(cache->kv_pairs[i]);
    }
    check_and_free(cache->kv_pairs);
    check_and_free(cache);
}

void Cache_put(Cache_T cache, KV_Pair_T kv)
{
    int capacity = cache->capacity;
    KV_Pair_T *kvps = cache->kv_pairs;
    int free_space_index = -1;
    //First check for matching kvpair
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && kvps[i]->hash_val == kv->hash_val) {
            int old_priority = kvps[i]->priority;
            // free mem of old kvp
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            // make sure new priority is 1
            kv->priority = 1;
            // insert new kv-pair
            kvps[i] = kv;
            // increment all other priorities that used to be in front
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
                    if (kvps[j]->priority < old_priority)
                        kvps[j]->priority += 1;
            return;
        }
        //save 1st NULL pointer we come to to possibly save time
        else if (kvps[i] == NULL && free_space_index == -1) 
            free_space_index = i;
    }
    //Otherwise, check for free space in table
    if (free_space_index != -1) {
        kv->priority = 1;
        kvps[free_space_index] = kv;
        for (int j = 0; j < capacity; j++)
            //increment all others no matter what
            if (kvps[j] != NULL && j != free_space_index)
                kvps[j]->priority += 1;
        cache->curr_size++;
        return;
    }
    //else, we have to kick out stale or least recently requested item and
    // then use that space
    int least_recently_requested = -1;
    time_t curr_time = time(NULL);
    for (int i = 0; i < capacity; i++) {
        //check stale
        if (curr_time > kvps[i]->expiration_date) {
#if DEBUG
	    fprintf(stderr, "stale\n");
#endif
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            kv->priority = 1;
            kvps[i] = kv;
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
                    kvps[j]->priority += 1;
            return;
        }
        //save oldest request index in case none are stale
        else if (kvps[i]->priority == capacity)
            least_recently_requested = i;
    }
    if (least_recently_requested == -1) {
        fprintf(stderr, "Error: cannot remove oldest request because of"
                        " a priorities issue.\n");
        exit(EXIT_FAILURE);
    }
    //if reached this point, we have the index of oldest request. replace it
    // with the new kv pair & return
    free(kvps[least_recently_requested]->val->object);
    free(kvps[least_recently_requested]->val);
    free(kvps[least_recently_requested]);
    kv->priority = 1;
    kvps[least_recently_requested] = kv;
    //increment all other priorities
    for (int j = 0; j < capacity; j++)
        //if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
        if (kvps[j] != NULL && j != least_recently_requested)
            kvps[j]->priority += 1;
    return;
}

KV_Pair_T Cache_get(Cache_T cache, unsigned long key_hash)
{
    KV_Pair_T *kvps = cache->kv_pairs;
    int capacity = cache->capacity;
    time_t curr_time = time(NULL);
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && key_hash == (kvps[i])->hash_val) {
            //If stale, remove from cache & report DNE
            if (curr_time > kvps[i]->expiration_date) {
                Cache_remove(cache, key_hash);
                return NULL;
            }
            //else not stale -> update priorities & return corresponding value
            int old_priority = kvps[i]->priority;
            kvps[i]->priority = 1;
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && key_hash != (kvps[j])->hash_val)
                    if (kvps[j]->priority < old_priority)
                        kvps[j]->priority += 1;
            return kvps[i];
        }
    }
    //If we reached this point, key doesn't exist in cache
    return NULL; 
}

void Cache_remove(Cache_T cache, unsigned long key_hash)
{
    KV_Pair_T *kvps = cache->kv_pairs;
    int capacity = cache->capacity;
    //find corresponding key-val pair in cache
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && key_hash == (kvps[i])->hash_val) {
            int prio = kvps[i]->priority;
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            kvps[i] = NULL;
            //decrease priority values of all other kvps in cache that had a
            //"worse" priority, aka move them up in the queue
            for (int j = 0; j < capacity; j++) {
                if (kvps[j] != NULL && kvps[j]->priority > prio) {
                    kvps[j]->priority -= 1;
                }
            }
            cache->curr_size -= 1;
            return;
        }
    }
    fprintf(stderr, "Error: Could not remove key with hash %lu from table "
                    "because key did not exist\n", key_hash);
}

void Cache_print(Cache_T cache)
{
    printf("******* PRINTING CACHE STATE **********\n");
    int capacity = cache->capacity;
    time_t now = time(NULL);
    printf("TIME NOW: %s\n", asctime(localtime(&now)));
    printf("capacity: %d\ncurr_size: %d\n", capacity, cache->curr_size);
    KV_Pair_T *kvps = cache->kv_pairs;
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL) {
            printf(" _____________________________\n"
                   "|expires: %s prio: %d, hash: %lu |\n"
                   "------------------------------\n"
                   "|val: %s |\n",
                    asctime(localtime(&(kvps[i]->expiration_date))),
                    kvps[i]->priority, kvps[i]->hash_val,
                    (char *)kvps[i]->val->object);
        }
    }
    printf("***********************************************************\n\n\n");
}

