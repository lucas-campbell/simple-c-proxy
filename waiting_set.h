#ifndef WAITING_SET_H_
#define WAITING_SET_H_

// simple functions for using an unsigned long[1024] array as a list of fds
// with little to no error checking. Used by the proxy as a way to keep track
// of which file descriptors are waiting for a response to a GET request, and
// relies on the extreme unlikelyhood of hash(some_val) being 0. Stores 0 in
// the index if that fd is not being used, and the hash value for that resource
// (that would be used to retrive from a Cache_T) otherwise

static unsigned long waiting[1024];

#define ADD_WAITING(n, x) waiting[n] = x
#define REMOVE_WAITING(n) waiting[n] = 0
#define IS_WAITING(n) (!(waiting[n] == 0))
#define WAITING_HASH(n) waiting[n]

#endif //WAITING_SET_H_
