#ifndef WAITING_SET_H_
#define WAITING_SET_H_

#include <sys/select.h>

// Simple functions for using an unsigned long[FD_SETSIZE] array as a list of
// fds similar in functionality to the fd_set used by the select() function.
// Used by the proxy as a way to keep track of which file descriptors are
// waiting for a response to a GET request, and relies on the extreme
// unlikelyhood of hash(some_val) (see utils.c) being 0.
// The value at waiting[n] contains the value 0 if fd n is not being used.
// Otherwise, waiting[n] should be populated to contain the hash value of the
// resource previously requested by the fd n.

static unsigned long waiting[FD_SETSIZE];

#define ADD_WAITING(n, x) waiting[n] = x
#define REMOVE_WAITING(n) waiting[n] = 0
#define IS_WAITING(n) (!(waiting[n] == 0))
#define WAITING_HASH(n) waiting[n]

#endif //WAITING_SET_H_
