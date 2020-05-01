#ifndef PROXY_UTILS_INCLUDED
#define PROXY_UTILS_INCLUDED

#include <stdlib.h> //size_t

void check_and_free(void *mem);
void error(char *msg);
unsigned long hash(unsigned char *data, size_t len);

#endif //PROXY_UTILS_INCLUDED

