#include "utils.h"

#include <stdint.h> //uint32_t
#include <stdlib.h> //free
#include <stdio.h> //perror

/*
 * Safer free function
 */
void check_and_free(void *mem)
{
    if(mem != NULL)
        free(mem);
}

/*
 * error - wrapper for perror that exits the program
 */
void error(char *msg)
{
  perror(msg);
  exit(1);
} 

/* 
 * Hash function, originally written by Professor Daniel J Bernstein. Algorithm
 * taken from online.
 * Params:
 *      data: pointer to data that gets implicitly cast as char*
 *      len: # of bytes to hash
 * Returns:
 *      unsigned hash value
 */
unsigned long hash(unsigned char *data, size_t len)
{
    size_t count = 0;
    uint32_t hash = 5381;
    for (unsigned char c = *data; count < len; c = *data++) {
        hash = ((hash << 5) + hash) + c;
        count++;
    }
    return hash;    
}

