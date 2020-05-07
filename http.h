#ifndef HTTP_H
#define HTTP_H

#include "cache.h"

#include <netdb.h> //struct addrinfo
#include <stdbool.h>

typedef struct connect_info {
    struct addrinfo *hints;
    char *srv_hostname;
    char *the_request;
    int request_len;
    int srv_portno;
    bool connect_request;
    int sfd;
} connect_info;

int parse_request(char *buf, int len, char **hostname, int *portno,
                    unsigned long *hash_val);

int parse_response(char *buf, int size, KV_Pair_T kvp);

int send_response(int sockfd, KV_Pair_T response);

int http_receive_loop(int childfd, char **buf, char *c, int *n_read,
                        int *total_bytes_read, int *curr_bufsize,
                        int *prev_newline_index, int *content_length,
                        int *num_header_bytes, bool *done,
                        bool *content_present);

void connect_loop(int clientfd, char *server_hostname, int server_portno,
                  struct addrinfo hints);
int connect_to_server(int clientfd, struct connect_info *ci);

#endif //HTTP_H
