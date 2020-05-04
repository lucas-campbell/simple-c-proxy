#ifndef HTTP_H
#define HTTP_H

#include "cache.h"

#include <netdb.h> //struct addrinfo
#include <stdbool.h>

int parse_request(char *buf, int len, char **hostname, int *portno,
                    unsigned long *hash_val);

void parse_response(char *buf, int size, KV_Pair_T kvp);

int send_response(int sockfd, KV_Pair_T response);

void http_receive_loop(int childfd, char **buf, char *c, int *n_read,
                        int *total_bytes_read, int *curr_bufsize,
                        int *prev_newline_index, int *content_length,
                        int *num_header_bytes, bool *done,
                        bool *content_present);

void connect_loop(int clientfd, char *server_hostname, int server_portno,
                  struct addrinfo hints, char *request, int request_len);
int forward_packet(int from_fd, char *pkt, size_t len, int *sock_map);

#endif //HTTP_H
