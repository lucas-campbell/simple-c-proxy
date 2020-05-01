#ifndef CONNECT_INCLUDED
#define CONNECT_INCLUDED
/*
 * https://tools.ietf.org/html/rfc7231#section-4.3.6
 * loop for HTTP CONNECT method
 * Runs a loop that acts a blind tunnel for traffic between the client and 
 * requested resource. Responses from the server are not cached. Once the
 * connection is closed by either end, proxy will attempt to send outstanding
 * data from closed side to other side, then closes both connexns & returns.
 * 
 * clientfd: file descriptor for communicating with the client
 * 
 */

#include <netdb.h> //struct addrinfo

void connect_loop(int clientfd, char *server_hostname, int server_portno,
                  struct addrinfo hints, char *request, int request_len);
#endif //CONNECT_INCLUDED
