/* 
 * driver for HTTP/HTTPS proxy
 * Written by Lucas Campbell Spring 2020
 * COMP112 Networks
 * Prof. Dogar
 *
 */

/* User-defined headers */
#include "constants.h"
#include "utils.h"
#include "cache.h"
#include "http.h"
#include "waiting_set.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> 
#include <time.h> //time()
#include <unistd.h> //close, read, write

#include <netdb.h> //struct addrinfo, getnameinfo, etc
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

typedef struct accept_info {
    struct sockaddr_in *clientaddr; //must not be NULL
    socklen_t clientlen; //should be sizeof(*clientaddr)
    /* following params for use in getnameinfo(). Must populate
     * accordingly before call to handle_client_request() */
    char *client_hostname;
    char *client_servicename; 
    int host_size;
    int serv_size;
} accept_info;

int accept_new_connection(int parentfd, accept_info *ai);
void handle_client_request(int parentfd, accept_info *ai, int *sock_map,
                            Cache_T cache, fd_set *fds);
int forward_packet(int from_fd, int to_fd, int *sock_map, fd_set *fds);
void add_to_mapping (int clientfd, int serverfd, int *sock_map);
void handle_incoming_message(int from_fd, int *sock_map, Cache_T cache, fd_set *fds);

/* Main Driver */
int main(int argc, char *argv[])
{
    ////////////// Server Variables //////////////
    int parentfd; /* parent socket */
    int listen_portno; /* port to listen on */
    struct sockaddr_in this_serveraddr; /* server addrs */
    struct sockaddr_in clientaddr; /* client addr */
    char client_hostname[256];
    char client_servicename[256];
    int optval; /* flag value for setsockopt */
    Cache_T cache = Cache_new(START_CACHE_SIZE); /* proxy cache */
    int sr = 0; // select return value

    // Check cmd line args
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number for proxy>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    listen_portno = atoi(argv[1]);
    /*   
     * socket: create the parent socket 
     */
    parentfd = socket(AF_INET, SOCK_STREAM, 0);
    if (parentfd < 0) 
        error("ERROR opening socket");

    /* setsockopt: Handy debugging trick that lets 
     * us rerun the server immediately after we kill it; 
     * otherwise we have to wait about 20 secs. 
     * Eliminates "ERROR on binding: Address already in use" error. 
     */
    optval = 1;
    setsockopt(parentfd, SOL_SOCKET, SO_REUSEADDR, 
               (const void *)&optval , sizeof(int));

    /*
     * build the server's Internet address
     */
    bzero((char *) &this_serveraddr, sizeof(this_serveraddr));            

    /* this is an Internet address */
    this_serveraddr.sin_family = AF_INET;

    /* let the system figure out our IP address */
    this_serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    /* this is the port we will listen on */
    this_serveraddr.sin_port = htons((unsigned short)listen_portno);

    /* 
     * bind: associate the parent socket with a port 
     */
    if (bind(parentfd, (struct sockaddr *) &this_serveraddr, 
             sizeof(this_serveraddr)) < 0) 
        error("ERROR on binding");

    /* 
     * listen: make this socket ready to accept connection requests
     */
    /* allow 20 requests to queue up, although that value may get silently
     * overridden to 5 */ 
    if (listen(parentfd, 20) < 0) 
        error("ERROR on listen");

    /*
     * Setup for a mapping of client sockets to server sockets. 
     * Initialize all values to a sentinel value. Max value for a file
     * descriptor when using select is FD_SETSIZE, so we will use -1.
     */
    int sock_map[FD_SETSIZE];
    for (int i = 0; i < FD_SETSIZE; i++)
        sock_map[i] = -1;

    /* 
     * main loop logic: cycle through list of open file descriptors, and check
     * which of them are ready for reading.
     * For each ready fd:
     *   If it is the one we are listening on (parent socket):
     *     1) accept the new connection, and
     *     2) determine if it is for a GET (HTTP) or CONNECT (HTTPS) request (if
     *     it is neither, close the connection). Create a connection with the
     *     requested host server. Then
     *       a) if GET, check program cache to see if stored data available. If
     *       so, send with this. Otherwise, forward the request and add the new
     *       client to a set of "waiting" file descriptors
     *       b) if CONNECT, send confirmation (HTTP 200) back to client after
     *       connecting to requested server
     *  Else, determine if fd is responding to a previously sent GET request
     *  or continuing part of a CONNECT tunnel.
     *    1) if responding to GET, update cache and send response to client
     *    2) otherwise, forward the data through to the other side of the
     *    CONNECT tunnel
     */

    accept_info ai = {.clientaddr = &clientaddr
                        , .clientlen = sizeof(clientaddr)
                        , .client_hostname = &(client_hostname[0])
                        , .client_servicename = &(client_servicename[0])
                        , .host_size = sizeof(client_hostname)
                        , .serv_size = sizeof(client_servicename)
                        };
    fd_set active_fd_set, read_fd_set;
    FD_ZERO (&active_fd_set);
    FD_SET (parentfd, &active_fd_set);

    for (;;) {
        read_fd_set = active_fd_set;
        sr = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
        if (sr < 0) {
            perror("select");
            exit (EXIT_FAILURE);
        }
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd_set)) {
                if (i == parentfd) {
                    // Set up connection to desired resource, possibly
                    // forwarding a GET request
                    handle_client_request(parentfd, &ai, sock_map, cache,
                                            &active_fd_set);
                    // Continues inner for loop, read through all sockets with
                    // ready data
                    continue; 
                }
                // Otherwise we are either returning from a server after a GET
                // request or continuing a CONNECT tunnel, so forward 
                // packets accordingly
                else {
                    handle_incoming_message(i, sock_map, cache, &active_fd_set);
                }
            }
        }
    }

    Cache_free(cache);

    return EXIT_SUCCESS;
}

/*
 * Handles accepting a new client request on the parent socket, and delegates
 * work to helper functions accordingly.
 *
 * parentfd: parent socket to listen on
 * ai: pointer to pre-populated accept_info struct
 * sock_map: integer array, used for keeping track of client-server
 *           file descriptor pairings
 * cache: Proxy cache, used to check for extant results of GET requests
 * fds: fd_set pointer, updated accordingly if connections are successfully
 *      made
 *
 * Returns: None
 */
void handle_client_request(int parentfd, accept_info *ai, int *sock_map,
                            Cache_T cache, fd_set *fds)
{
    int clientfd = accept_new_connection(parentfd, ai);
    if (clientfd == -1) {
        fprintf(stderr, "Could not connect to client\n");
        return;
    }

    /* 
     * read: read input string from the client
     */
    int n_read, total_bytes_read, prev_newline_index, content_length,
        num_header_bytes, ret;
    bool done, check_newline, content_present;
    char c;
    n_read = total_bytes_read = prev_newline_index = content_length 
        = num_header_bytes = ret = 0;
    done = check_newline = content_present = false;
    char *buf = calloc(START_BUFSIZE, 1);
    int curr_bufsize = START_BUFSIZE;
    // Read until have received entire request
    while (!done) {
        ret = http_receive_loop(clientfd, &buf, &c, &n_read, &total_bytes_read,
                            &curr_bufsize, &prev_newline_index, 
                            &content_length, &num_header_bytes, &done,
                            &content_present);
        if (ret != 0) {
            check_and_free(buf);
            close(clientfd);
            return;
        }
    }
#if TRACE
    printf("HTTP_LOOP done, parsing buffer now\n");
#endif
    int server_portno = -1;
    char *extern_hostname = NULL;
    unsigned long hash_val = 0;
    ret = parse_request(buf, total_bytes_read,
                        &extern_hostname, &server_portno, &hash_val);

    //Request was not GET or CONNECT
    if (ret == -1) {
        check_and_free(extern_hostname);
        check_and_free(buf);
        close(clientfd);
        return;
    }
    if (extern_hostname == NULL) { //Clients must specify a hostname
        fprintf(stderr, "Error: No hostname supplied in request:\n%s\n", buf);
        //check_and_free(extern_hostname); not needed
        check_and_free(buf);
        close(clientfd);
        return;
    }
#if TRACE
    printf("DONE parsing request. Hostname: %s, portno: %d\n",
            extern_hostname, server_portno);
    printf("Received request:\n%s\n", buf);
    printf("End of RQ string\n");
    fflush(NULL);
#endif
    // Check with Cache_get(cache, key_hash) if ya existe an entry
    KV_Pair_T response = Cache_get(cache, hash_val);
    if (response != NULL) {
        //update Age & write response to client
        send_response(clientfd, response);
        free(extern_hostname);
        free(buf);
        close(clientfd);
        return;
    }

    /* Setup for connecting to servers specified by the client */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; //IPV4 or IPV6
    hints.ai_socktype = SOCK_STREAM; //tcp stream connections
    // sets flags to (AI_V4MAPPED | AI_ADDRCONFIG),
    // means returned socket addresses will be suitable for connect()
    hints.ai_flags = 0; 
    hints.ai_protocol = 0; //any protocol allowed

    connect_info ci = {0};
    ci.hints = &hints;
    ci.srv_hostname = extern_hostname;
    ci.srv_portno = server_portno;
    ci.connect_request = (ret == 1);
    // if dealing GET request, add the request & len info to fwd to server
    if (!(ci.connect_request)) {
        ci.the_request = buf;
        ci.request_len = total_bytes_read;
    }

    // Set up connection with desired server
    if (connect_to_server(clientfd, &ci) == 0) {
        // if GET request, note that in set of waiting fds
        if (!(ci.connect_request)) {
            ADD_WAITING(clientfd, hash_val);
        }
        // create pairing in sock_map array
        add_to_mapping(clientfd, ci.sfd, sock_map);
        FD_SET(clientfd, fds);
        FD_SET(ci.sfd, fds);
    }
    check_and_free(extern_hostname);
    check_and_free(buf);
    return;
}

/*
 * Given a parent socket (parentfd) and accept_info struct(ai), accept()'s a
 * new connection.
 * On success, returns the new file descriptor. If an error occurs, returns -1.
 */
int accept_new_connection(int parentfd, accept_info *ai)
{
    /* 
     * accept: wait for a connection request 
     */
    int childfd = accept(parentfd, (struct sockaddr *) (ai->clientaddr),
                        &(ai->clientlen));
    if (childfd < 0) {
        perror("accept");
        close(childfd);
        return -1;
    }
    
    memset(ai->client_hostname, 0, ai->host_size);
    memset(ai->client_servicename, 0, ai->serv_size);
#if TRACE
    fprintf(stderr, "Before getnameinfo\n");
#endif
    /* 
     * getnameinfo: determine who sent the message, fills in clientaddr struct
     */
    int name_info = getnameinfo((struct sockaddr *)(ai->clientaddr),
            ai->clientlen, ai->client_hostname,
                ai->host_size, ai->client_servicename,
                ai->serv_size, 0);
    if (name_info != 0) {
        if (name_info == EAI_SYSTEM) {
            perror("System Error during getnameinfo()");
        }
        else {
            fprintf(stderr, "getnameinfo: %s\n", gai_strerror(name_info));
        }
        return -1;
    }
#if TRACE
    printf("getnameinfo returned: %d\n", name_info);
#endif
#if DEBUG
    char *hostaddrp = inet_ntoa(ai->clientaddr->sin_addr);
    if (hostaddrp == NULL) {
        perror("ERROR on inet_ntoa\n");
        return -1;
    }
    printf("accepted incoming connection from: %s (%s), service name: %s\n", 
            ai->client_hostname, hostaddrp, ai->client_servicename);
#endif
    return childfd;
}

/*
 * Update the mapping of client-server file descriptors. -1 indicates None.
 * Once a connection to a server has been established, accessing
 * sock_map[clientfd] == serverfd,
 *      and 
 * sock_map[serverfd] == clientfd
 * so that CONNECT tunnels can be treated symetrically.
 *
 * clientfd: file descriptor of the client
 * serverfd: file descriptor of the server
 * sock_map: int *, an int[FD_SETSIZE] array that has been intitialized with
 *           all -1 values.
 */
void add_to_mapping (int clientfd, int serverfd, int *sock_map)
{
    if ((clientfd < 0 || clientfd > FD_SETSIZE) || 
            (serverfd < 0 || serverfd > FD_SETSIZE))
    {
        fprintf(stderr, "Error adding to socket mappings\n");
        exit(EXIT_FAILURE);
    }

    sock_map[clientfd] = serverfd;
    sock_map[serverfd] = clientfd;
}

/*
 * Forwards a packet to its socket pair according to the socket mapping
 * in the array sock_map.
 * Returns:
 * 0 on success
 * -1 if failed to read packet for forwarding
 * -2 if writing to the corresponding fd failed.
 */
int forward_packet(int from_fd, int to_fd, int *sock_map, fd_set *fds)
{
    char buf[PACKET_SIZE];
    memset(buf, 0, PACKET_SIZE);
    //read from waiting socket
    int n_read = read(from_fd, buf, PACKET_SIZE);
    if (n_read == -1) {
        perror("Reading from socket");
        return -1;
    }

    if (to_fd == -1) {
        fprintf(stderr, "No buddy to forward to :(\n");
        return -2;
    }
    if (n_read == 0) { //time to close the connection
        close(from_fd);
        close(to_fd);
        sock_map[from_fd] = -1;
        sock_map[to_fd] = -1;
        FD_CLR(from_fd, fds);
        FD_CLR(to_fd, fds);
        return 0;
    }
    int n_write = write(to_fd, buf, n_read);
    if (n_write == -1) {
        perror("Forwarding packet");
        return -2;
    }
    return 0;
}

/*
 * 
 */
void handle_incoming_message(int from_fd, int *sock_map, Cache_T cache, fd_set *fds)
{
    if (from_fd < 0 || from_fd > FD_SETSIZE) {
        fprintf(stderr, "Error handling incoming message\n");
        exit(EXIT_FAILURE);
    }
    int to_fd = sock_map[from_fd];
    if (to_fd == -1) {
        fprintf(stderr, "Error with socket mappings\n");
        exit(EXIT_FAILURE);
    }
    //Check if fd returning from a GET request
    if (!IS_WAITING(to_fd)) {
        //Not waiting, so we must be forwarding some part of a CONNECT tunnel
        forward_packet(from_fd, to_fd, sock_map, fds);
        return;
    }

    // We're receiving a response for a GET request, so pull up the hash for it
    unsigned long h = WAITING_HASH(to_fd);
    
    int n_read, total_bytes_read, prev_newline_index, content_length,
        num_header_bytes, ret;
    bool done, check_newline, content_present;
    char c;
    n_read = total_bytes_read = prev_newline_index = content_length 
        = num_header_bytes = ret = 0;
    done = check_newline = content_present = false;
    char *buf = calloc(START_BUFSIZE, 1);
    int curr_bufsize = START_BUFSIZE;
    // Read until have received entire request
    while (!done) {
        ret = http_receive_loop(from_fd, &buf, &c, &n_read, &total_bytes_read,
                            &curr_bufsize, &prev_newline_index, 
                            &content_length, &num_header_bytes, &done,
                            &content_present);
        if (ret != 0) {
            free(buf);
            close(to_fd);
            close(from_fd);
            sock_map[to_fd] = -1;
            sock_map[from_fd] = -1;
            REMOVE_WAITING(to_fd);
            FD_CLR(from_fd, fds);
            FD_CLR(to_fd, fds);
            return;
        }
    } //now, have supposedly received entire HTTP response from server

    //create & fill in kvp struct
    KV_Pair_T response = malloc(sizeof(struct KV_Pair_T));
    response->val = malloc(sizeof(struct Val_T));

    response->priority = -1;
    response->hash_val = h;
    response->put_date = -1;
    
    // parse response buffer from server
    ret = parse_response(buf, total_bytes_read, response);

    if (ret == 0) { 
        // Successfully parsed, so add to cache
        // and forward to client
        response->put_date = time(NULL);

        Cache_put(cache, response);

        send_response(to_fd, response);
    }
    else {
        //Error, so free key-value pair before returning
#if DEBUG
        printf("Error in response from server:%s\n", buf);
#endif
        check_and_free(response->val->object);
        check_and_free(response->val);
        check_and_free(response);
    }

    free(buf);
    close(to_fd);
    close(from_fd);
    sock_map[to_fd] = -1;
    sock_map[from_fd] = -1;
    REMOVE_WAITING(to_fd);
    FD_CLR(from_fd, fds);
    FD_CLR(to_fd, fds);
    return;
}
