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
    struct sockaddr_in *clientaddr;
    socklen_t clientlen;
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

int main(int argc, char *argv[])
{
    ////////////// Server Variables //////////////
    int parentfd; /* parent socket */
    //TODO int childfd; /* child socket */
    //TODO int sockfd; /* socket to connect to external server */
    int listen_portno; /* port to listen on */
    //TODO int server_portno; /* port to connect to external server on */
    // TODO remove int clientlen; /* byte size of client's address */
    struct sockaddr_in this_serveraddr; /* server addrs */
    //TODO remove ?struct sockaddr_in extern_serveraddr; /* server addrs */
    struct sockaddr_in clientaddr; /* client addr */
    //TODO remove struct hostent *extern_serverp; /* client host info */
    //TODO struct addrinfo *result, *rp;
    //TODO struct hostent *client_hostp; /* client host info */
    char client_hostname[256];
    char client_servicename[256];
    //TODO remove char *buf; /* message buffer */
    //TODO char *extern_hostname; /* host to connect to */
    int optval; /* flag value for setsockopt */
    //int n_read, n_write; /* message byte size */
    Cache_T cache = Cache_new(START_CACHE_SIZE); /* proxy cache */
    // TODO remove clientlen = sizeof(clientaddr);
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
    if (listen(parentfd, 20) < 0) /* allow 20 requests to queue up */ 
        error("ERROR on listen");

    /*
     * Setup for a mapping of client sockets to server sockets. Used for
     * HTTPS connections.
     * Initialize all values to a sentinel value. Max value for a file
     * descriptor when using select is FD_SETSIZE, so we will use this.
     */
    int sock_map[FD_SETSIZE];
    for (int i = 0; i < FD_SETSIZE; i++)
        sock_map[i] = -1;

    /* 
     * TODO re-write this description
     * main loop: wait for a connection request, echo input line, 
     * then close connection.
     */

    accept_info ai = {.clientaddr = &clientaddr
                        , .clientlen = sizeof(clientaddr)
                        , .client_hostname = &(client_hostname[0])
                        , .client_servicename = &(client_servicename[0])
                        , .host_size = sizeof(client_hostname)
                        , .serv_size = sizeof(client_servicename)
                        };
    fd_set active_fd_set, read_fd_set;
    struct timeval * tv = NULL;
    FD_ZERO (&active_fd_set);
    FD_SET (parentfd, &active_fd_set);

    for (;;) {
        read_fd_set = active_fd_set;
        sr = select(FD_SETSIZE, &read_fd_set, NULL, NULL, tv);
        if (sr < 0) {
            perror("select");
            exit (EXIT_FAILURE);
        }
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd_set)) {
                if (i == parentfd) {
                    handle_client_request(parentfd, &ai, sock_map, cache, &active_fd_set);
                    //continues for loop, read through all sockets with ready data
                    continue; 
                }
                // Otherwise we are either returning from a server after a GET
                // request or continuing a CONNECT tunnel, so forward accordingly
                else {
                    handle_incoming_message(i, sock_map, cache, &active_fd_set);
                }
            }
        }
    }
        //// Check with Cache_get(cache, key_hash) if ya existe an entry
        //KV_Pair_T response = Cache_get(cache, hash_val);
        ////  if ya existe:
        //if (response != NULL) {
        //    //update Age & write response to client
        //    send_response(childfd, response);
        //}
        //  else get fresh one (set up connxn w/server)
        //else {
        //    /* Set up connection using desired host/port */
        //    char srv_portno[6]; //maximum of 65,535 ports
        //    memset(srv_portno, 0, 6);
        //    sprintf(srv_portno, "%d", server_portno); //adds null
	//    int s = getaddrinfo(extern_hostname, srv_portno, &hints, &result);
        //    if (s != 0) {
        //        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        //        exit(EXIT_FAILURE);
        //    }
        //    /* getaddrinfo() returns a list of address structures.
        //      Try each address until we successfully connect(2).
        //      If socket(2) (or connect(2)) fails, we (close the socket
        //      and) try the next address. */
        //    for (rp = result; rp != NULL; rp = rp->ai_next) {
        //        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        //        if (sockfd == -1)
        //            continue;
        //        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
        //            break;                  /* Success */
        //        close(sockfd);
        //    }
        //    if (rp == NULL) {               /* No address succeeded */
        //        fprintf(stderr, "Could not connect during GET\n");
        //        //TODO don't fail here, restart!
        //        exit(EXIT_FAILURE);
        //    }
        //    freeaddrinfo(result);           /* No longer needed */

        //    //Write the GET request ourselves to the server
        //    n_write = write(sockfd, buf, total_bytes_read);
        //    (void)n_write;

        //    /* Now, reading back response from requested server */

        //    //zero out the buffer before reading back from external server
        //    bzero(buf, total_bytes_read);
        //    total_bytes_read = prev_newline_index =
        //            content_length = num_header_bytes = 0;
        //    done = check_newline = content_present = false;
        //    // Read until have received entire request
        //    while (!done) {
        //        http_receive_loop(sockfd, &buf, &c, &n_read, &total_bytes_read,
        //                            &curr_bufsize, &prev_newline_index, 
        //                            &content_length, &num_header_bytes, &done,
        //                            &content_present);
        //    } //now, have supposedly received entire HTTP response from server

        //    //create & fill in kvp struct
        //    KV_Pair_T response = malloc(sizeof(struct KV_Pair_T));
        //    response->val = malloc(sizeof(struct Val_T));

        //    response->priority = -1;
        //    response->hash_val = hash_val;
        //    response->put_date = -1;
        //    
        //    parse_response(buf, total_bytes_read, response);

        //    response->put_date = time(NULL);

        //    Cache_put(cache, response);
        //
        //    send_response(childfd, response);

        //    close(sockfd);
        //    //Cache_print(cache);
        //}
    //    free(extern_hostname);
    //    free(buf);
    //    close(childfd);
    //}

    Cache_free(cache);

    return EXIT_SUCCESS;
}

void handle_client_request(int parentfd, accept_info *ai, int *sock_map,
                            Cache_T cache, fd_set *fds)
{
    int clientfd = accept_new_connection(parentfd, ai);
    
    /* 
     * read: read input string from the client
     */
    int n_read, total_bytes_read, prev_newline_index, content_length,
        num_header_bytes;
    bool done, check_newline, content_present;
    char c;
    n_read = total_bytes_read = prev_newline_index = content_length 
        = num_header_bytes = 0;
    done = check_newline = content_present = false;
    char *buf = calloc(START_BUFSIZE, 1);
    int curr_bufsize = START_BUFSIZE;
    // Read until have received entire request
    while (!done) {
        http_receive_loop(clientfd, &buf, &c, &n_read, &total_bytes_read,
                            &curr_bufsize, &prev_newline_index, 
                            &content_length, &num_header_bytes, &done,
                            &content_present);
    }
#if TRACE
    printf("HTTP_LOOP done, parsing buffer now\n");
#endif
    int server_portno = -1;
    char *extern_hostname = NULL;
    int ret = 0;
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
    hints.ai_socktype = SOCK_STREAM;
    // sets flags to (AI_V4MAPPED | AI_ADDRCONFIG),
    // means returned socket addresses will be suitable for connect()
    hints.ai_flags = 0; 
    hints.ai_protocol = 0; //any protocol allowed

    //TODO initialize sfd here?
    connect_info ci = {0};
    ci.hints = &hints;
    ci.srv_hostname = extern_hostname;
    ci.srv_portno = server_portno;
    ci.connect_request = (ret == 1);
    // if dealing GET request, make sure to note that in set of waiting fds
    // and add the GET request & len info to fwd to server
    if (!(ci.connect_request)) {
        ci.the_request = buf;
        ci.request_len = total_bytes_read;
        ADD_WAITING(clientfd, hash_val);
    }

    // Set up connection with desired server
    if (connect_to_server(clientfd, &ci) == 0)
        // create pairing in sock_map array
        add_to_mapping(clientfd, ci.sfd, sock_map);
    check_and_free(extern_hostname);
    check_and_free(buf);
    FD_SET(clientfd, fds);
    FD_SET(ci.sfd, fds);
    return;
}

/*
 * Given a parent socket and accept_info struct, accept()'s a new connection
 * from the parentfd.
 * ai struct should have clientaddr 
 */
int accept_new_connection(int parentfd, accept_info *ai)
{
    /* 
     * accept: wait for a connection request 
     */
    int childfd = accept(parentfd, (struct sockaddr *) (ai->clientaddr),
                        &(ai->clientlen));
    if (childfd < 0) 
        //TODO error another way
        error("ERROR on accept");
    
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
        else
            gai_strerror(name_info);
    }
#if TRACE
    fprintf(stderr, "getnameinfo returned: %d\n", name_info);
#endif
        char *hostaddrp = inet_ntoa(ai->clientaddr->sin_addr);
        if (hostaddrp == NULL)
            //TODO error cleanup
            error("ERROR on inet_ntoa\n");
#if DEBUG
        printf("server established connection. Host: %s (%s), service name: %s\n", 
                ai->client_hostname, hostaddrp, ai->client_servicename);
#endif
        return childfd;
}

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

//TODO replace exits with returns
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
        //We must be forwarding some part of a CONNECT tunnel
        forward_packet(from_fd, to_fd, sock_map, fds);
        return;
    }

    // We're receiving a response for a GET request, so pull up the hash for it
    unsigned long h = WAITING_HASH(to_fd);
    
    int n_read, total_bytes_read, prev_newline_index, content_length,
        num_header_bytes;
    bool done, check_newline, content_present;
    char c;
    n_read = total_bytes_read = prev_newline_index = content_length 
        = num_header_bytes = 0;
    done = check_newline = content_present = false;
    char *buf = calloc(START_BUFSIZE, 1);
    int curr_bufsize = START_BUFSIZE;
    // Read until have received entire request
    while (!done) {
        http_receive_loop(from_fd, &buf, &c, &n_read, &total_bytes_read,
                            &curr_bufsize, &prev_newline_index, 
                            &content_length, &num_header_bytes, &done,
                            &content_present);
    } //now, have supposedly received entire HTTP response from server

    //create & fill in kvp struct
    KV_Pair_T response = malloc(sizeof(struct KV_Pair_T));
    response->val = malloc(sizeof(struct Val_T));

    response->priority = -1;
    response->hash_val = h;
    response->put_date = -1;
    
    parse_response(buf, total_bytes_read, response);

    response->put_date = time(NULL);

    Cache_put(cache, response);

    send_response(to_fd, response);

    //TODO respect Connection: Keep-Alive headers and don't close sockets?
    //might complicate things a LOT
    close(to_fd);
    close(from_fd);
    sock_map[to_fd] = -1;
    sock_map[from_fd] = -1;
    REMOVE_WAITING(to_fd);
    FD_CLR(from_fd, fds);
    FD_CLR(to_fd, fds);
    //Cache_print(cache);
    return;
}
