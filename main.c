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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> 
#include <time.h> //time(), struct timeval
#include <unistd.h> //close, read, write

#include <netdb.h> //struct addrinfo, getnameinfo, etc
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>


int main(int argc, char *argv[])
{
    ////////////// Server Variables //////////////
    int parentfd; /* parent socket */
    int childfd; /* child socket */
    int sockfd; /* socket to connect to external server */
    int listen_portno; /* port to listen on */
    int server_portno; /* port to connect to external server on */
    int clientlen; /* byte size of client's address */
    struct sockaddr_in this_serveraddr; /* server addrs */
    //TODO struct sockaddr_in extern_serveraddr; /* server addrs */
    struct sockaddr_in clientaddr; /* client addr */
    //TODO remove struct hostent *extern_serverp; /* client host info */
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    //struct hostent *client_hostp; /* client host info */
    char client_hostname[256];
    char client_servicename[256];
    char *buf; /* message buffer */
    char *hostaddrp; /* dotted decimal host addr string */
    char *extern_hostname; /* host to connect to */
    int optval; /* flag value for setsockopt */
    int n_read, n_write; /* message byte size */
    Cache_T cache = Cache_new(START_CACHE_SIZE); /* proxy cache */

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
    if (listen(parentfd, 5) < 0) /* allow 5 requests to queue up TODO more here?*/ 
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
     * Setup for connecting to servers specified by the client
     */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; //IPV4 or IPV6
    hints.ai_socktype = SOCK_STREAM;
    // sets flags to (AI_V4MAPPED | AI_ADDRCONFIG)
    // means returned socket addresses will be suitable for connect()
    hints.ai_flags = 0; 
    hints.ai_protocol = 0; //any protocol allowed

    /* 
     * main loop: wait for a connection request, echo input line, 
     * then close connection.
     */
    clientlen = sizeof(clientaddr);
    while (1) {

        /* 
         * accept: wait for a connection request 
         */
        childfd = accept(parentfd, (struct sockaddr *) &clientaddr,
                        (socklen_t *) &clientlen);
        if (childfd < 0) 
            error("ERROR on accept");
        
        /* 
         * gethostbyaddr: determine who sent the message, fills in clientaddr
         * struct
         */
        //client_hostp = gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr, 
        //                      sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        memset(client_hostname, 0, sizeof(client_hostname));
        memset(client_servicename, 0, sizeof(client_servicename));
        //memset(&clientaddr, 0, clientlen);
#if TRACE
        fprintf(stderr, "Before getnameinfo\n");
#endif
        int name_info = getnameinfo((struct sockaddr *)&clientaddr, clientlen, client_hostname,
                    sizeof(client_hostname), client_servicename,
                    sizeof(client_servicename), 0);
        if (name_info != 0){
            if (name_info == EAI_SYSTEM) {
                perror("System Error during getnameinfo()");
            }
            else
                gai_strerror(name_info);
        }
#if TRACE
        fprintf(stderr, "getnameinfo returned: %d\n", name_info);
#endif
        //if (client_hostp == NULL)
        //    //error("ERROR on gethostbyaddr");
        //    herror("ERROR on gethostbyaddr");
        hostaddrp = inet_ntoa(clientaddr.sin_addr);
        if (hostaddrp == NULL)
            error("ERROR on inet_ntoa\n");
#if DEBUG
        printf("server established connection with %s (%s)\n", 
                client_hostname, hostaddrp);
#endif
        
        /* 
         * read: read input string from the client
         */
        int curr_bufsize = START_BUFSIZE;
        int total_bytes_read, prev_newline_index, content_length, num_header_bytes;
        bool done, check_newline, content_present;
        char c;
        total_bytes_read = prev_newline_index = content_length = num_header_bytes = 0;
        done = check_newline = content_present = false;
        buf = malloc(START_BUFSIZE);
        memset(buf, 0, START_BUFSIZE);
        //bzero(buf, START_BUFSIZE);
        // Read until have received entire request
        while (!done) {
            http_receive_loop(childfd, &buf, &c, &n_read, &total_bytes_read,
                                &curr_bufsize, &prev_newline_index, 
                                &content_length, &num_header_bytes, &done,
                                &content_present);
        }

        // Once we have full buffer, analyze it and create connection with
        // desired server or report back an error
        // create partially filled request struct to insert into table
#if TRACE
        printf("HTTP_LOOP done, parsing buffer now\n");
#endif
        server_portno = -1;
        extern_hostname = NULL;
        int ret = 0;
        unsigned long hash_val = 0;
        ret = parse_request(buf, total_bytes_read,
                            &extern_hostname, &server_portno, &hash_val);
        if (ret == -1) {
            check_and_free(extern_hostname);
            check_and_free(buf);
            close(childfd);
            continue;
        }

        // If no hostname supplied, close & wait for new connection
        if (extern_hostname == NULL) {
            fprintf(stderr, "Error: No hostname supplied in GET request:\n%s\n", buf);
            //check_and_free(extern_hostname); not needed
            check_and_free(buf);
            close(childfd);
            continue;
        }

#if TRACE
        printf("DONE parsing request. Hostname: %s, portno: %d\n",
                extern_hostname, server_portno);
#endif
#if DEBUG
        printf("Received request:\n%s\n", buf);
#endif

        // if serving a connect request, enter separate loop and continue
        // indefinitely through there
        // TODO
        if (ret == 1) {
            connect_loop(childfd, extern_hostname, server_portno, hints,
                            buf, total_bytes_read);
            check_and_free(extern_hostname);
            check_and_free(buf);
            //close_connections(...);
            continue;
        }
        

        // Check with Cache_get(cache, key_hash) if ya existe an entry
        KV_Pair_T response = Cache_get(cache, hash_val);
        //  if ya existe:
        if (response != NULL) {
            //update Age & write response to client
            send_response(childfd, response);
        }
        //  else get fresh one (set up connxn w/server)
        else {
            /* Set up connection using desired host/port */
            char srv_portno[6]; //maximum of 65,535 ports
            memset(srv_portno, 0, 6);
            sprintf(srv_portno, "%d", server_portno); //adds null
	    int s = getaddrinfo(extern_hostname, srv_portno, &hints, &result);
            if (s != 0) {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            /* getaddrinfo() returns a list of address structures.
              Try each address until we successfully connect(2).
              If socket(2) (or connect(2)) fails, we (close the socket
              and) try the next address. */
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sockfd == -1)
                    continue;
                if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
                    break;                  /* Success */
                close(sockfd);
            }
            if (rp == NULL) {               /* No address succeeded */
                fprintf(stderr, "Could not connect during GET\n");
                //TODO don't fail here, restart!
                exit(EXIT_FAILURE);
            }
            freeaddrinfo(result);           /* No longer needed */

            //Write the GET request ourselves to the server
            n_write = write(sockfd, buf, total_bytes_read);
            (void)n_write;

            /* Now, reading back response from requested server */

            //zero out the buffer before reading back from external server
            bzero(buf, total_bytes_read);
            total_bytes_read = prev_newline_index =
                    content_length = num_header_bytes = 0;
            done = check_newline = content_present = false;
            // Read until have received entire request
            while (!done) {
                http_receive_loop(sockfd, &buf, &c, &n_read, &total_bytes_read,
                                    &curr_bufsize, &prev_newline_index, 
                                    &content_length, &num_header_bytes, &done,
                                    &content_present);
            } //now, have supposedly received entire HTTP response from server

            //create & fill in kvp struct
            KV_Pair_T response = malloc(sizeof(struct KV_Pair_T));
            response->val = malloc(sizeof(struct Val_T));

            response->priority = -1;
            response->hash_val = hash_val;
            response->put_date = -1;
            
            parse_response(buf, total_bytes_read, response);

            response->put_date = time(NULL);

            Cache_put(cache, response);
        
            send_response(childfd, response);

            close(sockfd);
            //Cache_print(cache);
        }
        free(extern_hostname);
        free(buf);
        close(childfd);
    }

    Cache_free(cache);

    return EXIT_SUCCESS;
}
