#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h> //close, read, write

#include "constants.h"
#include "connect.h"
#include "utils.h"
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
void connect_loop(int clientfd, char *server_hostname, int server_portno,
                  struct addrinfo hints, char *request, int request_len)
{
#if TRACE
    printf("Entering connect_loop()\n");
#endif
    // TODO remove these params
    (void)request;
    (void)request_len;
    struct addrinfo *result, *rp;
    //(void)clientfd;
    //(void)server_hostname;
    //(void)server_portno;
    // open a socket for connection with desired target
    int serverfd; //will be for comms with server
    int n_write, n_read;
    char *msg_buf, *error_msg;
    bool fail = false;
    bool closed = false;

    /* Set up connection using desired host/port */
    char srv_portno[6]; //maximum of 65,535 ports
    memset(srv_portno, 0, 6);
    sprintf(srv_portno, "%d", server_portno); //adds null
    int s = getaddrinfo(server_hostname, srv_portno, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(EXIT_FAILURE);
    }
    /* Connect to desired resource.
     * getaddrinfo() returns a list of address structures.
      Try each address until we successfully connect(2).
      If socket(2) (or connect(2)) fails, we (close the socket
      and) try the next address. */
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        serverfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (serverfd == -1)
            continue;
        if (connect(serverfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */
        //else
        close(serverfd);
    }
    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not connect during CONNECT\n");
        exit(EXIT_FAILURE);
    }
    freeaddrinfo(result);           /* No longer needed */

    ////connection request to forward editing//////////////////////
    //// TODO maybe make this a separate func
    ////char        cpy[request_len]; //for strtok'ing
    ////char msg_to_fwd[request_len]; //for sending to the server
    //char        *cpy = malloc(request_len); //for strtok'ing
    //char *msg_to_fwd = malloc(request_len); //for sending to the server
    //memset(cpy,        0, request_len);
    //memset(msg_to_fwd, 0, request_len);
    //int bytes = 0; //total bytes of msg, updated as copied over
    //int line_len = 0; //length of each line of request
    //memcpy(cpy, request, request_len);
    //char *line = strtok(cpy, "\n");
    //while (line != NULL) {
    //    //Proxy-Connection header advised not to be sent in any requests
    //    char *bad = strstr(line, "Proxy-Connection");
    //    if (bad == NULL) {
    //        // TODO some nice pointer math that copies appropriate 
    //        // bytes from char *request to msg_to_fwd + adds \r, 
    //        // aka just copying over appropriate header fields.
    //        // TODO
    //        // To look at: https://tools.ietf.org/html/rfc7230#appendix-A.1.2
    //        // https://tools.ietf.org/html/rfc7230#section-5.7.2
    //        // https://tools.ietf.org/html/rfc7231#section-4.3.6
    //        line_len = strlen(line);
    //        memcpy(msg_to_fwd+bytes, line, line_len);
    //        bytes += line_len;
    //        msg_to_fwd[bytes] = '\n'; //bc strtok takes out \n
    //        bytes++;
    //    }
    //    line = strtok(NULL, "\n");
    //}
    //bytes--;

    ////////////////////////////

    //n_write = write(serverfd, msg_to_fwd, bytes);

    //if (n_write != bytes) {
    //    fprintf(stderr, "Error forwarding connect request to server\n");
    //    close(serverfd);
    //    close(clientfd);
    //    return;
    //}

    //n_write = write(serverfd, request, request_len);

    //if (n_write != request_len) {
    //    fprintf(stderr, "Error forwarding connect request to server\n");
    //    close(serverfd);
    //    close(clientfd);
    //    return;
    //}
    // TODO free this?
    msg_buf = malloc(START_BUFSIZE);
    memset(msg_buf, 0, START_BUFSIZE);
    //n_read = read(serverfd, msg_buf, START_BUFSIZE);

    //send HTTP 200 confirmation response back to client
    char *success = "HTTP/1.1 200 OK\r\n\r\n";
    //msg_buf = malloc(sizeof(START_BUFSIZE));
    memcpy(msg_buf, success, strlen(success));
    msg_buf[strlen(success)] = '\0';
    n_write = write(clientfd, msg_buf, strlen(msg_buf));
    if (n_write == -1) {
        //TODO fail some other way & close fds
        error("Writing to client failed:");
    }
    //n_read = read(clientfd, msg_buf, START_BUFSIZE);

    // loop of:
    //   1) read from client
    //   2) send to server
    //   3) read from server
    //   4) send to client
    // with error checking & seeing if connexn closed/etc
    fd_set active_fd_set, read_fd_set;
    struct timeval * tv = NULL;
    FD_ZERO (&active_fd_set);
    FD_SET (clientfd, &active_fd_set);
    FD_SET (serverfd, &active_fd_set);
#if DEBUG
    printf("entering select loop in CONNECT\n");
#endif
    while (!(fail || closed)) {
        read_fd_set = active_fd_set;
        //TODO maybe also have a write_fds here, but probably not
        int ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL, tv);
        if (ret == -1) {
            fail = true;
            error_msg = "select() during CONNECT method";
            break;
        }
        // look through sockets with data ready to be read
        for (int i = 0; i < FD_SETSIZE; i++) {
            if (FD_ISSET(i, &read_fd_set)) {
                if (i == clientfd) {
#if TRACE
                    printf("msg from client\n");
#endif
                    // read from client, send to server
                    memset(msg_buf, 0, START_BUFSIZE);
                    n_read = read(clientfd, msg_buf, START_BUFSIZE);
                    if (n_read < 0) {
                        fail = true;
                        error_msg = "reading from client in CONNECT tunnel";
                        break;
                    }
                    else if (n_read == 0) { //TODO possibly add check/print here?
                        closed = true;
                        break;
                    }
                    else {
                        n_write = write(serverfd, msg_buf, n_read);
                        if (n_write <= 0) {
                            fail = true;
                            error_msg = "writing to server in CONNECT tunnel";
                            break;
                        }
                    }
                }
                else if (i == serverfd) {
#if TRACE
                    printf("msg from server\n");
#endif
                    //read from server, send to client
                    memset(msg_buf, 0, START_BUFSIZE);
                    n_read = read(serverfd, msg_buf, START_BUFSIZE);
                    if (n_read < 0) {
                        fail = true;
                        error_msg = "reading from server in CONNECT tunnel";
                        break;
                    }
                    else if (n_read == 0) { //TODO possibly add check/print here?
                        closed = true;
                        break;
                    }
                    else {
                        n_write = write(clientfd, msg_buf, n_read);
                        if (n_write <= 0) {
                            fail = true;
                            error_msg = "writing to client in CONNECT tunnel";
                            break;
                        }
                    }
                }
                else {
                    //error, fd on is not clientfd or serverfd
                    fprintf(stderr, "Bad value in FD_ISSET");
                }
            }
        }
    }
#if DEBUG
    printf("end of select loop in CONNECT\n");
#endif

    if (fail) {
        perror(error_msg);
    }
    close(clientfd);
    close(serverfd);
#if TRACE
    printf("End of connect_loop()\n");
#endif
    return;
}
