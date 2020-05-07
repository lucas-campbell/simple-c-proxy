#include "http.h"
#include "utils.h"
#include "constants.h"

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h> //time() etc
#include <unistd.h> //close, read, write

/* 
 * Sets hostname and portno according to info in buf, and defaults portno
 * to 80. Also sets hash_val to a unique hash value according to a combination
 * of the resource, host, and port requested (if doing a GET request).
 *
 * Return values: 0 indicates GET request, 1 is CONNECT. -1 indicates error.
 */
int parse_request(char *buf, int len, char **hostname, int *portno,
                  unsigned long *hash_val)
{
    int ret = 0;
    int major, minor; //HTTP version
    char *tokens = calloc(len+1, 1); //+1 for possible final strtok null
    char *line, *resource;
    bool head_rq = false;
    memcpy(tokens, buf, len); //create copy bc strtok edits the string

    //split into tokens based on newlines
    line = strtok(tokens, "\n");
    if (line == NULL) {
        free(tokens);
        return -1;
    }
    resource = malloc(strlen(line));

    //***NOTE***: only bother scanning until \r bc strtok replaces \n with \0
    // Also, "resource" var here has null char placed @ end by sscanf
    if (sscanf(line, "GET %s HTTP/%d.%d\r", resource, &major, &minor) != 3) {
        if (sscanf(line, "HEAD %s HTTP/%d.%d\r", resource, &major, &minor) == 3) {
            head_rq = true;
        }
        else if (sscanf(line, "CONNECT %s HTTP/%d.%d\r", resource, &major, &minor) == 3) {
            ret = 1;
        }
        else {
#if DEBUG
            printf("Cannot service request:\n%s\n", tokens);
#endif
            ret = -1;
        }
    }

    while (line != NULL) {
        //Check first 5 chars to see if params specify a Host
        if (strncmp(line, "Host:", 5) == 0) { 
            int line_len = strlen(line);
            int i = 5;
            *hostname = malloc(line_len);
            //Check if rest of line contains another ':' to specify the port #
            while (i < line_len && line[i] != ':') { 
                i++;
            }
            if (line[i] == ':') { // then 2nd : found, so portno was specified
                sscanf(line+i, ":%d\r", portno);
                char hostnameonly[i+1]; //+1 for null 
                memcpy(hostnameonly, line, i);
                hostnameonly[i] = '\0';
                sscanf(hostnameonly, "Host: %s", *hostname);
            }
            else { //no portno specified
                sscanf(line, "Host: %s\r", *hostname);
                *portno = 80;
            }
            break;
        }
        line = strtok(NULL, "\n");
    }
#if TRACE
    char *type;
    if (ret == 1) type = "CONNECT";
    else if (ret == 0) type = "GET/HEAD";
    else type = "UNKOWN";
    printf("parsed %s request: %s\n", type, buf);
    if (*hostname != NULL)
        printf("Got host: %s, set portno to %d\n", *hostname, *portno);
#endif
    
    // Don't care about hashing for connect requests, since results are not
    // cacheable
    if (ret == 0) {
        /* create hash based on hostname + resource (+port) */
        int to_hash_len = strlen(resource); //ok bc sscanf adds null char
        char ascii_portno[6]; //maximum of 65,535 ports
        memset(ascii_portno, 0, 6);
        if (*hostname != NULL) {
            to_hash_len += strlen(*hostname); //sscanf adds null
        }
        sprintf(ascii_portno, "%d", *portno); //adds null
        to_hash_len += strlen(ascii_portno);

        //add string at beginning to differentiate between HEAD/GET responses
        if (head_rq) {
            to_hash_len += 4; //"HEAD"
        } else {
            to_hash_len += 3; //"GET"
        }

        //Order of hashed string: "HEAD" or "GET", resource, hostname, port num
        char to_hash[to_hash_len];
        int method_len;
        if (head_rq) {
            memcpy(to_hash, "HEAD", 4);
            method_len = 4;
        } else {
            memcpy(to_hash, "GET", 3);
            method_len = 3;
        }

        // resource
        memcpy(to_hash+method_len, resource, strlen(resource));
        if (*hostname != NULL) {
            // hostname
            memcpy(to_hash+(method_len+strlen(resource)), *hostname, strlen(*hostname));
            // portno
            memcpy(to_hash+(method_len+strlen(resource)+strlen(*hostname)-1),
                    ascii_portno, strlen(ascii_portno));
        }
        *hash_val = hash((unsigned char *)to_hash, to_hash_len);
    }

    check_and_free(resource);
    free(tokens);
    return ret;
}

/*
 * buf: response received from server
 * size: length of response
 * kvp: newly malloc'd key-value pair that will be
 *      filled in by this function
 *
 *  Returns 0 on successful parse, -1 otherwise
 */
int parse_response(char *buf, int size, KV_Pair_T kvp)
{
    int major, minor, response_code, max_age, content_length;
    content_length = 0;
    max_age = -1;
    char * line = NULL;
    char reason[100];
    char *tokens = calloc(size+1, 1); //+1 for possible final strtok null

    memcpy(tokens, buf, size);
    //split into tokens based on newlines
    line = strtok(tokens, "\n");
    if (line == NULL) {
        free(tokens);
        return -1;
    }

    if (sscanf(line, "HTTP/%d.%d %d %s\r\n", &major, &minor, &response_code,
                reason) != 4) {
#if DEBUG
        printf("Error with first line of HTTP response\n%s\n", buf);
#endif
        free(tokens);
        return -1;
    }
    bool got_age, got_len;
    got_age = got_len = false;
    while (line != NULL) {
        if (!got_age) {
            if(strncmp(line, "Cache-Control:", 14) == 0) {
                char *maybe = strstr(line, "max-age=");
                if (maybe != NULL) {
                    max_age = 0;
                    sscanf(maybe, "max-age=%d\r", &max_age);
                }
                got_age = true;
            }
        }
        if (!got_len) {
            if (sscanf(line, "Content-Length: %d\r", &content_length) == 1) {
                got_len = true;
            }
        }
        if (got_len && got_age)
            break;
        line = strtok(NULL, "\n");
    }

    //fill in kvp
    time_t now = time(NULL);
    if (max_age == -1)
        max_age = 3600; //default
    time_t m_age = max_age;
    kvp->expiration_date = m_age + now;
    kvp->val->content_len = content_length;
    kvp->val->header_size = size - content_length;
    kvp->val->object = malloc(size);
    memcpy(kvp->val->object, buf, size);
    free(tokens);
    return 0;
}

int send_response(int sockfd, KV_Pair_T response)
{
    if (response == NULL) {
        fprintf(stderr, "ERROR, Tried to send a NULL response to client\n");
        return 0;
    }

    struct tm zero_secs = {0};
    struct tm one_secs = {0};
    one_secs.tm_sec = 1;
    time_t zero = mktime(&zero_secs);
    time_t one = mktime(&one_secs);
    // should be 1 anyways, but trying to be portableish
    double one_second = difftime(one, zero); 

    /* Build Age header field */
    time_t now = time(NULL);
    int age = (int)(difftime(now, response->put_date) * one_second);
    //should be enough space for the number of seconds
    char ascii_age[107]; 
    sprintf(ascii_age, "Age: %d\r\n", age);
    char *newline = strchr(ascii_age, '\n');
    *(newline + 1) = '\0'; //manual null char

    //shortcut vars
    int header_size = response->val->header_size;
    int content_len = response->val->content_len;
    char *to_send = (char *)(response->val->object); 
     
    /* Message to finally send to server */
    char msg[header_size + content_len + strlen(ascii_age)];

    /*
     * Order: OG Header(s) - extra CRLF, added Age header+ending CRLF,
     * then content
     */
    memcpy(msg, to_send, header_size-2); //not final CRLF
    memcpy(msg+(header_size-2), ascii_age, strlen(ascii_age));
    msg[header_size+(strlen(ascii_age)-2)] = '\r';
    msg[header_size+(strlen(ascii_age)-1)] = '\n';

    //content, if any
    if (content_len > 0) {
        // offset by original header + new age header
        memcpy(msg+(header_size + strlen(ascii_age)),
                // offset by original header
                to_send+header_size, content_len);
    }

    ssize_t n_write = write(sockfd, msg, header_size+content_len+strlen(ascii_age));
    if (n_write != header_size+content_len+(int)strlen(ascii_age)) {
        fprintf(stderr, "Error writing response to client\n");
    }
    return n_write;
}

/* Loop iteration for parsing an HTTP request OR response from socket. To be
 * called until *done == true, to ensure that all content has been read and put
 * into *buf.
 *
 * Returns 0 on a successful iteration of the loop, -1 otherwise.
 *
 * Params:
 *  int childfd: file descriptor for socket to read from
 *  char **buf:
 *  char *c: last character read from socket
 *  int *n_read: num bytes read on last read call
 *  int *total_bytes_read: total num bytes read so far
 *  int *curr_bufsize: current number of bytes allocated at *buf
 *  int *prev_newline_index: index of previous newline character
 *  int *content_length: total bytes of content
 *  int *num_header_bytes: total number of bytes in the header of msg,
 *                          including terminating CRLF
 *  bool *done: indicates if we have read all of header (+ possible message)
 *              from socket
 *  bool *content_present: does the message header contain the header-field
                           for Content-Length?
 */
int http_receive_loop(int childfd, char **buf, char *c, int *n_read,
                        int *total_bytes_read, int *curr_bufsize,
                        int *prev_newline_index, int *content_length,
                        int *num_header_bytes, bool *done,
                        bool *content_present)
{
    //Read a byte from stream
    //*n_read = read(childfd, (*buf)+(*total_bytes_read), 1);
    *n_read = recv(childfd, (*buf)+(*total_bytes_read), 1, 0);
    if (*n_read < 0) {
        perror("http_receive_loop");
        return -1;
    }
    if (*n_read == 0) {
        *done = true;
        (*buf)[*total_bytes_read] = '\0';
        return 0;
    }
    *total_bytes_read += *n_read; 
    *c = (*buf)[(*total_bytes_read)-1];
    // May need to expand buffer if especially long GET request
    if (*total_bytes_read == *curr_bufsize) {
        *curr_bufsize = 2*(*curr_bufsize);
        *buf = realloc(*buf, *curr_bufsize);
        memset((*buf)+(*total_bytes_read), 0, (*total_bytes_read));
    }
    if (*c == '\n') {
        //check if we have run into 2 CRLFs in a row
        //--> indicates end of header or end of entire message
        int i = *total_bytes_read - 1;
        if (((*buf)[i-3] == '\r' && (*buf)[i-2] == '\n') && (*buf)[i-1] == '\r') {
            if (!(*content_present)) {
                // 2 CRLFs + no content --> done reading
                *done = true;
                (*buf)[*total_bytes_read] = '\0';
                return 0;
            }
            else {
                //we have reached the end of the header and will now need to
                //read content of msg
                *num_header_bytes = *total_bytes_read;
            }
        }
        else if (sscanf((*buf)+((*prev_newline_index)+1),
                    "Content-Length: %d\r\n", content_length) == 1) {
            //Prev line indicated that message contains a body/payload
            *content_present = true;
        }
        *prev_newline_index = *total_bytes_read-1;
    }
    if (*total_bytes_read == *num_header_bytes + *content_length &&
            *num_header_bytes != 0){ //extra check, in case v long header
        *done = true;
        (*buf)[*total_bytes_read] = '\0';
    }
    return 0;
}


/*
 * Connects to a desired resource indicated by connect_info struct *ci.
 * fd associated with connected server is put in ci->sfd
 *
 * Return values:
 *  0: All ok, should call add_to_mapping() next
 *  -1: problem communicating to server
 *  -2: could not write confirmation to client
 */
int connect_to_server(int clientfd, struct connect_info *ci)
{
#if TRACE
    printf("Entering connect_to_server()\n");
#endif
    /* Connect to desired server */
    struct addrinfo *result, *rp; 
    int serverfd; //fd for comms with server
    int n_write;
    char *msg_buf;

    /* Set up connection using desired host/port */
    char server_portno[6]; //maximum of 65,535 ports
    memset(server_portno, 0, 6);
    sprintf(server_portno, "%d", ci->srv_portno); //adds null
    int s = getaddrinfo(ci->srv_hostname, server_portno, ci->hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        close(clientfd);
        return -1;
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
        fprintf(stderr, "Could not connect during %s\n",
                ci->connect_request?"CONNECT":"GET");
        close(clientfd);
        return -1;
    }
    freeaddrinfo(result);           /* No longer needed */

#if DEBUG
    printf("made connection with server %s (port %s)\n",
            ci->srv_hostname, server_portno);
#endif

    if (ci->connect_request) {
        /* Send confirmation to client */
        msg_buf = calloc(START_BUFSIZE, 1);
        char *success = "HTTP/1.1 200 OK\r\n\r\n";
        memcpy(msg_buf, success, strlen(success));
        msg_buf[strlen(success)] = '\0';
        n_write = write(clientfd, msg_buf, strlen(msg_buf));
        if (n_write == -1) {
            perror("Writing to client failed:");
            free(msg_buf);
            close(serverfd);
            close(clientfd);
            return -2;
        }
        free(msg_buf);
    }
    else {
        n_write = write(serverfd, ci->the_request, ci->request_len);
        if (n_write == -1) {
            perror("Writing GET request to server");
            close(serverfd);
            close(clientfd);
            return -1;
        }
        //no need to ADD_WAITING(), was already done before this function 
        //if necessary in handle_client_request logic
    }

    ci->sfd = serverfd;
#if TRACE
    printf("Successfully finished connect_to_server()\n");
#endif
    return 0;
}
