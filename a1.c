/*
 * a1.c -- HTTP Proxy
 * Written by Lucas Campbell Spring 2020
 * COMP112 Networks
 * Prof. Dogar
 *
 */

/* User-defined headers */
#include "constants.h"
#include "connect.h"
#include "utils.h"

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

////////// Struct Definitions //////////
typedef struct Val_T {
    size_t header_size;
    size_t content_len;
    void *object;
} *Val_T;

typedef struct KV_Pair_T {
    int priority; //lowest priority (1) == most recently requested,
                  //highest priority (capacity) == least recently requested
    unsigned long hash_val;
    time_t put_date;
    time_t expiration_date;
    Val_T val;
} *KV_Pair_T;

typedef struct Cache_T {
    int capacity;
    int curr_size;
    KV_Pair_T *kv_pairs;
} *Cache_T;
////////////////////////////////////////

// Fwd declarations
Cache_T Cache_new(int capacity);
void Cache_free(Cache_T cache);
void Cache_put(Cache_T cache, KV_Pair_T kv);
KV_Pair_T Cache_get(Cache_T cache, unsigned long key_hash);
void Cache_remove(Cache_T cache, unsigned long key_hash);
void Cache_print(Cache_T cache);

//
// Sets hostname and portno according to info in buf, and defaults portno
// to 80. Also sets hash_val to a unique hash value according to a combination
// of the resource, host, and port requested (if doing a GET request).
// Return values: 0 indicates GET request, 1 is CONNECT. -1 indicates error.
int parse_request(char *buf, int len, char **hostname, int *portno,
                  unsigned long *hash_val)
{
    int ret = 0;
    int major, minor; //HTTP version
    char tokens[len];
    char *line, *resource;
    memcpy(tokens, buf, len); //create copy bc strtok edits the string

    //split into tokens based on newlines
    line = strtok(tokens, "\n");
    resource = malloc(strlen(line));

    //***NOTE***: only bother scanning until \r bc strtok replaces \n with \0
    // Also, "resource" var here has null char placed @ end by sscanf
    if (sscanf(line, "GET %s HTTP/%d.%d\r", resource, &major, &minor) != 3) {
        if (sscanf(line, "CONNECT %s HTTP/%d.%d\r", resource, &major, &minor) == 3) {
            ret = 1;
        }
        else {
            fprintf(stderr, "Error with first line of GET Request\n%s\n", tokens);
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
#if DEBUG
    printf("parsed %s request: %s\n", (ret == 1)?"CONNECT":"GET", buf);
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
        char to_hash[to_hash_len];
        //Order of hashed string: resource, hostname, port num     
        // resource
        memcpy(to_hash, resource, strlen(resource));
        if (*hostname != NULL) {
            // hostname
            memcpy(to_hash+(strlen(resource)), *hostname, strlen(*hostname));
            // portno
            memcpy(to_hash+(strlen(resource)+strlen(*hostname)-1),
                    ascii_portno, strlen(ascii_portno));
        }
        *hash_val = hash((unsigned char *)to_hash, to_hash_len);
    }

    check_and_free(resource);

    return ret;
}

/*
 * buf: response received from server
 * size: length of response
 * kvp: newly malloc'd key-value pair that will be
 *      filled in by this function
 */
void parse_response(char *buf, int size, KV_Pair_T kvp) {
    int major, minor, response_code, max_age, content_length;
    content_length = 0;
    max_age = -1;
    char * line = NULL;
    char reason[100];
    char tokens[size];

    memcpy(tokens, buf, size);
    //split into tokens based on newlines
    line = strtok(tokens, "\n");

    if (sscanf(line, "HTTP/%d.%d %d %s\r\n", &major, &minor, &response_code,
                reason) != 4) {
        fprintf(stderr, "Error with first line of HTTP response\n%s\n", buf);
        exit(-1);
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
        if (!got_len)
            if (sscanf(line, "Content-Length: %d\r\n", &content_length) == 1) {
                got_len = true;
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

///////////////////////// CACHE FUNCTIONS ////////////////////////////

/* unused function */
//KV_Pair_T make_kvp(unsigned long hash_val, time_t expiration_date, void *buf,
//                    int buf_size, int header_size)
//{
//    KV_Pair_T kvp = malloc(sizeof(struct KV_Pair_T));    
//    kvp->val = malloc(sizeof(struct Val_T));
//
//    kvp->priority = -1;
//    kvp->hash_val = hash_val;
//    kvp->put_date = -1;
//    kvp->expiration_date = expiration_date;
//    
//    kvp->val->header_size = header_size;
//    kvp->val->content_len = buf_size - header_size;
//    kvp->val->object = malloc(buf_size);
//    memcpy(kvp->val->object, buf, buf_size);
//
//    return kvp;
//}

Cache_T Cache_new(int capacity)
{
    // calculate & allocate correct memory for cache
    Cache_T cache = malloc(sizeof(struct Cache_T));
    cache->capacity = capacity;
    // Each KV pair will be malloc'd as it is created
    cache->kv_pairs = calloc((size_t)capacity, sizeof(KV_Pair_T));

    return cache;
}

void Cache_free(Cache_T cache)
{
    int capacity = cache->capacity;
    for (int i = 0; i < capacity; i++) {
        check_and_free((cache->kv_pairs[i])->val->object);
        check_and_free((cache->kv_pairs[i])->val);
        check_and_free(cache->kv_pairs[i]);
    }
    check_and_free(cache->kv_pairs);
    check_and_free(cache);
}

void Cache_put(Cache_T cache, KV_Pair_T kv)
{
    int capacity = cache->capacity;
    KV_Pair_T *kvps = cache->kv_pairs;
    int free_space_index = -1;
    //First check for matching kvpair
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && kvps[i]->hash_val == kv->hash_val) {
            int old_priority = kvps[i]->priority;
            // free mem of old kvp
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            // make sure new priority is 1
            kv->priority = 1;
            // insert new kv-pair
            kvps[i] = kv;
            // increment all other priorities that used to be in front
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
                    if (kvps[j]->priority < old_priority)
                        kvps[j]->priority += 1;
            return;
        }
        //save 1st NULL pointer we come to to possibly save time
        else if (kvps[i] == NULL && free_space_index == -1) 
            free_space_index = i;
    }
    //Otherwise, check for free space in table
    if (free_space_index != -1) {
        kv->priority = 1;
        kvps[free_space_index] = kv;
        for (int j = 0; j < capacity; j++)
            //increment all others no matter what
            if (kvps[j] != NULL && j != free_space_index)
                kvps[j]->priority += 1;
        cache->curr_size++;
        return;
    }
    //else, we have to kick out stale or least recently requested item and
    // then use that space
    int least_recently_requested = -1;
    time_t curr_time = time(NULL);
    for (int i = 0; i < capacity; i++) {
        //check stale
        if (curr_time > kvps[i]->expiration_date) {
#if DEBUG
	    fprintf(stderr, "stale\n");
#endif
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            kv->priority = 1;
            kvps[i] = kv;
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
                    kvps[j]->priority += 1;
            return;
        }
        //save oldest request index in case none are stale
        else if (kvps[i]->priority == capacity)
            least_recently_requested = i;
    }
    if (least_recently_requested == -1) {
        fprintf(stderr, "Error: cannot remove oldest request because of"
                        " a priorities issue.\n");
        exit(EXIT_FAILURE);
    }
    //if reached this point, we have the index of oldest request. replace it
    // with the new kv pair & return
    free(kvps[least_recently_requested]->val->object);
    free(kvps[least_recently_requested]->val);
    free(kvps[least_recently_requested]);
    kv->priority = 1;
    kvps[least_recently_requested] = kv;
    //increment all other priorities
    for (int j = 0; j < capacity; j++)
        //if (kvps[j] != NULL && kvps[j]->hash_val != kv->hash_val)
        if (kvps[j] != NULL && j != least_recently_requested)
            kvps[j]->priority += 1;
    return;
}

/* Reports a value DNE (or stale) by returning NULL */
KV_Pair_T Cache_get(Cache_T cache, unsigned long key_hash)
{
    KV_Pair_T *kvps = cache->kv_pairs;
    int capacity = cache->capacity;
    time_t curr_time = time(NULL);
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && key_hash == (kvps[i])->hash_val) {
            //If stale, remove from cache & report DNE
            if (curr_time > kvps[i]->expiration_date) {
                Cache_remove(cache, key_hash);
                return NULL;
            }
            //else not stale -> update priorities & return corresponding value
            int old_priority = kvps[i]->priority;
            kvps[i]->priority = 1;
            for (int j = 0; j < capacity; j++)
                if (kvps[j] != NULL && key_hash != (kvps[j])->hash_val)
                    if (kvps[j]->priority < old_priority)
                        kvps[j]->priority += 1;
            return kvps[i];
        }
    }
    //If we reached this point, key doesn't exist in cache
    return NULL; 
}

// Removes from cache and decrements necessary priorities of other kvps
void Cache_remove(Cache_T cache, unsigned long key_hash)
{
    KV_Pair_T *kvps = cache->kv_pairs;
    int capacity = cache->capacity;
    //find corresponding key-val pair in cache
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL && key_hash == (kvps[i])->hash_val) {
            int prio = kvps[i]->priority;
            free(kvps[i]->val->object);
            free(kvps[i]->val);
            free(kvps[i]);
            kvps[i] = NULL;
            //decrease priority values of all other kvps in cache that had a
            //"worse" priority, aka move them up in the queue
            for (int j = 0; j < capacity; j++) {
                if (kvps[j] != NULL && kvps[j]->priority > prio) {
                    kvps[j]->priority -= 1;
                }
            }
            cache->curr_size -= 1;
            return;
        }
    }
    fprintf(stderr, "Error: Could not remove key with hash %lu from table "
                    "because key did not exist\n", key_hash);
}

void Cache_print(Cache_T cache)
{
    printf("******* PRINTING CACHE STATE **********\n");
    int capacity = cache->capacity;
    time_t now = time(NULL);
    printf("TIME NOW: %s\n", asctime(localtime(&now)));
    printf("capacity: %d\ncurr_size: %d\n", capacity, cache->curr_size);
    KV_Pair_T *kvps = cache->kv_pairs;
    for (int i = 0; i < capacity; i++) {
        if (kvps[i] != NULL) {
            printf(" _____________________________\n"
                   "|expires: %s prio: %d, hash: %lu |\n"
                   "------------------------------\n"
                   "|val: %s |\n",
                    asctime(localtime(&(kvps[i]->expiration_date))),
                    kvps[i]->priority, kvps[i]->hash_val,
                    (char *)kvps[i]->val->object);
        }
    }
    printf("***********************************************************\n\n\n");
}

//TODO remove
//// Routes to either parse_response or parse_request
//void parse_message(char *buf, int size)
//{
//    if (strncmp(buf, "GET", 3) == 0)
//    {
//        parse_request(buf, size);
//    }
//    else if (strncmp(buf, "HTTP", 4) == 0)
//    {
//        parse_response(buf, size);
//    }
//    else {
//        fprintf(stderr, "Could not parse msg %s\n", buf);
//        exit(-1);
//    }
//}

/* Loop iteration for parsing an HTTP request OR response from socket. To be
 * called until *done == true, to ensure that all content has been read and put
 * into *buf.
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
void http_receive_loop(int childfd, char **buf, char *c, int *n_read,
                        int *total_bytes_read, int *curr_bufsize,
                        int *prev_newline_index, int *content_length,
                        int *num_header_bytes, bool *done,
                        bool *content_present)
{
    //Read a byte from stream
//#if TRACE
//    printf("about to httpread\n");
//#endif
    *n_read = read(childfd, (*buf)+(*total_bytes_read), 1);
//#if TRACE
//    printf("done httpread\n");
//#endif
    *total_bytes_read += *n_read; 
    *c = (*buf)[(*total_bytes_read)-1];
    //TODO error recovery
    if (*n_read < 0) 
        error("ERROR reading from socket");
    if (*n_read == 0) {
        *done = true;
        return;
    }
//#if TRACE
//    printf("server received %d bytes, last byte received: %x,"
//        "curr buffer: %s\n", *n_read, (*buf)[*total_bytes_read-1], *buf);
//    printf("curr_bufsize: %d, total_bytes_read: %d\n\n", *curr_bufsize, *total_bytes_read);
//    printf("content_present: %d, content_length: %d, header: %d\n", *content_present, *content_length, *num_header_bytes);
//#endif
    // May need to expand buffer if especially long GET request
    if (*total_bytes_read == *curr_bufsize) {
        *curr_bufsize = 2*(*curr_bufsize);
        *buf = realloc(*buf, *curr_bufsize);
    }
    if (*c == '\n') {
        //check if we have run into 2 CRLFs in a row --> indicates end of header
        int i = *total_bytes_read - 1;
        if (((*buf)[i-3] == '\r' && (*buf)[i-2] == '\n') && (*buf)[i-1] == '\r') {
            if (!(*content_present)) {
                // 2 CRLFs + no content --> done reading
                *done = true;
                return;
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
        //TODO remove this and others above
//#if TRACE
//        printf("Looked for Content-Length in: %s\n",(*buf)+(*prev_newline_index)+1);
//#endif
        *prev_newline_index = *total_bytes_read-1;
    }
    if (*total_bytes_read == *num_header_bytes + *content_length &&
            *num_header_bytes != 0) //extra check, in case v long header
        *done = true;
}

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
