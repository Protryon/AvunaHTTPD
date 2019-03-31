//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_HTTP_H
#define AVUNA_HTTPD_HTTP_H

#include <avuna/pmem.h>
#include <avuna/headers.h>
#include <avuna/vhost.h>
#include <avuna/provider.h>
#include <avuna/server.h>
#include <avuna/cache.h>
#include <avuna/connection.h>

// perhaps a data attachment system?

struct request {
    char* method;
    char* path;
    char* http_version;
    struct headers* headers;
    struct provision* body; // may be NULL
    int add_to_cache; // todo: remove
};


struct response {
    char* http_version;
    char* code;
    struct headers* headers;
    struct provision* body; // may be NULL
    int parsed; // todo: remove
    struct scache* fromCache; // todo: remove
};


struct request_session {
    struct conn* conn;
    struct response* response;
    struct request* request;
    char* request_htpath;
    char* request_extra_path;
    struct vhost* vhost;
    struct mempool* pool;
};


int parseRequest(struct request_session* rs, char* data, size_t maxPost);

unsigned char* serializeRequest(struct request_session* rs, size_t* len);

int parseResponse(struct request_session* rs, char* data);

unsigned char* serializeResponse(struct request_session* rs, size_t* len);


#endif //AVUNA_HTTPD_HTTP_H
