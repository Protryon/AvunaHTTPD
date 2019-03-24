/*
 * http.h
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */


#ifndef HTTP_H_
#define HTTP_H_

#include <stdlib.h>
#include "accept.h"
#include "pmem.h"
#include "headers.h"

#define METHOD_UNK -1
#define METHOD_GET 0
#define METHOD_POST 1
#define METHOD_HEAD 2

const char* getMethod(int m);

struct request_session {
		struct work_param* wp;
		struct conn* sender;
		struct response* response;
		struct request* request;
		struct mempool* pool;
};

struct body {
		char* mime_type;
		size_t len;
		unsigned char* data;
		int stream_fd;
		int stream_type;
};

struct request {
		int method;
		char* path;
		char* version;
		struct headers* headers;
		struct body* body; // may be NULL
		int atc;
		struct vhost* vhost;
};

int parseRequest(struct request_session *rs, char *data, size_t maxPost);

unsigned char* serializeRequest(struct request_session* rs, size_t* len);

struct response {
		char* version;
		char* code;
		struct headers* headers;
		struct body* body; // may be NULL
		int parsed;
		struct scache* fromCache;
};

int parseResponse(struct request_session* rs, char* data);

unsigned char* serializeResponse(struct request_session* rs, size_t* len);


#endif /* HTTP_H_ */
