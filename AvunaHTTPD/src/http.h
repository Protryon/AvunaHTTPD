/*
 * http.h
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

#include <stdlib.h>
#include "accept.h"

#ifndef HTTP_H_
#define HTTP_H_

#define METHOD_UNK -1
#define METHOD_GET 0
#define METHOD_POST 1
#define METHOD_HEAD 2

struct headers {
		int count;
		char** names;
		char** values;
};

const char* header_get(const struct headers* headers, const char* name);

int header_set(struct headers* headers, const char* name, const char* value);

int header_add(struct headers* headers, const char* name, const char* value);

int parseHeaders(struct headers* headers, char* data);
char* serializeHeaders(struct headers* headers, size_t* len);

void freeHeaders(struct headers* headers);

struct body {
		char* mime_type;
		size_t len;
		unsigned char* data;
};

struct request {
		int method;
		char* path;
		char* version;
		struct headers headers;
		struct body* body; // may be NULL
};

int parseRequest(struct request* request, char* data);
unsigned char* serializeRequest(struct request* request, size_t* len);

struct response {
		char* version;
		char* code;
		struct headers headers;
		struct body* body; // may be NULL
};

int parseResponse(struct response* response, char* data);
unsigned char* serializeResponse(struct response* response, size_t* len);

int generateResponse(struct conn* sender, struct response* response, struct request* request);

#endif /* HTTP_H_ */
