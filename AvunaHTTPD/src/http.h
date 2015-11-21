/*
 * http.h
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

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

int parseHeaders(struct headers* headers, unsigned char* data);
unsigned char* serializeHeaders(struct headers* headers, ssize_t* len);

struct body {
		char* mime_type;
		ssize_t len;
		unsigned char* data;
};

struct request {
		int method;
		char* path;
		char* version;
		struct headers headers;
		struct body* body; // may be NULL
};

int parseRequest(struct request* request, unsigned char* data);
unsigned char* serializeRequest(struct request* request, ssize_t* len);

struct response {
		char* version;
		struct response_code *rcode;
		struct headers headers;
		struct body* body; // may be NULL
};

int parseResponse(struct response* response, unsigned char* data);
unsigned char* serializeResponse(struct response* response, ssize_t* len);

int generateResponse(struct conn* sender, struct response* response, struct request* request);

#endif /* HTTP_H_ */
