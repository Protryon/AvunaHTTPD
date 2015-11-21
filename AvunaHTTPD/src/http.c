/*
 * http.c
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

#include "http.h"
#include "util.h"

int parseHeaders(struct headers* headers, unsigned char* data) {

	xfree(data);
	return 0;
}

unsigned char* serializeHeaders(struct headers* headers, ssize_t* len) {

}

int parseRequest(struct request* request, unsigned char* data) {

	xfree(data);
	return 0;
}

unsigned char* serializeRequest(struct request* request, ssize_t* len) {

}

int parseResponse(struct response* response, unsigned char* data) {

	xfree(data);
	return 0;
}

unsigned char* serializeResponse(struct response* response, ssize_t* len) {

}

int generateResponse(struct conn* sender, struct response* response, struct request* request) {

	return 0;
}
