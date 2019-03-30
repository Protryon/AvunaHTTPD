/*
 * http.h
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */


#ifndef HTTP_H_
#define HTTP_H_

#include <stdlib.h>
#include <avuna/http.h>

int parseRequest(struct request_session* rs, char* data, size_t maxPost);

unsigned char* serializeRequest(struct request_session* rs, size_t* len);

int parseResponse(struct request_session* rs, char* data);

unsigned char* serializeResponse(struct request_session* rs, size_t* len);


#endif /* HTTP_H_ */
