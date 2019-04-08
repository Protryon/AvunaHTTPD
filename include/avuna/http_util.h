/*
 * util.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <avuna/pmem.h>
#include <avuna/http.h>
#include <sys/stat.h>
#include <stdlib.h>

char* escapehtml(struct mempool* pool, const char* orig);

void generateBaseErrorPage(struct request_session* rs, const char* msg);

char* config_get_default(struct config_node* node, char* key, char* def);

#endif /* UTIL_H_ */
