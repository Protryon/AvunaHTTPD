//
// Created by p on 3/30/19.
//

#ifndef AVUNA_HTTPD_UTIL_H
#define AVUNA_HTTPD_UTIL_H

#include <avuna/pmem.h>
#include <avuna/http.h>
#include <avuna/config.h>

#define HTBASE(vh) ((struct vhost_htbase*) (vh)->sub->extra)

void generateDefaultErrorPage(struct request_session* rs, const char* msg);

int check_cache(struct request_session* rs);

void check_client_cache(struct request_session* rs);

#endif //AVUNA_HTTPD_UTIL_H
