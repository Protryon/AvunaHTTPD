//
// Created by p on 3/30/19.
//

#ifndef AVUNA_HTTPD_GZIP_H
#define AVUNA_HTTPD_GZIP_H

#include <avuna/provider.h>
#include <avuna/http.h>
#include <stdlib.h>

ssize_t gzip_stream_read(struct provision* provision, struct provision_data* buffer);

int should_gzip(struct request_session* rs);

int gzip_total(struct request_session* rs);

int init_gzip_stream(struct request_session* rs, struct provision* parent, struct provision* provision);


#endif //AVUNA_HTTPD_GZIP_H
