//
// Created by p on 2/10/19.
//

#ifndef AVUNA_HTTPD_HTTP_PIPELINE_H
#define AVUNA_HTTPD_HTTP_PIPELINE_H

#include "vhost.h"
#include "work.h"

void generateDefaultErrorPage(struct request_session* rs, struct vhost* vh, const char* msg);

int generateResponse(struct request_session* rs);


#endif //AVUNA_HTTPD_HTTP_PIPELINE_H