//
// Created by p on 2/10/19.
//

#ifndef AVUNA_HTTPD_HTTP_PIPELINE_H
#define AVUNA_HTTPD_HTTP_PIPELINE_H

#include <avuna/http.h>

int domeq(const char* dom1, const char* dom2);

int generateResponse(struct request_session* rs);

#endif //AVUNA_HTTPD_HTTP_PIPELINE_H
