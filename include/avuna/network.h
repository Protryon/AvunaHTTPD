//
// Created by p on 3/31/19.
//

#ifndef AVUNA_HTTPD_NETWORK_H
#define AVUNA_HTTPD_NETWORK_H

#include <avuna/http.h>
#include <time.h>

void send_request_session(struct request_session* rs, struct timespec* start);

#endif //AVUNA_HTTPD_NETWORK_H
