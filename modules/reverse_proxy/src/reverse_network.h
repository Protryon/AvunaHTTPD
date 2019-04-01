//
// Created by p on 3/31/19.
//

#ifndef AVUNA_HTTPD_REVERSE_NETWORK_H
#define AVUNA_HTTPD_REVERSE_NETWORK_H


#include <avuna/queue.h>
#include <avuna/http.h>
#include <stdint.h>
#include <stdlib.h>

struct http_client_extra {
    struct queue* forwarding_sessions;
    struct request_session* currently_forwarding;
};

void http_client_on_closed(struct sub_conn* sub_conn);

int handle_http_client_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);

#endif //AVUNA_HTTPD_REVERSE_NETWORK_H
