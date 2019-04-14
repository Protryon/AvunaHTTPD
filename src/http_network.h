//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HTTP_NETWORK_H
#define AVUNA_HTTPD_HTTP_NETWORK_H

#include <avuna/http.h>
#include <avuna/provider.h>
#include <avuna/connection.h>
#include <stdint.h>
#include <time.h>

struct http_server_extra {
    struct request_session* currently_posting;
    int skip_generate_response;
    struct request_session* currently_streaming;
};

void log_request_session(struct request_session* rs, struct timespec* start);

void determine_vhost(struct request_session* rs, char* authority);

void http_on_closed(struct sub_conn* sub_conn);

int handle_http_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);

int http_stream_notify(struct request_session* rs);

#endif //AVUNA_HTTPD_HTTP_NETWORK_H
