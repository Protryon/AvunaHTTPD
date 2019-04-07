//
// Created by p on 4/6/19.
//

#ifndef AVUNA_HTTPD_HTTP_NETWORK_H
#define AVUNA_HTTPD_HTTP_NETWORK_H

#include <avuna/http.h>
#include <avuna/connection.h>
#include <stdint.h>

struct http_server_extra {
    struct request_session* currently_posting;
    int skip_generate_response;
    struct request_session* currently_streaming;
};

void http_on_closed(struct sub_conn* sub_conn);

int handle_http_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);


#endif //AVUNA_HTTPD_HTTP_NETWORK_H
