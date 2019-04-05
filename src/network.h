/*
 * work.h
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#ifndef WORK_H_
#define WORK_H_

#include <avuna/server.h>
#include <avuna/connection.h>
#include <avuna/queue.h>
#include <avuna/http.h>
#include <stdlib.h>

struct work_param {
    size_t i;
    struct server_info* server;
    int pipes[2];
};

struct http_server_extra {
    struct request_session* currently_posting;
    int skip_generate_response;
    struct request_session* currently_streaming;
};

void http_on_closed(struct sub_conn* sub_conn);

int handle_http_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len);

void run_work(struct work_param* param);

#endif /* WORK_H_ */
