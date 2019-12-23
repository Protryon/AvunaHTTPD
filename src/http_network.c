//
// Created by p on 4/6/19.
//

#include "http_network.h"
#include "http_pipeline.h"
#include <avuna/http_util.h>
#include <avuna/vhost.h>
#include <avuna/http.h>
#include <avuna/pmem.h>
#include <avuna/connection.h>
#include <avuna/provider.h>
#include <avuna/globals.h>
#include <avuna/network.h>
#include <avuna/module.h>
#include <avuna/util.h>
#include <errno.h>
#include <arpa/inet.h>

void log_request_session(struct request_session* rs, struct timespec* start) {
    struct timespec stt2;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt2);
    double msp =
        (stt2.tv_nsec / 1000000.0 + stt2.tv_sec * 1000.0) - (start->tv_nsec / 1000000.0 + start->tv_sec * 1000.0);
    const char* mip = NULL;
    char tip[48];
    if (rs->conn->addr.tcp6.sin6_family == AF_INET) {
        struct sockaddr_in* sip4 = &rs->conn->addr.tcp4;
        mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
    } else if (rs->conn->addr.tcp6.sin6_family == AF_INET6) {
        struct sockaddr_in6* sip6 = &rs->conn->addr.tcp6;
        if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) &&
            memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
            mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
        } else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
    } else if (rs->conn->addr.tcp6.sin6_family == AF_LOCAL) {
        mip = "UNIX";
    } else {
        mip = "UNKNOWN";
    }
    if (mip == NULL) {
        errlog(rs->conn->server->logsess, "Invalid IP Address: %s", strerror(errno));
    }
    acclog(rs->conn->server->logsess, "%s %s %s/%s%s returned %s took: %f ms", mip, rs->request->method,
           rs->conn->server->id, rs->vhost->name, rs->request->path, rs->response->code, msp);
}


void send_request_session_http11(struct request_session* rs, struct timespec* start) {
    size_t response_length = 0;
    unsigned char* serialized_response = serializeResponse(rs, &response_length);
    log_request_session(rs, start);
    buffer_push(&rs->src_conn->write_buffer, serialized_response, response_length);
    trigger_write(rs->src_conn);
    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_request_completed) {
            module->events.on_request_completed(module, rs);
        }
        ITER_LLIST_END();
    }
}

void determine_vhost(struct request_session* rs, char* authority) {
    if (authority == NULL) authority = "";
    struct vhost* vhost = NULL;
    for (size_t i = 0; i < rs->conn->server->vhosts->count; i++) {
        struct vhost* iter_vhost = rs->conn->server->vhosts->data[i];
        if (iter_vhost->hosts->count == 0) {
            vhost = iter_vhost;
            break;
        } else
            for (size_t x = 0; x < iter_vhost->hosts->count; x++) {
                if (domeq(iter_vhost->hosts->data[x], authority)) {
                    vhost = iter_vhost;
                    break;
                }
            }
        if (vhost != NULL) break;
    }
    rs->vhost = vhost;
}

void http_on_closed(struct sub_conn* sub_conn) {
    pfree(sub_conn->conn->pool);
}

int http_stream_notify(struct request_session* rs) {
    struct http_server_extra* extra = rs->src_conn->extra;
    struct provision* provision = rs->response->body;
    struct provision_data data;
    data.data = NULL;
    data.size = 0;
    ssize_t total_read = provision->data.stream.read(provision, &data);
    if (total_read == -1) {
        pfree(rs->pool);
        extra->currently_streaming = NULL;
        // backend server failed during stream
    } else if (total_read == 0) {
        // end of stream
        if (data.size > 0) {
            pxfer(provision->pool, rs->src_conn->pool, data.data);
            buffer_push(&rs->src_conn->write_buffer, data.data, data.size);
            trigger_write(rs->src_conn);
        }
        pfree(rs->pool);
        extra->currently_streaming = NULL;
    } else if (total_read == -2) {
        // nothing to read, not end of stream
        return 0;
    } else {
        pxfer(provision->pool, rs->src_conn->pool, data.data);
        buffer_push(&rs->src_conn->write_buffer, data.data, data.size);
        trigger_write(rs->src_conn);
        return 0;
    }
    return 1;
}


int handle_http_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    struct http_server_extra* extra = sub_conn->extra;
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    restart:;

    // active post reading
    if (extra->currently_posting != NULL) {
        struct provision* provision = extra->currently_posting->request->body;
        if (provision->type == PROVISION_DATA && sub_conn->read_buffer.size >= provision->data.data.size) {
            struct timespec stt;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);
            pxfer(provision->pool, sub_conn->pool, provision->data.data.data);
            buffer_pop(&sub_conn->read_buffer, provision->data.data.size, provision->data.data.data);
            ITER_LLIST(loaded_modules, value) {
                struct module* module = value;
                if (module->events.on_request_post_received && module->events.on_request_post_received(module, extra->currently_posting)) {
                    return 1;
                }
                ITER_LLIST_END();
            }
            if (!extra->skip_generate_response) {
                generateResponse(extra->currently_posting);
            }
            if (extra->currently_posting->response->body != NULL && extra->currently_posting->response->body->type == PROVISION_STREAM) {
                extra->currently_streaming = extra->currently_posting;
                if (extra->currently_posting->response->body->data.stream.delay_header_output) {
                    memcpy(&extra->currently_posting->response->body->data.stream.delayed_start, &stt, sizeof(struct timespec));
                    extra->currently_posting->response->body->data.stream.delay_finish = send_request_session_http11;
                } else {
                    send_request_session_http11(extra->currently_posting, &stt);
                }
                extra->currently_posting = NULL;
                goto restart;
            } else {
                send_request_session_http11(extra->currently_posting, &stt);
                pfree(extra->currently_posting->pool);
                extra->currently_posting = NULL;
            }
        } else { // PROVISION_STREAM
            errlog(delog, "Invalid state! STREAM found during active post read");
            return 0;
        }
    }

    if (extra->currently_streaming != NULL) {
        return 0;
    }

    //TODO: while the HTTP spec doesn't allow \n, we should probably accept it similar to other implementations
    size_t match_length = 0;
    static unsigned char newlines[4] = {0x0D, 0x0A, 0x0D, 0x0A};

    // shrink read_buf if it was part header
    if (sub_conn->read_buffer.size < read_buf_len) {
        size_t shrink = read_buf_len - sub_conn->read_buffer.size;
        read_buf += shrink;
        read_buf_len -= shrink;
    }

    if (read_buf_len == 0) {
        return 0;
    }

    // prepare match_length from previous buffer
    struct llist_node* read_tail = sub_conn->read_buffer.buffers->tail;
    if (read_tail != NULL) {
        struct buffer_entry* entry = read_tail->data;
        if (entry->data == read_buf) {
            if (read_tail->prev == NULL) { // could be popped above
                goto post_precheck;
            }
            entry = read_tail->prev->data;
        }
        ssize_t checking_index = entry->size - 3;
        if (checking_index < 0)
            checking_index = 0;
        for (; checking_index < entry->size; ++checking_index) {
            char c = ((char*) entry->data)[checking_index];
            if (c == newlines[match_length]) {
                match_length++;
                if (match_length == 4) {
                    errlog(sub_conn->conn->server->logsess, "Invalid state! This should never happen.");
                }
            } else if (c == newlines[0]) {
                match_length = 1;
            } else {
                match_length = 0;
            }
        }
    }
    post_precheck:;

    // match double newline
    for (size_t checking_index = 0; checking_index < read_buf_len; ++checking_index) {
        char c = read_buf[checking_index];
        if (c == newlines[match_length]) {
            match_length++;
            if (match_length != 4) {
                continue;
            }
            struct mempool* req_pool = mempool_new();
            pchild(sub_conn->pool, req_pool);
            size_t req_size = sub_conn->read_buffer.size + checking_index + 1 - read_buf_len;
            unsigned char* request_headers = pmalloc(req_pool, req_size + 1);
            buffer_pop(&sub_conn->read_buffer, req_size, request_headers);
            request_headers[req_size] = 0;

            struct timespec stt;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);

            struct request_session* rs = pcalloc(req_pool, sizeof(struct request_session));
            rs->conn = sub_conn->conn;
            rs->src_conn = sub_conn;
            rs->request = pcalloc(req_pool, sizeof(struct request));
            rs->pool = req_pool;
            if (parseRequest(rs, (char*) request_headers, sub_conn->conn->server->max_post) < 0) {
                errlog(sub_conn->conn->server->logsess, "Malformed Request!\n%s", request_headers);
                return 1;
            }
            rs->response = pcalloc(rs->pool, sizeof(struct response));
            rs->response->headers = header_new(rs->pool);
            rs->response->http_version = "HTTP/1.1";
            rs->response->code = "200 OK";
            int skip_generate_response = 0;
            ITER_LLIST(loaded_modules, value) {
                struct module* module = value;
                if (module->events.on_request_received) {
                    int status = module->events.on_request_received(module, rs);
                    if (status == 1) {
                        skip_generate_response = 1;
                        break;
                    } else if (status == -1) {
                        return 1;
                    }
                }
                ITER_LLIST_END();
            }
            determine_vhost(rs, header_get(rs->request->headers, "Host"));
            ITER_LLIST(loaded_modules, value) {
                struct module* module = value;
                if (module->events.on_request_vhost_resolved) {
                    rs->vhost = module->events.on_request_vhost_resolved(module, rs, rs->vhost);
                }
                ITER_LLIST_END();
            }
            if (rs->request->body != NULL && rs->request->body->type == PROVISION_DATA) {
                extra->currently_posting = rs;
                extra->skip_generate_response = skip_generate_response;
                goto restart;
            }
            if (!skip_generate_response) {
                generateResponse(rs);
            }
            if (rs->response->body != NULL && rs->response->body->type == PROVISION_STREAM) {
                extra->currently_streaming = rs;
                if (rs->response->body->data.stream.delay_header_output) {
                    memcpy(&rs->response->body->data.stream.delayed_start, &stt, sizeof(struct timespec));
                    rs->response->body->data.stream.delay_finish = send_request_session_http11;
                } else {
                    send_request_session_http11(rs, &stt);
                }
                goto restart;
            } else {
                send_request_session_http11(rs, &stt);
                pfree(req_pool);
            }
        } else if (c == newlines[0])
            match_length = 1;
        else
            match_length = 0;
    }
    return 0;
}