//
// Created by p on 3/31/19.
//

#include "reverse_network.h"
#include <avuna/buffer.h>
#include <avuna/http.h>
#include <avuna/connection.h>
#include <avuna/network.h>
#include <stdint.h>
#include <stdlib.h>

void http_client_on_closed(struct sub_conn* sub_conn) {
    pfree(sub_conn->conn->pool);
}


int handle_http_client_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    struct http_client_extra* extra = sub_conn->extra;
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    restart:;

    if (extra->currently_forwarding != NULL) {
        struct provision* provision = extra->currently_forwarding->response->body;
        struct provision_data data;
        data.data = NULL;
        data.size = 0;
        ssize_t total_read = provision->data.stream.read(provision, &data);
        if (total_read == -1) {
            // backend server failed during stream
            pfree(extra->currently_forwarding->pool);
            return 0;
        } else if (total_read == 0) {
            // end of stream
            queue_pop(extra->forwarding_sessions);
            pfree(extra->currently_forwarding->pool);
        } else if (total_read == -2) {
            // nothing to read, not end of stream
        } else {
            pxfer(provision->pool, extra->currently_forwarding->src_conn->pool, data.data);
            buffer_push(&extra->currently_forwarding->src_conn->write_buffer, data.data, data.size);
            return 0;
        }
    }

    /*
    if (ct == 1 && conn->stream_type >= 0) {
        int se = 0;
        if (conn->stream_type == STREAM_TYPE_RAW) {
            if (conn->forwarding_request->response->fromCache != NULL) {
                if (conn->stream_md5 == NULL) {
                    conn->stream_md5 = pmalloc(sub_conn->pool, sizeof(MD5_CTX));
                    MD5_Init(conn->stream_md5);
                }
                ITER_LLIST(sub_conn->read_buffer.buffers, value)
                    {
                        struct buffer_entry* entry = value;
                        MD5_Update(conn->stream_md5, entry->data, entry->size);
                    ITER_LLIST_END();
                }
            }

            uint8_t* total_read = pmalloc(conn->forwarding_request->pool, sub_conn->read_buffer.size);
            size_t read_size = buffer_pop(&sub_conn->read_buffer, sub_conn->read_buffer.size, total_read);

            if (conn->forwarding_request->request->add_to_cache) {
                buffer_push(&conn->cache_buffer, total_read, read_size);
            }
            buffer_push(&sub_conn->write_buffer, total_read, read_size);

            conn->streamed += sub_conn->read_buffer.size;
            if (conn->streamed >= conn->stream_len) {
                struct response* fwd_response = conn->forwarding_request->response;
                if (conn->forwarding_request->request->add_to_cache) {
                    struct vhost* vhost = conn->forwarding_request->request->vhost;
                    const char* content_type = header_get(fwd_response->headers, "Content-Type");
                    int is_dynamic_type = hashset_has(
                        conn->forwarding_request->request->vhost->sub.rproxy.dynamic_types, content_type);

                    if (!is_dynamic_type) {
                        conn->forwarding_request->request->add_to_cache = 1;
                        struct scache* new_scache = pmalloc(vhost->pool, sizeof(struct scache));
                        if (fwd_response->body == NULL) {
                            fwd_response->body = pmalloc(sub_conn->pool, sizeof(struct body));
                        }
                        fwd_response->body->data = pmalloc(conn->forwarding_request->pool, conn->cache_buffer.size);
                        fwd_response->body->len = buffer_pop(&conn->cache_buffer, conn->cache_buffer.size,
                                                             fwd_response->body->data);
                        fwd_response->body->stream_type = STREAM_TYPE_INVALID;
                        fwd_response->body->stream_fd = -1;
                        fwd_response->body->mime_type = content_type;
                        new_scache->content_encoding = header_get(fwd_response->headers, "Content-Encoding") != NULL;
                        new_scache->code = fwd_response->code;
                        new_scache->headers = fwd_response->headers;
                        new_scache->request_path = conn->forwarding_request->request->path;
                        if (fwd_response->body == NULL) {
                            new_scache->etag[0] = '\"';
                            memset(new_scache->etag + 1, '0', 32);
                            new_scache->etag[33] = '\"';
                            new_scache->etag[34] = 0;
                        } else {
                            MD5_CTX md5ctx;
                            MD5_Init(&md5ctx);
                            MD5_Update(&md5ctx, fwd_response->body->data, fwd_response->body->len);
                            unsigned char rawmd5[16];
                            MD5_Final(rawmd5, &md5ctx);
                            new_scache->etag[34] = 0;
                            new_scache->etag[0] = '\"';
                            for (int i = 0; i < 16; i++) {
                                snprintf(new_scache->etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
                            }
                            new_scache->etag[33] = '\"';
                        }
                        header_setoradd(fwd_response->headers, "ETag", new_scache->etag);
                        cache_add(conn->forwarding_request->request->vhost->sub.rproxy.cache, new_scache);
                        fwd_response->fromCache = new_scache;
                    } else {
                        conn->forwarding_request->request->add_to_cache = 0;
                    }
                }
                if (conn->stream_md5 != NULL) {
                    unsigned char rawmd5[16];
                    MD5_Final(rawmd5, conn->stream_md5);
                    conn->stream_md5 = NULL;
                    for (int i = 0; i < 16; i++) {
                        snprintf(fwd_response->fromCache->etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
                    }
                    header_setoradd(fwd_response->fromCache->headers, "ETag", fwd_response->fromCache->etag);
                }
                conn->stream_type = STREAM_TYPE_INVALID;
                conn->streamed = 0;
                queue_pop(conn->fw_queue);
                se = 1;
            }
        } else if (conn->stream_type == STREAM_TYPE_CHUNKED) { // chunked already

        }
        if (!se) goto pc;
    }*/

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
            } else if (c == newlines[0])
                match_length = 1;
            else
                match_length = 0;
        }
    }
    post_precheck:;

    // match double new line
    for (size_t checking_index = 0; checking_index < read_buf_len; ++checking_index) {
        char c = read_buf[checking_index];
        if (c == newlines[match_length]) {
            match_length++;
            if (match_length == 4) {
                struct request_session* rs = queue_peek(extra->forwarding_sessions);
                size_t req_size = sub_conn->read_buffer.size + checking_index + 1 - read_buf_len;
                unsigned char* request_headers = pmalloc(rs->pool, req_size + 1);
                buffer_pop(&sub_conn->read_buffer, req_size, request_headers);
                request_headers[req_size] = 0;

                struct timespec stt;
                clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);

                if (parseResponse(rs, sub_conn, (char*) request_headers) < 0) {
                    errlog(sub_conn->conn->server->logsess, "Malformed Response!");
                    sub_conn->on_closed(sub_conn);
                    return 1;
                }
                if (rs->response->body != NULL) {
                    rs->response->body->content_type = (char*) header_get(rs->response->headers, "Content-Type");
                }
                send_request_session(rs, &stt);
                if (rs->response->body != NULL) {
                    if (rs->response->body->type == PROVISION_DATA) {
                        pxfer(rs->response->body->pool, sub_conn->pool, rs->response->body->data.data.data);
                        buffer_push(&rs->src_conn->write_buffer, rs->response->body->data.data.data, rs->response->body->data.data.size);
                    } else {
                        extra->currently_forwarding = rs;
                        goto restart;
                    }
                }
                queue_pop(extra->forwarding_sessions);
                pfree(rs->pool);
            }
        } else if (c == newlines[0]) {
            match_length = 1;
        } else {
            match_length = 0;
        }
    }
    return 0;
}