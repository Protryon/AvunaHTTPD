//
// Created by p on 4/6/19.
//

#include "http2_pipeline.h"
#include "http_pipeline.h"
#include "http2_network.h"
#include "http_network.h"
#include <avuna/connection.h>
#include <avuna/hpack.h>
#include <avuna/headers.h>
#include <avuna/http2.h>
#include <avuna/http.h>
#include <avuna/network.h>
#include <avuna/string.h>
#include <avuna/module.h>
#include <avuna/provider.h>

void send_request_session_http2(struct request_session* rs, struct timespec* start) {
    struct http2_server_extra* extra = rs->src_conn->extra;
    size_t header_length = 0;
    char* status = str_dup(rs->response->code, 0, rs->pool);
    char* status_space = strchr(status, ' ');
    if (status_space != NULL) {
        status_space[0] = 0;
    }
    header_prepend(rs->response->headers, ":status", status);
    header_del(rs->response->headers, "connection");
    header_del(rs->response->headers, "transfer-encoding");
    struct http2_stream* stream = rs->extra;
    uint8_t* headers = hpack_encode(extra->recv_hpack_ctx, rs->pool, rs->response->headers, &header_length);

    log_request_session(rs, start);
    size_t max_frame_size = extra->other_max_frame_size - 32;
    struct frame* header_frame = http2_make_frame(rs->pool, FRAME_HEADERS_ID);
    header_frame->stream_id = stream->identifier;
    uint8_t header_finish_flags = 0;
    header_finish_flags |= 0x4;
    if (rs->response->body->type == PROVISION_DATA && rs->response->body->data.data.size == 0) {
        header_finish_flags |= 0x1;
    }
    header_frame->data.headers.data_length = header_length > max_frame_size ? max_frame_size : header_length;
    header_frame->data.headers.data = headers;
    if (header_length > max_frame_size) {
        header_length -= max_frame_size;
        headers += max_frame_size;
    } else {
        header_frame->flags = header_finish_flags;
        header_length = 0;
        headers = NULL;
    }
    http2_send_frame(rs->src_conn, header_frame);

    while (header_length > 0) {
        struct frame* continuation = http2_make_frame(rs->pool, FRAME_CONTINUATION_ID);
        continuation->stream_id = stream->identifier;
        continuation->data.continuation.data_length = header_length > max_frame_size ? max_frame_size : header_length;
        continuation->data.continuation.data = headers;
        if (header_length > max_frame_size) {
            header_length -= max_frame_size;
            headers += max_frame_size;
        } else {
            header_frame->flags = header_finish_flags;
            header_length = 0;
            headers = NULL;
        }
        http2_send_frame(rs->src_conn, continuation);
    }

    if (rs->response->body->type == PROVISION_DATA && rs->response->body->data.data.size > 0) {
        http2_send_data(rs, rs->response->body->data.data.data, rs->response->body->data.data.size, 1);
    } else if (rs->response->body->type == PROVISION_STREAM) {
        // nop
    }

    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_request_completed) {
            module->events.on_request_completed(module, rs);
        }
        ITER_LLIST_END();
    }
}


int handle_http2_request(struct sub_conn* sub_conn, struct http2_stream* stream) {
    struct mempool* req_pool = mempool_new();
    pchild(req_pool, stream->pool);

    struct timespec stt;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);

    struct request_session* rs = pcalloc(req_pool, sizeof(struct request_session));
    rs->extra = stream;
    rs->pool = req_pool;
    rs->conn = sub_conn->conn;
    rs->src_conn = sub_conn;
    rs->request = pcalloc(req_pool, sizeof(struct request));
    rs->request->method = header_get(stream->headers, ":method");
    rs->request->path = header_get(stream->headers, ":path");
    if (!str_eq(header_get(stream->headers, ":scheme"), "https") || !rs->request->method || !rs->request->path) {
        return 1;
    }
    char* authority = header_get(stream->headers, ":authority");
    header_add(stream->headers, "host", authority);
    rs->request->http_version = "HTTP/2";
    rs->request->headers = stream->headers;
    rs->request->body = pcalloc(rs->pool, sizeof(struct provision));
    rs->request->body->pool = rs->pool;
    rs->request->body->type = PROVISION_DATA;
    const char* posted_content_type = header_get(rs->request->headers, "Content-Type");
    rs->request->body->content_type = (char*) (posted_content_type == NULL ? "application/x-www-form-urlencoded" : posted_content_type);
    rs->request->body->data.data.data = pmalloc(rs->pool, stream->data_buffer.size);
    rs->request->body->data.data.size = buffer_pop(&stream->data_buffer, stream->data_buffer.size, rs->request->body->data.data.data);

    rs->response = pcalloc(rs->pool, sizeof(struct response));
    rs->response->headers = header_new(rs->pool);
    rs->response->http_version = rs->request->http_version;
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
    determine_vhost(rs, authority);
    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_request_vhost_resolved) {
            rs->vhost = module->events.on_request_vhost_resolved(module, rs, rs->vhost);
        }
        ITER_LLIST_END();
    }
    if (!skip_generate_response) {
        generateResponse(rs);
    }
    if (rs->response->body != NULL && rs->response->body->type == PROVISION_STREAM) {
        if (rs->response->body->data.stream.delay_header_output) {
            memcpy(&rs->response->body->data.stream.delayed_start, &stt, sizeof(struct timespec));
            rs->response->body->data.stream.delay_finish = send_request_session_http2;
        } else {
            send_request_session_http2(rs, &stt);
        }
    } else {
        send_request_session_http2(rs, &stt);
        pfree(req_pool);
    }
    return 0;
}

int http2_start_connection(struct sub_conn* sub_conn) {
    struct http2_server_extra* extra = sub_conn->extra;
    struct frame* settings = http2_make_frame(sub_conn->pool, FRAME_SETTINGS_ID);
    settings->data.settings.entry_count = 2;
    settings->data.settings.entries = pcalloc(sub_conn->pool, 6 * 2);
    settings->data.settings.entries[0].key = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
    settings->data.settings.entries[0].value = 4096;
    extra->send_hpack_ctx->max_dynamic_size = 4096;
    settings->data.settings.entries[1].key = HTTP2_SETTINGS_MAX_FRAME_SIZE;
    settings->data.settings.entries[1].value = (uint32_t) extra->our_max_frame_size;
    // TODO: all other supported settings
    http2_send_frame(sub_conn, settings);
    // TODO: verify ack
    return 0;
}

struct _hashmap_remove_callback_arg {
    struct hashmap* hashmap;
    uint32_t stream_id;
};

void _hashmap_remove_callback(struct _hashmap_remove_callback_arg* arg) {
    hashmap_putint(arg->hashmap, arg->stream_id, NULL);
}

int receive_http2_frame(struct sub_conn* sub_conn, struct frame* frame) {
    struct http2_server_extra* extra = sub_conn->extra;
    struct http2_stream* stream = frame->stream_id == 0 ? NULL : hashmap_getint(extra->streams, frame->stream_id);
    switch (frame->type) {
        case FRAME_DATA_ID:;
            if (stream == NULL || stream->state != STREAM_OPEN) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                return 1;
            }
            if (frame->data.data.data_length + stream->data_buffer.size > sub_conn->conn->server->max_post) {
                http2_error(sub_conn, HTTP2_FRAME_SIZE_ERROR); // TODO: this should probably be more graceful?
                return 1;
            }
            pxfer(frame->pool, stream->pool, frame->data.data.data);
            buffer_push(&stream->data_buffer, frame->data.data.data, frame->data.data.data_length);
            if (frame->flags & 0x1) {
                stream->state = STREAM_HALF_CLOSED_REMOTE;
                return handle_http2_request(sub_conn, stream);
            }
            break;
        case FRAME_HEADERS_ID:;
            if (stream == NULL) {
                struct mempool* pool = mempool_new();
                pchild(sub_conn->pool, pool);
                stream = pcalloc(pool, sizeof(struct http2_stream));
                stream->pool = pool;
                stream->identifier = frame->stream_id;
                stream->state = STREAM_OPEN;
                stream->headers = header_new(stream->pool);
                buffer_init(&stream->data_buffer, pool);
                hashmap_putint(extra->streams, frame->stream_id, stream);
                struct _hashmap_remove_callback_arg* callback_arg = pmalloc(stream->pool, sizeof(struct _hashmap_remove_callback_arg));
                callback_arg->hashmap = extra->streams;
                callback_arg->stream_id = stream->identifier;
                phook(stream->pool, (void (*)(void*)) _hashmap_remove_callback, callback_arg);
            } else if (stream->state != STREAM_IDLE) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                return 1;
            }
            if (hpack_decode(stream->headers, extra->send_hpack_ctx, frame->pool, frame->data.headers.data, frame->data.headers.data_length)) {
                http2_error(sub_conn, HTTP2_COMPRESSION_ERROR);
                return 1;
            }
            if (frame->flags & 0x4) {
                stream->headers_finished = 1;
            }
            if (frame->flags & 0x1) {
                stream->state = STREAM_HALF_CLOSED_REMOTE;
                return handle_http2_request(sub_conn, stream);
            }
            break;
        case FRAME_PRIORITY_ID:;
            printf("priority\n");
            break;
        case FRAME_RST_STREAM_ID:;
            //TODO: request cancelling?
            // WARNING: the stream may/probably has alrady been freed, so we do nothing
            // don't trust the client to tell us when to free
            hashmap_putint(extra->streams, frame->stream_id, NULL);
            break;
        case FRAME_SETTINGS_ID:;
            if (frame->flags & 0x1) {
                if (frame->data.settings.entry_count != 0) {
                    http2_error(sub_conn, HTTP2_FRAME_SIZE_ERROR);
                    return 1;
                }
                break;
            }
            if (frame->stream_id != 0) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                return 1;
            }
            // TODO: all other supported settings
            for (size_t i = 0; i < frame->data.settings.entry_count; ++i) {
                switch (frame->data.settings.entries[i].key) {
                    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:;
                        extra->recv_hpack_ctx->current_max_dynamic_size = extra->recv_hpack_ctx->max_dynamic_size = frame->data.settings.entries[i].value;
                        break;
                    case HTTP2_SETTINGS_ENABLE_PUSH:;
                        // push not yet supported
                        break;
                    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:;
                        // ignored because we don't open streams yet
                        break;
                    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:;
                        // window size nyi
                        break;
                    case HTTP2_SETTINGS_MAX_FRAME_SIZE:;
                        extra->other_max_frame_size = frame->data.settings.entries[i].value;
                        if (frame->data.settings.entries[i].value > 65536) {
                            extra->other_max_frame_size = 65536;
                        } else if (frame->data.settings.entries[i].value < 256) {
                            http2_error(sub_conn, HTTP2_FRAME_SIZE_ERROR);
                            return 1;
                        }
                    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:;
                        // TODO: implement
                        break;
                    default:;
                        break;
                        // skip
                }
            }
            struct frame* settings = http2_make_frame(sub_conn->pool, FRAME_SETTINGS_ID);
            settings->flags = 0x1; // ACK
            http2_send_frame(sub_conn, settings);
            break;
        case FRAME_PUSH_PROMISE_ID:;
            break;
        case FRAME_PING_ID:;
            struct frame* pong = http2_make_frame(sub_conn->pool, FRAME_PING_ID);
            settings->data.ping.data = frame->data.ping.data;
            http2_send_frame(sub_conn, pong);
            break;
        case FRAME_GOAWAY_ID:;
            return 1;
        case FRAME_WINDOW_UPDATE_ID:;
            // not yet implemented
            break;
        case FRAME_CONTINUATION_ID:;
            if (stream == NULL || (stream->state != STREAM_OPEN && stream->state != STREAM_HALF_CLOSED_REMOTE && !stream->headers_finished)) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                return 1;
            }
            pxfer(frame->pool, stream->pool, frame->data.continuation.data);
            if (hpack_decode(stream->headers, extra->send_hpack_ctx, frame->pool, frame->data.headers.data, frame->data.headers.data_length)) {
                http2_error(sub_conn, HTTP2_COMPRESSION_ERROR);
                return 1;
            }
            if (frame->flags & 0x4) {
                stream->headers_finished = 1;
            }
            break;
        default:;
            // unknown packet type
            return 1;
    }
    return 0;
}