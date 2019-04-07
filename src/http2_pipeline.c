//
// Created by p on 4/6/19.
//

#include "http2_pipeline.h"
#include "http_pipeline.h"
#include "http2_network.h"
#include <avuna/connection.h>
#include <avuna/hpack.h>
#include <avuna/http2.h>
#include <avuna/http.h>
#include <avuna/network.h>

void send_frame(struct sub_conn* sub_conn, struct frame* frame) {
    serialize_frame(frame, &sub_conn->write_buffer, 0);
    pfree(frame->pool);
    trigger_write(sub_conn);
}

struct frame* make_frame(struct sub_conn* sub_conn, uint8_t type) {
    struct mempool* pool = mempool_new();
    struct frame* frame = pcalloc(pool, sizeof(struct frame));
    frame->pool = pool;
    frame->type = type;
    return frame;
}

void http2_error(struct sub_conn* sub_conn, uint32_t error_code) {
    struct http2_server_extra* extra = sub_conn->extra;
    struct frame* frame = make_frame(sub_conn, FRAME_GOAWAY_ID);
    frame->data.goaway.error_code = error_code;
    frame->data.goaway.last_stream_id = extra->other_min_next_stream == 0 ? 0 : extra->other_min_next_stream - 2;
    send_frame(sub_conn, frame);
    //TODO: close connection
}

int handle_http2_request(struct sub_conn* sub_conn, struct http2_stream* stream) {

    return 0;
}

int receive_http2_frame(struct sub_conn* sub_conn, struct frame* frame) {
    int return_value = 0;
    struct http2_server_extra* extra = sub_conn->extra;
    struct http2_stream* stream = frame->stream_id == 0 ? NULL : hashmap_getptr(extra->streams, (void*) frame->stream_id);
    switch (frame->type) {
        case FRAME_DATA_ID:;
            if (stream == NULL || stream->state != STREAM_OPEN) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                goto ret; // TODO: close
            }
            pxfer(frame->pool, stream->pool, frame->data.data.data);
            buffer_push(&stream->data_buffer, frame->data.data.data, frame->data.data.data_length);
            if (frame->flags & 0x1) {
                stream->state = STREAM_HALF_CLOSED_REMOTE;
                return_value = handle_http2_request(sub_conn, stream);
                goto ret;
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
                buffer_init(&stream->header_buffer, pool);
                buffer_init(&stream->data_buffer, pool);
            } else if (stream->state != STREAM_IDLE) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                goto ret; // TODO: close
            }
            pxfer(frame->pool, stream->pool, frame->data.headers.data);
            // struct headers* headers = hpack_decode(extra->hpack_ctx, frame->pool, frame->data.headers.data, frame->data.headers.data_length);
            buffer_push(&stream->header_buffer, frame->data.headers.data, frame->data.headers.data_length);
            if (frame->flags & 0x4) {
                stream->headers_finished = 1;
            }
            if (frame->flags & 0x1) {
                stream->state = STREAM_HALF_CLOSED_REMOTE;
                return_value = handle_http2_request(sub_conn, stream);
                goto ret;
            }
            break;
        case FRAME_PRIORITY_ID:;
            break;
        case FRAME_RST_STREAM_ID:;
            break;
        case FRAME_SETTINGS_ID:;
            for (size_t i = 0; i < frame->data.settings.entry_count; ++i) {
                switch (frame->data.settings.entries[i].key) {
                    case HTTP2_SETTINGS_HEADER_TABLE_SIZE:;
                        if (frame->data.settings.entries[i].value > 65536) {
                            extra->hpack_ctx->real_max_dynamic_size = extra->hpack_ctx->max_dynamic_size = 65536;
                            struct frame* settings = make_frame(sub_conn, FRAME_SETTINGS_ID);
                            settings->data.settings.entry_count = 1;
                            settings->data.settings.entries = pcalloc(frame->pool, 6);
                            settings->data.settings.entries[0].key = HTTP2_SETTINGS_HEADER_TABLE_SIZE;
                            settings->data.settings.entries[0].value = 65536;
                            send_frame(sub_conn, settings);
                            //TODO: expect ack?
                        } else {
                            extra->hpack_ctx->real_max_dynamic_size = extra->hpack_ctx->max_dynamic_size = frame->data.settings.entries[i].value;
                        }
                    case HTTP2_SETTINGS_ENABLE_PUSH:;
                    case HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:;
                    case HTTP2_SETTINGS_INITIAL_WINDOW_SIZE:;
                    case HTTP2_SETTINGS_MAX_FRAME_SIZE:;
                    case HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:;
                    default:;
                        // skip
                }
            }
            struct frame* settings = make_frame(sub_conn, FRAME_SETTINGS_ID);
            settings->flags = 0x1; // ACK
            send_frame(sub_conn, settings);
            break;
        case FRAME_PUSH_PROMISE_ID:;
            break;
        case FRAME_PING_ID:;
            break;
        case FRAME_GOAWAY_ID:;
            break;
        case FRAME_WINDOW_UPDATE_ID:;
            break;
        case FRAME_CONTINUATION_ID:;
            if (stream == NULL || (stream->state != STREAM_OPEN && stream->state != STREAM_HALF_CLOSED_REMOTE && !stream->headers_finished)) {
                http2_error(sub_conn, HTTP2_PROTOCOL_ERROR);
                goto ret; // TODO: close
            }
            pxfer(frame->pool, stream->pool, frame->data.continuation.data);
            buffer_push(&stream->header_buffer, frame->data.continuation.data, frame->data.continuation.data_length);
            if (frame->flags & 0x4) {
                stream->headers_finished = 1;
            }
            break;
        default:;
            return_value = 1;
            goto ret;
    }
    ret:;
    pfree(frame->pool);
    return return_value;
}