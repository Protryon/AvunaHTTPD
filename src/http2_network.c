//
// Created by p on 4/6/19.
//

#include "http2_network.h"
#include "http2_pipeline.h"
#include <avuna/connection.h>
#include <avuna/http2.h>
#include <avuna/buffer.h>
#include <avuna/http_util.h>
#include <avuna/util.h>
#include <stdint.h>

const uint8_t* preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

void http2_send_frame(struct sub_conn* sub_conn, struct frame* frame) {
    serialize_frame(frame, &sub_conn->write_buffer, 0);
    pfree(frame->pool);
    trigger_write(sub_conn);
}

struct frame* http2_make_frame(struct mempool* parent, uint8_t type) {
    struct mempool* pool = mempool_new();
    pchild(parent, pool);
    struct frame* frame = pcalloc(pool, sizeof(struct frame));
    frame->pool = pool;
    frame->type = type;
    return frame;
}

void http2_error(struct sub_conn* sub_conn, uint32_t error_code) {
    struct http2_server_extra* extra = sub_conn->extra;
    struct frame* frame = http2_make_frame(sub_conn->pool, FRAME_GOAWAY_ID);
    frame->data.goaway.error_code = error_code;
    frame->data.goaway.last_stream_id = extra->other_min_next_stream == 0 ? 0 : extra->other_min_next_stream - 2;
    http2_send_frame(sub_conn, frame);
}

void http2_send_data(struct request_session* rs, uint8_t* data, size_t data_length, uint8_t terminate) {
    struct http2_server_extra* extra = rs->src_conn->extra;
    size_t max_frame_size = extra->other_max_frame_size - 32;
    uint8_t finish_flags = 0x1;
    size_t i = 0;
    struct http2_stream* stream = rs->extra;
    while (i < data_length || (data_length == 0 && terminate)) {
        struct frame* data_frame = http2_make_frame(rs->pool, FRAME_DATA_ID);
        data_frame->stream_id = stream->identifier;
        data_frame->data.data.data = data == NULL ? NULL : data + i;
        data_frame->data.data.data_length = data == NULL ? 0 : data_length > max_frame_size ? max_frame_size : data_length;
        i += data_length;
        if (terminate && i >= data_length) {
            data_frame->flags |= finish_flags;
            terminate = 0;
        }
        http2_send_frame(rs->src_conn, data_frame);
    }
}

int handle_http2_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    struct http2_server_extra* extra = sub_conn->extra;
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    if (!extra->has_received_preface) {
        if (sub_conn->read_buffer.size >= 24) {
            uint8_t maybe_preface[24];
            buffer_pop(&sub_conn->read_buffer, 24, maybe_preface);
            if (!memeq(maybe_preface, 24, preface, 24)) {
                return 1;
            }
            extra->has_received_preface = 1;
            if (http2_start_connection(sub_conn)) {
                return 1;
            }
        }
    }
    while (sub_conn->read_buffer.size > 9) {
        uint8_t header[9];
        buffer_peek(&sub_conn->read_buffer, 9, header);
        uint32_t frame_size = (uint32_t) header[0] << 16 | (uint32_t) header[1] << 8 | (uint32_t) header[2];
        if (frame_size > extra->our_max_frame_size) {
            return 1;
        }
        if (sub_conn->read_buffer.size >= frame_size + 9) {
            buffer_pop(&sub_conn->read_buffer, frame_size + 9, extra->frame_buffer);
            struct mempool* frame_pool = mempool_new();
            pchild(sub_conn->pool, frame_pool);
            uint32_t error_code = 0;
            struct frame* frame = parse_frame(frame_pool, extra->frame_buffer, frame_size, &error_code);
            if (receive_http2_frame(sub_conn, frame)) {
                pfree(frame->pool);
                return 1;
            }
            pfree(frame->pool);
        } else {
            break;
        }
    }
    return 0;
}

int http2_stream_notify(struct request_session* rs) {
    struct http2_stream* stream = rs->extra;
    struct provision* provision = rs->response->body;
    struct provision_data data;
    data.data = NULL;
    data.size = 0;
    ssize_t total_read = provision->data.stream.read(provision, &data);
    if (total_read == -1) {
        // backend server failed during stream
        http2_send_data(rs, NULL, 0, 1);
        pfree(rs->pool);
    } else if (total_read == 0) {
        // end of stream_id
        if (data.size > 0) {
            pxfer(provision->pool, stream->pool, data.data);
            http2_send_data(rs, data.data, data.size, 1);
        } else {
            http2_send_data(rs, NULL, 0, 1);
            pfree(rs->pool);
        }
    } else if (total_read == -2) {
        // nothing to read, not end of stream
        return 0;
    } else {
        pxfer(provision->pool, stream->pool, data.data);
        http2_send_data(rs, data.data, data.size, 0);
        return 0;
    }
    return 1;
}
