/*
 * http2.c
 *
 *  Created on: Dec 13, 2015
 *      Author: root
 */


#include <avuna/http2.h>
#include <avuna/buffer.h>
#include <avuna/pmem.h>

#define DECODE4 ((uint32_t) data[i] << 24 | (uint32_t) data[i + 1] << 16 | (uint32_t) data[i + 2] << 8 | (uint32_t) data[i + 3])

#define ASSERT_LENGTH(n) if (length - i < n) { *error_code = HTTP2_FRAME_SIZE_ERROR; return NULL; }
#define ASSERT_STRONG_LENGTH(n) if (length - i != n) { *error_code = HTTP2_FRAME_SIZE_ERROR; return NULL; }

struct frame* parse_frame(struct mempool* pool, uint8_t* data, size_t length, uint32_t* error_code) {
    struct frame* frame = pcalloc(pool, sizeof(struct frame));
    frame->pool = pool;
    size_t i = 0;
    uint32_t encoded_length = (uint32_t) data[i] << 16 | (uint32_t) data[i + 1] << 8 | (uint32_t) data[i + 2];
    i += 3;
    if (encoded_length != length) {
        *error_code = HTTP2_FRAME_SIZE_ERROR;
        return NULL;
    }
    frame->type = data[i++];
    frame->flags = data[i++];
    frame->stream_id = DECODE4;
    i += 4;
    frame->stream_id = frame->stream_id << 1 >> 1; // ignore reserved bit
    data += 9;
    i = 0;
    uint8_t padding = 0;
    int is_padded = 0, is_priority = 0;
    switch (frame->type) {
        case FRAME_DATA_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) { // padded
                ASSERT_LENGTH(1);
                padding = data[i++];
            }
            frame->data.data.data_length = length - padding - (is_padded ? 1 : 0);
            ASSERT_STRONG_LENGTH(frame->data.data.data_length);
            frame->data.data.data = pmalloc(pool, frame->data.data.data_length);
            memcpy(data + i, frame->data.data.data, frame->data.data.data_length);
            break;
        case FRAME_HEADERS_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) { // padded
                ASSERT_LENGTH(1);
                padding = data[i++];
            }
            is_priority = frame->flags & 0x20;
            if (is_priority) {
                ASSERT_LENGTH(5);
                frame->data.headers.stream_dependency = DECODE4;
                i += 4;
                frame->data.headers.exclusive = (uint8_t) (frame->data.headers.stream_dependency >> 31);
                frame->data.headers.stream_dependency = frame->data.headers.stream_dependency << 1 >> 1;
                frame->data.headers.weight = data[i++];
            }
            frame->data.headers.data_length = length - padding - (is_padded ? 1 : 0) - (is_priority ? 5 : 0);
            ASSERT_STRONG_LENGTH(frame->data.headers.data_length);
            frame->data.headers.data = pmalloc(pool, frame->data.headers.data_length);
            memcpy(data + i, frame->data.headers.data, frame->data.headers.data_length);
            break;
        case FRAME_PRIORITY_ID:;
            ASSERT_STRONG_LENGTH(5);
            frame->data.priority.stream_dependency = DECODE4;
            i += 4;
            frame->data.priority.exclusive = (uint8_t) (frame->data.priority.stream_dependency >> 31);
            frame->data.priority.stream_dependency = frame->data.priority.stream_dependency << 1 >> 1;
            frame->data.priority.weight = data[i++];
            break;
        case FRAME_RST_STREAM_ID:;
            ASSERT_STRONG_LENGTH(4);
            frame->data.rst_stream.error_code = DECODE4;
            i += 4;
            break;
        case FRAME_SETTINGS_ID:;
            if ((length - i) % 6 != 0) {
                *error_code = HTTP2_FRAME_SIZE_ERROR;
                return NULL;
            }
            frame->data.settings.entry_count = (length - i) / 6;
            frame->data.settings.entries = pmalloc(pool, frame->data.settings.entry_count * 6);
            for (size_t x = 0; x < frame->data.settings.entry_count; ++x) {
                frame->data.settings.entries[x].key = (uint16_t) data[i] << 8 | (uint16_t) data[i + 1];
                i += 2;
                frame->data.settings.entries[x].value = DECODE4;
                i += 4;
            }
            break;
        case FRAME_PUSH_PROMISE_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) { // padded
                ASSERT_LENGTH(1);
                padding = data[i++];
            }
            ASSERT_LENGTH(4);
            frame->data.push_promise.stream_id = DECODE4 << 1 >> 1;
            i += 4;
            frame->data.push_promise.data_length = length - padding - (is_padded ? 1 : 0) - 4;
            ASSERT_STRONG_LENGTH(frame->data.push_promise.data_length);
            frame->data.push_promise.data = pmalloc(pool, frame->data.push_promise.data_length);
            memcpy(data + i, frame->data.push_promise.data, frame->data.push_promise.data_length);
            break;
        case FRAME_PING_ID:;
            ASSERT_STRONG_LENGTH(8);
            frame->data.ping.data = (uint64_t) DECODE4 << 32;
            i += 4;
            frame->data.ping.data |= (uint64_t) DECODE4;
            i += 4;
            break;
        case FRAME_GOAWAY_ID:;
            ASSERT_LENGTH(8);
            frame->data.goaway.last_stream_id = DECODE4 << 1 >> 1;
            i += 4;
            frame->data.goaway.error_code = DECODE4;
            i += 4;
            // debug data ignored
            break;
        case FRAME_WINDOW_UPDATE_ID:;
            ASSERT_STRONG_LENGTH(4);
            frame->data.window_update.increment = DECODE4 << 1 >> 1;
            i += 4;
            break;
        case FRAME_CONTINUATION_ID:;
            frame->data.continuation.data_length = length;
            ASSERT_STRONG_LENGTH(frame->data.continuation.data_length);
            frame->data.continuation.data = pmalloc(pool, frame->data.continuation.data_length);
            memcpy(data + i, frame->data.continuation.data, frame->data.continuation.data_length);
            break;
        default:;
            *error_code = HTTP2_PROTOCOL_ERROR;
            return NULL;
    }
    return frame;
}

#undef ASSERT_LENGTH
#undef ASSERT_STRONG_LENGTH

#define SET_LENGTH(x) { header[0] = ((x - 9) >> 16) & 0xFF; header[1] = ((x - 9) >> 8) & 0xFF; header[2] = (x - 9) & 0xFF; }

int serialize_frame(struct frame* frame, struct buffer* buffer, uint8_t padding) {
    static uint8_t pad[256];
    uint8_t* header = pcalloc(buffer->pool, 32);
    header[3] = frame->type;
    header[4] = frame->flags;
    memcpy(header + 5, &frame->stream_id, 4);
    int is_padded = 0, is_priority = 0;
    size_t i = 9;
    switch (frame->type) {
        case FRAME_DATA_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) {
                header[i++] = padding;
            }
            SET_LENGTH(i + padding + frame->data.data.data_length);
            buffer_push(buffer, header, i);
            buffer_push(buffer, frame->data.data.data, frame->data.data.data_length);
            if (is_padded) {
                buffer_push(buffer, pad, padding);
            }
            break;
        case FRAME_HEADERS_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) {
                header[i++] = padding;
            }
            is_priority = frame->flags & 0x20;
            if (is_priority) {
                uint32_t total_stream = frame->data.headers.stream_dependency | ((uint32_t) frame->data.headers.exclusive << 31);
                memcpy(header + i, &total_stream, 4);
                i += 4;
                header[i++] = frame->data.headers.weight;
            }
            SET_LENGTH(i + padding + frame->data.headers.data_length);
            buffer_push(buffer, header, i);
            buffer_push(buffer, frame->data.headers.data, frame->data.headers.data_length);
            if (is_padded) {
                buffer_push(buffer, pad, padding);
            }
            break;
        case FRAME_PRIORITY_ID:;
            uint32_t total_stream = frame->data.priority.stream_dependency | ((uint32_t) frame->data.priority.exclusive << 31);
            memcpy(header + i, &total_stream, 4);
            i += 4;
            header[i++] = frame->data.priority.weight;
            SET_LENGTH(i);
            buffer_push(buffer, header, i);
            break;
        case FRAME_RST_STREAM_ID:;
            memcpy(header + i, &frame->data.rst_stream.error_code, 4);
            i += 4;
            SET_LENGTH(i);
            buffer_push(buffer, header, i);
            break;
        case FRAME_SETTINGS_ID:;
            SET_LENGTH(i + frame->data.settings.entry_count * 6);
            buffer_push(buffer, header, i);
            if (frame->data.settings.entry_count > 0) {
                buffer_push(buffer, frame->data.settings.entries, frame->data.settings.entry_count * 6);
            }
            break;
        case FRAME_PUSH_PROMISE_ID:;
            is_padded = frame->flags & 0x08;
            if (is_padded) {
                header[i++] = padding;
            }
            memcpy(header + i, &frame->data.push_promise.stream_id, 4);
            i += 4;
            SET_LENGTH(i + padding + frame->data.push_promise.data_length);
            buffer_push(buffer, header, i);
            buffer_push(buffer, frame->data.push_promise.data, frame->data.push_promise.data_length);
            if (is_padded) {
                buffer_push(buffer, pad, padding);
            }
            break;
        case FRAME_PING_ID:;
            memcpy(header + i, &frame->data.ping.data, 8);
            i += 8;
            SET_LENGTH(i);
            buffer_push(buffer, header, i);
            break;
        case FRAME_GOAWAY_ID:;
            memcpy(header + i, &frame->data.goaway.last_stream_id, 4);
            i += 4;
            memcpy(header + i, &frame->data.goaway.error_code, 4);
            i += 4;
            // debug data ignored
            SET_LENGTH(i);
            buffer_push(buffer, header, i);
            break;
        case FRAME_WINDOW_UPDATE_ID:;
            memcpy(header + i, &frame->data.window_update.increment, 4);
            i += 4;
            SET_LENGTH(i);
            buffer_push(buffer, header, i);
            break;
        case FRAME_CONTINUATION_ID:;
            SET_LENGTH(i + frame->data.continuation.data_length);
            buffer_push(buffer, header, i);
            buffer_push(buffer, frame->data.continuation.data, frame->data.continuation.data_length);
            break;
        default:;
            return -1;
    }
    return 0;
}