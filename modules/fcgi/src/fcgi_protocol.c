/*
 * fcgi.c
 *
 *  Created on: Nov 26, 2015
 *      Author: root
 */

#include "fcgi_protocol.h"
#include <avuna/string.h>
#include <errno.h>


void fcgi_writeFrame(struct buffer* buffer, struct fcgi_frame* frame) {
    uint8_t* header = pcalloc(buffer->pool, 8);
    header[0] = FCGI_VERSION_1;
    header[1] = frame->type;
    header[2] = (uint8_t) ((frame->request_id & 0xFF00) >> 8);
    header[3] = (uint8_t) (frame->request_id & 0x00FF);
    header[4] = (uint8_t) ((frame->len & 0xFF00) >> 8);
    header[5] = (uint8_t) (frame->len & 0x00FF);
    header[6] = 0; // 0 padding
    header[7] = 0; // reserved
    buffer_push(buffer, header, 8);
    buffer_push(buffer, frame->data, frame->len);
}

void fcgi_writeParam(struct buffer* buffer, uint16_t reqid, const char* name, const char* value) {
    struct fcgi_frame frame;
    frame.type = FCGI_PARAMS;
    frame.request_id = reqid;
    if (value == NULL) {
        value = "";
    }
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    int large_name = name_len > 127;
    int large_value = value_len > 127;
    frame.len = (uint16_t) ((large_name ? 4 : 1) + (large_value ? 4 : 1) + name_len + value_len);
    uint8_t* data = pmalloc(buffer->pool, frame.len);
    int i = 0;
    if (large_name) {
        data[i++] = (uint8_t) ((name_len & 0xFF000000) >> 24 | 0x80);
        data[i++] = (uint8_t) ((name_len & 0x00FF0000) >> 16);
        data[i++] = (uint8_t) ((name_len & 0x0000FF00) >> 8);
        data[i++] = (uint8_t) (name_len & 0x000000FF);
    } else {
        data[i++] = (uint8_t) name_len;
    }
    if (large_value) {
        data[i++] = (uint8_t) (((value_len & 0xFF000000) >> 24) | 0x80);
        data[i++] = (uint8_t) ((value_len & 0x00FF0000) >> 16);
        data[i++] = (uint8_t) ((value_len & 0x0000FF00) >> 8);
        data[i++] = (uint8_t) (value_len & 0x000000FF);
    } else {
        data[i++] = (uint8_t) value_len;
    }
    memcpy(data + i, name, name_len);
    i += name_len;
    memcpy(data + i, value, value_len);
    frame.data = data;
    fcgi_writeFrame(buffer, &frame);
}

ssize_t fcgi_readFrame(struct buffer* buffer, struct fcgi_frame* frame, struct mempool* pool) {
    uint8_t header[8];
    buffer_peek(buffer, 8, header);
    if (header[0] != FCGI_VERSION_1) {
        return -1;
    }
    frame->type = header[1];
    frame->request_id = (header[2] << 8) + header[3];
    frame->len = (header[4] << 8) + header[5];
    uint8_t padding = header[6];
    //7 = reserved
    if (buffer->size < 8 + frame->len + padding) {
        return -2;
    }
    frame->data = pmalloc(pool, frame->len + 1);
    ((uint8_t*) frame->data)[frame->len] = 0;
    buffer_skip(buffer, 8);
    buffer_pop(buffer, frame->len, frame->data);
    buffer_skip(buffer, padding);
    return 0;
}
