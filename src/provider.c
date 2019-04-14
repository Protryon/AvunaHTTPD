//
// Created by p on 3/30/19.
//

#include <avuna/provider.h>
#include <avuna/string.h>
#include <stdio.h>

ssize_t raw_stream_read(struct provision* provision, struct provision_data* buffer) {
    ssize_t length = provision->data.stream.known_length;
    if (length <= 0) {
        length = 4096;
    }
    buffer->data = pmalloc(provision->pool, (size_t) length);
    return buffer->size = (size_t) read(provision->data.stream.stream_fd, buffer->data, (size_t) length);
}

//TODO: subconns for raw_stream!

ssize_t chunked_read(struct provision* provision, struct provision_data* buffer) {
    struct chunked_stream_extra* extra = provision->extra;
    buffer->size = extra->sub_conn->read_buffer.size + 128;
    buffer->data = pmalloc(provision->pool, buffer->size);
    size_t buffer_index = 0;
    if (extra->sub_conn->read_buffer.size == 0) {
        return -2;
    }
    while (extra->sub_conn->read_buffer.size > 0) {
        ssize_t remaining = extra->remaining;
        if (remaining == -1) {
            char length[17];
            buffer_peek(&extra->sub_conn->read_buffer, 16, (uint8_t*) length);
            length[16] = 0;
            char* post_length = NULL;
            size_t length_int = strtoull(length, &post_length, 10);
            if (post_length == NULL || !str_prefixes(post_length, "\r\n")) {
                return -2; // stream_id blocked, not an error
            }
            size_t read_length = post_length - length + 2; // includes trailing \r\n
            if (length_int == 0) {
                return 0; // end of stream_id
            }
            buffer_skip(&extra->sub_conn->read_buffer, read_length);
            extra->remaining = length_int;
        }
        if (extra->sub_conn->read_buffer.size >= remaining) {
            buffer_index += buffer_pop(&extra->sub_conn->read_buffer, (size_t) remaining, buffer->data + buffer_index);
            extra->remaining = -1;
        } else {
            size_t popped = buffer_pop(&extra->sub_conn->read_buffer, (size_t) remaining, buffer->data + buffer_index);
            extra->remaining -= popped;
            buffer_index += popped;
        }
    }
    return buffer_index;
}