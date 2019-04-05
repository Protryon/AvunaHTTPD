//
// Created by p on 4/2/19.
//

#include <avuna/http.h>
#include <avuna/pmem.h>
#include <avuna/globals.h>


struct chunked_stream_data {
    struct provision* parent;
    int finished;
};

ssize_t chunked_stream_read(struct provision* provision, struct provision_data* buffer) {
    struct chunked_stream_data* data = provision->data.stream.extra;
    if (data->finished) {
        return 0;
    }
    struct provision_data output;
    output.data = NULL;
    output.size = 0;
    ssize_t read = data->parent->data.stream.read(data->parent, &output);
    if (read == 0) {

    } else if (read < 0) {
        return read;
    }

    if (read == 0) {
        data->finished = 1;
    }

    char size_str[128];

    int size_len = snprintf(size_str, 128, "%lX\r\n", output.size);

    uint8_t* new_data = pmalloc(provision->pool, (size_t) (read + size_len + 2));
    memcpy(new_data, size_str, (size_t) size_len);
    memcpy(new_data + size_len, output.data, output.size);
    memcpy(new_data + size_len + output.size, "\r\n", 2);
    buffer->data = new_data;
    buffer->size = (size_t) (size_len + output.size + 2);
    return read == 0 ? 0 : buffer->size;
}

int init_chunked_stream(struct request_session* rs, struct provision* parent, struct provision* provision) {
    struct chunked_stream_data* data = provision->data.stream.extra = pcalloc(parent->pool, sizeof(struct chunked_stream_data));
    data->parent = parent;
    provision->type = PROVISION_STREAM;
    provision->data.stream.known_length = -1;
    provision->data.stream.extra = data;
    provision->data.stream.read = chunked_stream_read;
    return 0;
}