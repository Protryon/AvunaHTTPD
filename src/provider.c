//
// Created by p on 3/30/19.
//

#include <avuna/provider.h>
#include <stdio.h>

ssize_t raw_stream_read(struct provision* provision, struct provision_data* buffer) {
    return read(provision->data.stream.stream_fd, buffer->data, buffer->size);
}