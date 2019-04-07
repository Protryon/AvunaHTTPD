//
// Created by p on 4/6/19.
//

#include "hpack.h"
#include "huffman.h"
#include <avuna/headers.h>
#include <string.h>

// https://tools.ietf.org/html/rfc7541

size_t hpack_decode_integer(uint8_t prefix, uint8_t prefix_mask, const uint8_t* input, size_t* offset, size_t length) {
    if ((prefix & prefix_mask) != prefix_mask) {
        return prefix;
    }
    size_t bit = 0b1;
    size_t ret = 0;
    while (*offset < length && (input[*offset] >> 7) && bit > 0) {
        uint8_t octet = input[*offset] << 1 >> 1;
        ret += (size_t) octet * bit;
        bit <<= 7;
        ++(*offset);
    }
    return ret;
}

char* hpack_decode_string(struct mempool* pool, const uint8_t* input, size_t* offset, size_t length, size_t* out_length) {
    if (*offset >= length) {
        return NULL;
    }
    uint8_t prefix = input[*offset];
    ++(*offset);
    int huffman_coded = prefix >> 7;
    size_t string_length = hpack_decode_integer(prefix >> 1 << 1, 0b1111111, input, offset, length);
    if (*offset + string_length >= length) {
        return NULL;
    }
    uint8_t* str = pmalloc(pool, string_length + 1);
    str[string_length] = 0;
    memcpy(str, input + *offset, string_length);
    (*offset) += string_length;
    if (huffman_coded) {
        char* decoded = (char*) huffman_decode(pool, str, string_length, out_length);
        pprefree(pool, str);
        return decoded;
    }
    return (char*) str;
}

struct headers* hpack_decode(struct hpack_ctx* ctx, struct mempool* pool, uint8_t* data, size_t data_length) {
    struct headers* headers = header_new(pool);
    for (size_t i = 0; i < data_length;) {
        uint8_t octet = data[i++];
        if (octet >> 7) { // 6.1.  Indexed Header Field Representation
            size_t index = octet << 1 >> 1;
            index = hpack_decode_integer((uint8_t) index, 0b1111111, data, &i, data_length);
            // TODO: deref index
        } else if (octet >> 6 == 0b01) { // 6.2.1.  Literal Header Field with Incremental Indexing
            size_t index = octet ^ (uint8_t) 0b01;
            index = hpack_decode_integer((uint8_t) index, 0b111111, data, &i, data_length);
            if (index == 0) {
                char* name = hpack_decode_string(data, &i, data_length);
                char* value = hpack_decode_string(data, &i, data_length);

            } else {
                char* value = hpack_decode_string(data, &i, data_length);
            }
        } else if (octet >> 5 == 0b001) { // 6.3.  Dynamic Table Size Update
            size_t new_size = octet << 3 >> 3;
            new_size = hpack_decode_integer((uint8_t) new_size, 0b11111, data, &i, data_length);

        } else if (octet >> 4 == 0b0001) { // 6.2.3.  Literal Header Field Never Indexed
            size_t index = octet & (uint8_t) 0b1111;
            index = hpack_decode_integer((uint8_t) index, 0b1111, data, &i, data_length);
            if (index == 0) {
                char* name = hpack_decode_string(data, &i, data_length);
                char* value = hpack_decode_string(data, &i, data_length);

            } else {
                char* value = hpack_decode_string(data, &i, data_length);
            }
        } else if (octet >> 4 == 0) { // 6.2.2.  Literal Header Field without Indexing
            size_t index = octet & (uint8_t) 0b1111;
            index = hpack_decode_integer((uint8_t) index, 0b1111, data, &i, data_length);
            if (index == 0) {
                char* name = hpack_decode_string(data, &i, data_length);
                char* value = hpack_decode_string(data, &i, data_length);

            } else {
                char* value = hpack_decode_string(data, &i, data_length);
            }
        }
    }
    return headers;
}

