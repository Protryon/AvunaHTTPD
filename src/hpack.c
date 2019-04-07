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

void hpack_init_static_entries() {
    int x = 0;
    static_entries[x].key = ":authority";
    static_entries[x++].value = NULL;
    static_entries[x].key = ":method";
    static_entries[x++].value = "GET";
    static_entries[x].key = ":method";
    static_entries[x++].value = "POST";
    static_entries[x].key = ":path";
    static_entries[x++].value = "/";
    static_entries[x].key = ":path";
    static_entries[x++].value = "/index.html";
    static_entries[x].key = ":scheme";
    static_entries[x++].value = "http";
    static_entries[x].key = ":scheme";
    static_entries[x++].value = "https";
    static_entries[x].key = ":status";
    static_entries[x++].value = "200";
    static_entries[x].key = ":status";
    static_entries[x++].value = "204";
    static_entries[x].key = ":status";
    static_entries[x++].value = "206";
    static_entries[x].key = ":status";
    static_entries[x++].value = "304";
    static_entries[x].key = ":status";
    static_entries[x++].value = "400";
    static_entries[x].key = ":status";
    static_entries[x++].value = "404";
    static_entries[x].key = ":status";
    static_entries[x++].value = "500";
    static_entries[x].key = "accept-charset";
    static_entries[x++].value = NULL;
    static_entries[x].key = "accept-encoding";
    static_entries[x++].value = "gzip, deflate";
    static_entries[x].key = "accept-language";
    static_entries[x++].value = NULL;
    static_entries[x].key = "accept-ranges";
    static_entries[x++].value = NULL;
    static_entries[x].key = "accept";
    static_entries[x++].value = NULL;
    static_entries[x].key = "access-control-allow-origin";
    static_entries[x++].value = NULL;
    static_entries[x].key = "age";
    static_entries[x++].value = NULL;
    static_entries[x].key = "allow";
    static_entries[x++].value = NULL;
    static_entries[x].key = "authorization";
    static_entries[x++].value = NULL;
    static_entries[x].key = "cache-control";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-disposition";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-encoding";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-language";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-length";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-location";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-range";
    static_entries[x++].value = NULL;
    static_entries[x].key = "content-type";
    static_entries[x++].value = NULL;
    static_entries[x].key = "cookie";
    static_entries[x++].value = NULL;
    static_entries[x].key = "date";
    static_entries[x++].value = NULL;
    static_entries[x].key = "etag";
    static_entries[x++].value = NULL;
    static_entries[x].key = "expect";
    static_entries[x++].value = NULL;
    static_entries[x].key = "expires";
    static_entries[x++].value = NULL;
    static_entries[x].key = "from";
    static_entries[x++].value = NULL;
    static_entries[x].key = "host";
    static_entries[x++].value = NULL;
    static_entries[x].key = "if-match";
    static_entries[x++].value = NULL;
    static_entries[x].key = "if-modified-since";
    static_entries[x++].value = NULL;
    static_entries[x].key = "if-none-match";
    static_entries[x++].value = NULL;
    static_entries[x].key = "if-range";
    static_entries[x++].value = NULL;
    static_entries[x].key = "if-unmodified-since";
    static_entries[x++].value = NULL;
    static_entries[x].key = "last-modified";
    static_entries[x++].value = NULL;
    static_entries[x].key = "link";
    static_entries[x++].value = NULL;
    static_entries[x].key = "location";
    static_entries[x++].value = NULL;
    static_entries[x].key = "max-forwards";
    static_entries[x++].value = NULL;
    static_entries[x].key = "proxy-authenticate";
    static_entries[x++].value = NULL;
    static_entries[x].key = "proxy-authorization";
    static_entries[x++].value = NULL;
    static_entries[x].key = "range";
    static_entries[x++].value = NULL;
    static_entries[x].key = "referer";
    static_entries[x++].value = NULL;
    static_entries[x].key = "refresh";
    static_entries[x++].value = NULL;
    static_entries[x].key = "retry-after";
    static_entries[x++].value = NULL;
    static_entries[x].key = "server";
    static_entries[x++].value = NULL;
    static_entries[x].key = "set-cookie";
    static_entries[x++].value = NULL;
    static_entries[x].key = "strict-transport-security";
    static_entries[x++].value = NULL;
    static_entries[x].key = "transfer-encoding";
    static_entries[x++].value = NULL;
    static_entries[x].key = "user-agent";
    static_entries[x++].value = NULL;
    static_entries[x].key = "vary";
    static_entries[x++].value = NULL;
    static_entries[x].key = "via";
    static_entries[x++].value = NULL;
    static_entries[x].key = "www-authenticate";
    static_entries[x++].value = NULL;
}

struct hpack_ctx* hpack_init(struct mempool* pool, size_t max_dynamic_size) {
    if (static_entries[0].key == NULL) {
        hpack_init_static_entries();
    }
    struct hpack_ctx* ctx = pcalloc(pool, sizeof(struct hpack_ctx));
    ctx->pool = pool;
    ctx->dynamic_table = queue_new(0, 0, pool);
    ctx->lookup_map = hashmap_new(50, pool);
    ctx->max_dynamic_size = max_dynamic_size;
    return ctx;
}

struct hpack_entry* hpack_lookup(struct hpack_ctx* ctx, size_t index) {
    if (index == 0) {
        return NULL;
    } else if (index < 62) {
        return &static_entries[index - 1];
    } else {
        index -= 62;
        return queue_index(ctx->dynamic_table, index);
    }
}

void hpack_add_entry(struct hpack_ctx* ctx, struct hpack_entry* entry) {
    entry->size = strlen(entry->value) + strlen(entry->key) + 32;
    while (ctx->dynamic_size + entry->size > ctx->max_dynamic_size) {
        struct hpack_entry* popped = queue_pop(ctx->dynamic_table);
        if (popped == NULL) {
            break;
        }
        ctx->dynamic_size -= entry->size;
    }
    ctx->dynamic_size += entry->size;
    queue_push(ctx->dynamic_table, entry);
}

struct headers* hpack_decode(struct hpack_ctx* ctx, struct mempool* pool, uint8_t* data, size_t data_length) {
    struct headers* headers = header_new(pool);
    for (size_t i = 0; i < data_length;) {
        uint8_t octet = data[i++];
        if (octet >> 7) { // 6.1.  Indexed Header Field Representation
            size_t index = octet << 1 >> 1;
            index = hpack_decode_integer((uint8_t) index, 0b1111111, data, &i, data_length);
            if (index == 0) {
                return NULL;
            }
            struct hpack_entry* entry = hpack_lookup(ctx, index);
            if (entry == NULL) {
                return NULL;
            }
            header_add(headers, entry->key, entry->value == NULL ? "" : entry->value);
        } else if (octet >> 6 == 0b01) { // 6.2.1.  Literal Header Field with Incremental Indexing
            size_t index = octet ^ (uint8_t) 0b01;
            index = hpack_decode_integer((uint8_t) index, 0b111111, data, &i, data_length);
            if (index == 0) {
                size_t name_length = 0;
                char* name = hpack_decode_string(ctx->pool, data, &i, data_length, &name_length);
                size_t value_length = 0;
                char* value = hpack_decode_string(ctx->pool, data, &i, data_length, &value_length);
                struct hpack_entry* entry = pmalloc(ctx->pool, sizeof(struct hpack_entry));
                entry->key = name;
                entry->value = value;
                hpack_add_entry(ctx, entry);
                header_add(headers, name, value);
            } else {
                size_t value_length = 0;
                char* value = hpack_decode_string(ctx->pool, data, &i, data_length, &value_length);
                struct hpack_entry* entry = hpack_lookup(ctx, index);
                if (entry == NULL) {
                    return NULL;
                }
                struct hpack_entry* entry2 = pmalloc(ctx->pool, sizeof(struct hpack_entry));
                entry2->key = entry->key;
                entry2->value = value;
                hpack_add_entry(ctx, entry2);
                header_add(headers, entry->key, value);
            }
        } else if (octet >> 5 == 0b001) { // 6.3.  Dynamic Table Size Update
            size_t new_size = octet << 3 >> 3;
            new_size = hpack_decode_integer((uint8_t) new_size, 0b11111, data, &i, data_length);
            ctx->max_dynamic_size = new_size;
        } else if (octet >> 4 == 0b0001 || octet >> 4 == 0) { // 6.2.3.  Literal Header Field Never Indexed, 6.2.2.  Literal Header Field without Indexing
            size_t index = octet & (uint8_t) 0b1111;
            index = hpack_decode_integer((uint8_t) index, 0b1111, data, &i, data_length);
            if (index == 0) {
                size_t name_length = 0;
                char* name = hpack_decode_string(pool, data, &i, data_length, &name_length);
                size_t value_length = 0;
                char* value = hpack_decode_string(pool, data, &i, data_length, &value_length);
                header_add(headers, name, value);
            } else {
                size_t value_length = 0;
                char* value = hpack_decode_string(pool, data, &i, data_length, &value_length);
                struct hpack_entry* entry = hpack_lookup(ctx, index);
                if (entry == NULL) {
                    return NULL;
                }
                header_add(headers, entry->key, value);
            }
        } else {
            return NULL;
        }
    }
    return headers;
}

