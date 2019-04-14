//
// Created by p on 4/6/19.
//

#include "huffman.h"
#include <avuna/hpack.h>
#include <avuna/headers.h>
#include <avuna/globals.h>
#include <avuna/string.h>

// https://tools.ietf.org/html/rfc7541

size_t hpack_decode_integer(uint8_t prefix, uint8_t prefix_mask, const uint8_t* input, size_t* offset, size_t length) {
    if ((prefix & prefix_mask) != prefix_mask) {
        return prefix;
    }
    size_t bit = 0b1;
    size_t ret = 0;
    do {
        if (bit != 0b1) {
            ++(*offset);
        }
        uint8_t octet = (uint8_t) (input[*offset] & 0b1111111);
        ret += (size_t) octet * bit;
        bit <<= 7;
    } while (*offset < length && (input[*offset] >> 7) && bit > 0);
    ++(*offset);
    return ret + prefix_mask;
}

size_t hpack_encode_integer(uint8_t prefix, uint8_t prefix_mask, size_t integer, uint8_t* output, size_t* offset, size_t length) {
    if (*offset >= length) {
        return 0;
    }
    size_t original_offset = *offset;
    if (integer < prefix_mask) {
        output[(*offset)++] = (prefix & ~prefix_mask) | ((uint8_t) integer & prefix_mask);
        return 1;
    } else {
        output[(*offset)++] = (prefix & ~prefix_mask) | prefix_mask;
        integer -= prefix_mask;
    }

    size_t ret = 1;
    while (*offset < length && (integer >> 7)) {
        output[(*offset)++] = (uint8_t) (integer & 0b1111111) | (uint8_t) 0b10000000;
        ++ret;
        integer >>= 7;
    }
    if (*offset < length) {
        output[(*offset)++] = (uint8_t) (integer & 0b1111111);
        ++ret;
        integer >>= 7;
    }
    if (integer != 0) {
        *offset = original_offset;
        return 0;
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
    size_t string_length = hpack_decode_integer((uint8_t) (prefix & 0b1111111u), 0b1111111, input, offset, length);
    if (*offset + string_length > length) {
        return NULL;
    }
    uint8_t* str = pmalloc(pool, string_length + 1);
    str[string_length] = 0;
    memcpy(str, input + *offset, string_length);
    (*offset) += string_length;
    if (huffman_coded) {
        char* decoded = (char*) huffman_decode(pool, str, string_length, out_length);
        pprefree(pool, str); // TODO: this probably isnt worth doing
        return decoded;
    } else {
        *out_length = string_length;
    }
    return (char*) str;
}

size_t hpack_encode_string(struct mempool* pool, char* str, uint8_t huffman_coded, uint8_t* output, size_t* offset, size_t length) {
    if (*offset >= length) {
        return 0;
    }
    size_t original_offset = *offset;
    size_t str_length = strlen(str);
    if (huffman_coded) {
        str = (char*) huffman_encode(pool, (uint8_t*) str, str_length, &str_length);
    }
    if (str == NULL || hpack_encode_integer((uint8_t) (huffman_coded != 0) << 7, 0b1111111, str_length, output, offset, length) == 0) {
        *offset = original_offset;
        return 0;
    }
    if (*offset + str_length >= length) {
        *offset = original_offset;
        return 0;
    }
    memcpy(output + *offset, str, str_length);
    *offset += str_length;
    return *offset - original_offset;
}

struct hashset* never_index_headers;

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
    // no duplicates in static_entries, so no sublists
    static_entry_map = hashmap_new(64, global_pool);
    for (size_t i = 0; i < x; ++i) {
        struct hpack_entry* entry = &static_entries[i];
        entry->push_index = i + 1;
        struct llist* list = hashmap_get(static_entry_map, entry->key);
        if (list == NULL) {
            hashmap_put(static_entry_map, entry->key, list = llist_new(global_pool));
        }
        llist_append(list, entry);
    }
    never_index_headers = hashset_new(32, global_pool);
    hashset_add(never_index_headers, "content-length");
    hashset_add(never_index_headers, "cookie");
    hashset_add(never_index_headers, "set-cookie");
}

struct hpack_ctx* hpack_init(struct mempool* pool, size_t max_dynamic_size) {
    if (static_entries[0].key == NULL) {
        hpack_init_static_entries();
    }
    struct hpack_ctx* ctx = pcalloc(pool, sizeof(struct hpack_ctx));
    ctx->pool = pool;
    ctx->dynamic_table = queue_new(0, 0, pool);
    ctx->lookup_map = hashmap_new(50, pool);
    ctx->max_dynamic_size = ctx->current_max_dynamic_size = max_dynamic_size;
    return ctx;
}

void hpack_fix(struct hpack_ctx* ctx, size_t extra) {
    while (ctx->dynamic_size + extra > ctx->max_dynamic_size) {
        struct hpack_entry* popped = queue_pop(ctx->dynamic_table);
        if (popped == NULL) {
            break;
        }
        llist_del(popped->containing_lookup_list, popped->lookup_node);
        if (popped->containing_lookup_list->size == 0) {
            hashmap_put(ctx->lookup_map, popped->key, NULL);
        }
        ctx->dynamic_size -= popped->size;
    }
}

struct hpack_entry* hpack_lookup(struct hpack_ctx* ctx, size_t index) {
    if (index == 0) {
        return NULL;
    } else if (index < 62) {
        return &static_entries[index - 1];
    } else {
        hpack_fix(ctx, 0);
        index -= 62;
        return queue_index(ctx->dynamic_table, index);
    }
}

void hpack_add_entry(struct hpack_ctx* ctx, struct hpack_entry* entry) {
    entry->size = (entry->value == NULL ? 0 : strlen(entry->value)) + strlen(entry->key) + 32;
    hpack_fix(ctx, entry->size);
    ctx->dynamic_size += entry->size;
    entry->push_index = ctx->push_index++;
    queue_push(ctx->dynamic_table, entry);
}

int hpack_decode(struct headers* headers, struct hpack_ctx* ctx, struct mempool* pool, uint8_t* data, size_t data_length) {
    for (size_t i = 0; i < data_length;) {
        uint8_t octet = data[i++];
        if (octet >> 7) { // 6.1.  Indexed Header Field Representation
            size_t index = octet & 0b1111111lu;
            index = hpack_decode_integer((uint8_t) index, 0b1111111, data, &i, data_length);
            if (index == 0) {
                return 1;
            }
            struct hpack_entry* entry = hpack_lookup(ctx, index);
            if (entry == NULL) {
                return 1;
            }
            header_add(headers, entry->key, entry->value == NULL ? "" : entry->value);
        } else if (octet >> 6 == 0b01) { // 6.2.1.  Literal Header Field with Incremental Indexing
            size_t index = octet & 0b111111lu;
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
                struct llist* lookup_list = hashmap_get(ctx->lookup_map, name);
                if (lookup_list == NULL) {
                    hashmap_put(ctx->lookup_map, name, lookup_list = llist_new(ctx->pool));
                }
                entry->lookup_node = llist_append(lookup_list, entry);
                entry->containing_lookup_list = lookup_list;
                header_add(headers, name, value);
            } else {
                size_t value_length = 0;
                char* value = hpack_decode_string(ctx->pool, data, &i, data_length, &value_length);
                struct hpack_entry* entry = hpack_lookup(ctx, index);
                if (entry == NULL) {
                    return 1;
                }
                struct hpack_entry* entry2 = pmalloc(ctx->pool, sizeof(struct hpack_entry));
                entry2->key = entry->key;
                entry2->value = value;
                hpack_add_entry(ctx, entry2);
                struct llist* lookup_list = hashmap_get(ctx->lookup_map, entry->key);
                if (lookup_list == NULL) {
                    hashmap_put(ctx->lookup_map, entry->key, lookup_list = llist_new(ctx->pool));
                }
                entry2->lookup_node = llist_append(lookup_list, entry2);
                entry2->containing_lookup_list = lookup_list;
                header_add(headers, entry->key, value);
            }
        } else if (octet >> 5 == 0b001) { // 6.3.  Dynamic Table Size Update
            size_t new_size = octet & 0b11111lu;
            new_size = hpack_decode_integer((uint8_t) new_size, 0b11111, data, &i, data_length);
            if (new_size > ctx->max_dynamic_size) {
                return 1;
            }
            ctx->current_max_dynamic_size = new_size;
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
                    return 1;
                }
                header_add(headers, entry->key, value);
            }
        } else {
            return 1;
        }
    }
    return 0;
}

struct hpack_entry* _hpack_entry_in_list(struct llist* entries, char* value) {
    ITER_LLIST(entries, entry_value) {
        struct hpack_entry* hpack_entry = entry_value;
        if (hpack_entry->value != NULL && str_eq_case(hpack_entry->value, value)) {
            return hpack_entry;
        }
        ITER_LLIST_END();
    }
    return NULL;
}

uint8_t* hpack_encode(struct hpack_ctx* ctx, struct mempool* pool, struct headers* headers, size_t* out_length) {
    uint8_t* out = pmalloc(pool, 1024);
    size_t out_cap = 1024;
    size_t out_i = 0;
    ctx->current_max_dynamic_size = ctx->max_dynamic_size;
    while (!hpack_encode_integer(0b001 << 5, 0b11111, ctx->current_max_dynamic_size, out, &out_i, out_cap)) {
        out_cap *= 2;
        out = prealloc(pool, out, out_cap);
    }
    ITER_LLIST(headers->header_list, value) {
        struct header_entry* entry = value;
        int never_index = hashset_has(never_index_headers, entry->name);
        struct llist* static_entries = hashmap_get(static_entry_map, entry->name);
        struct hpack_entry* static_entry = static_entries != NULL ? _hpack_entry_in_list(static_entries, entry->value) : NULL;
        int static_name_only = 0;
        if (static_entries != NULL && static_entry == NULL) {
            static_entry = static_entries->head->data;
            static_name_only = 1;
        }
        struct hpack_entry* hpack_entry = NULL;
        size_t index = 0;
        int name_only = 0;
        struct llist* entries = hashmap_get(ctx->lookup_map, entry->name);
        if (static_entry == NULL || static_entry->value == NULL) {
            if (entries != NULL) {
                hpack_entry = _hpack_entry_in_list(entries, entry->value);
                index = hpack_entry == NULL ? 0 : (ctx->push_index - hpack_entry->push_index + 61);
            }
            if (static_entry != NULL && (hpack_entry == NULL || hpack_entry->value == NULL)) {
                hpack_entry = static_entry;
                index = static_entry->push_index;
                name_only = static_name_only;
            }
            if (hpack_entry == NULL && entries != NULL) {
                name_only = 1;
                hpack_entry = entries->head->data;
                index = hpack_entry == NULL ? 0 : (ctx->push_index - hpack_entry->push_index + 61);
            }
        } else {
            hpack_entry = static_entry;
            index = static_entry->push_index;
            name_only = static_name_only;
        }
        if (name_only || hpack_entry == NULL || hpack_entry->value == NULL) {
            // 6.2.1
            while (!hpack_encode_integer((uint8_t) (never_index ? 0b10000 : (0b01 << 6)), (uint8_t) (never_index ? 0b1111 : 0b111111), index, out, &out_i, out_cap)) {
                out_cap *= 2;
                out = prealloc(pool, out, out_cap);
            }
            while (index == 0 && !hpack_encode_string(pool, entry->name, 1, out, &out_i, out_cap)) {
                out_cap *= 2;
                out = prealloc(pool, out, out_cap);
            }
            while (!hpack_encode_string(pool, entry->value, 1, out, &out_i, out_cap)) {
                out_cap *= 2;
                out = prealloc(pool, out, out_cap);
            }
            if (!never_index) {
                hpack_entry = pmalloc(ctx->pool, sizeof(struct hpack_entry));
                hpack_entry->key = str_dup(entry->name, 0, pool);
                hpack_entry->value = str_dup(entry->value, 0, pool);
                hpack_add_entry(ctx, hpack_entry);
                if (entries == NULL) {
                    hashmap_put(ctx->lookup_map, entry->name, entries = llist_new(ctx->pool));
                }
                llist_append(entries, hpack_entry);
                hpack_entry->lookup_node = llist_append(entries, hpack_entry);
                hpack_entry->containing_lookup_list = entries;
            }
        } else {
            // 6.1: hpack_entry != NULL
            while (!hpack_encode_integer(0b1 << 7, 0b1111111, index, out, &out_i, out_cap)) {
                out_cap *= 2;
                out = prealloc(pool, out, out_cap);
            }
        }
        ITER_LLIST_END();
    }
    *out_length = out_i;
    return out;
}

