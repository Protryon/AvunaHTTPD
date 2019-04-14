//
// Created by p on 3/30/19.
//

#include <avuna/headers.h>
#include <avuna/string.h>
#include <avuna/provider.h>
#include <avuna/buffer.h>
#include <avuna/connection.h>
#include <avuna/globals.h>
#include <mod_htdocs/gzip.h>
#include <zlib.h>

int should_gzip(struct request_session* rs) {
    const char* content_encoding = header_get(rs->response->headers, "Content-Encoding");
    if (content_encoding != NULL) {
        return -1;
    }
    if (rs->response->body != NULL && content_encoding == NULL && (rs->response->body->type == PROVISION_STREAM || rs->response->body->data.data.size > 1024)) {
        return str_contains(header_get(rs->request->headers, "Accept-Encoding"), "gzip");
    }
    return 0;
}


int gzip_total(struct request_session* rs) {
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    int dr = 0;
    if ((dr = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY)) !=
        Z_OK) { // TODO: configurable level?
        errlog(rs->conn->server->logsess, "Error with zlib defaultInit2: %i", dr);
        return 1;
    }
    strm.avail_in = rs->response->body->data.data.size;
    strm.next_in = rs->response->body->data.data.data;
    void* cdata = pmalloc(rs->response->body->pool, 16384);
    size_t ts = 0;
    size_t cc = 16384;
    strm.avail_out = cc - ts;
    strm.next_out = cdata + ts;
    do {
        strm.avail_out  = cc - ts;
        strm.next_out = cdata + ts;
        dr = deflate(&strm, Z_FINISH);
        ts = strm.total_out;
        if (ts >= cc) {
            cc *= 2;
            cdata = prealloc(rs->response->body->pool, cdata, cc);
        }
        if (dr == Z_STREAM_ERROR) {
            errlog(rs->conn->server->logsess, "Stream error with zlib deflate");
            deflateEnd(&strm);
            return 1;
        }
    } while (strm.avail_out == 0);
    deflateEnd(&strm);
    cdata = prealloc(rs->pool, cdata, ts); // shrink
    rs->response->body->data.data.data = cdata;
    rs->response->body->data.data.size = ts;
    return 0;
}

struct gzip_stream_data {
    struct provision* parent;
    struct buffer in_data;
    z_stream strm;
    int finished;
};

ssize_t gzip_stream_read(struct provision* provision, struct provision_data* buffer) {
    struct gzip_stream_data* data = provision->data.stream.extra;
    if (data->finished) {
        return 0;
    }
    struct provision_data output;
    output.data = NULL;
    output.size = 0;
    ssize_t read = data->parent->data.stream.read(data->parent, &output);
    if (read == 0) {
        if (output.size > 0) {
            buffer_push(&data->in_data, output.data, output.size);
        }
    } else if (read < 0) {
        return read;
    } else {
        buffer_push(&data->in_data, output.data, output.size);
    }
    size_t out_cap = data->in_data.size;
    if (out_cap < 16) {
        out_cap = 1024;
    }
    void* out = pmalloc(provision->pool, out_cap);
    //TODO: will gzip not like having such small inputs due to linked buffer boundaries?
    data->strm.next_out = out;
    data->strm.avail_out = (uInt) out_cap;
    while (data->in_data.size > 0 || read == 0) {
        struct buffer_entry* entry = NULL;
        if (data->in_data.buffers->head == NULL) {
            data->strm.next_in = NULL;
            data->strm.avail_in = 0;
        } else {
            entry = data->in_data.buffers->head->data;
            data->strm.next_in = entry->data;
            data->strm.avail_in = (uInt) entry->size;
        }
        int status;
        while ((status = deflate(&data->strm, (read == 0 && data->in_data.buffers->size <= 1) ? Z_FINISH : Z_NO_FLUSH)) == Z_BUF_ERROR) {
            out_cap *= 2;
            size_t offset = (void*) data->strm.next_out - out;
            out = prealloc(provision->pool, out, out_cap);
            data->strm.next_out = out + offset;
            data->strm.avail_out = (uInt) (out_cap - offset);
        }
        if (status == Z_STREAM_ERROR) {
            data->finished = 1;
            deflateEnd(&data->strm);
            return -1;
        } else if (status == Z_STREAM_END) {
            data->finished = 1;
            deflateEnd(&data->strm);
            break;
        } else if (entry != NULL) {
            size_t consumed = entry->size - data->strm.avail_in;
            if (consumed > 0) {
                buffer_skip(&data->in_data, consumed);
            } else if (consumed == 0) {
                if (read == 0) {
                    errlog(delog, "GZIP error: cannot consume data when needing to finish deflation.");
                    return -1;
                }
                break;
            }
        }
    }
    buffer->data = out;
    buffer->size = (void*) data->strm.next_out - out;
    return buffer->size;
}

int init_gzip_stream(struct request_session* rs, struct provision* parent, struct provision* provision) {
    struct gzip_stream_data* data = provision->data.stream.extra = pcalloc(parent->pool, sizeof(struct gzip_stream_data));
    provision->data.stream.known_length = -1;
    data->parent = parent;
    buffer_init(&data->in_data, parent->pool);
    int dr = 0;
    if ((dr = deflateInit2(&data->strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY)) !=
        Z_OK) {
        errlog(rs->conn->server->logsess, "Error with zlib defaultInit2: %i", dr);
        return 1;
    }
    provision->data.stream.extra = data;
    provision->data.stream.read = gzip_stream_read;
    provision->data.stream.notify = NULL;
    return 0;
}