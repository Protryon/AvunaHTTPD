/*
 * http.c
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

#include <avuna/http.h>
#include <avuna/string.h>
#include <avuna/provider.h>
#include <errno.h>

int parseRequest(struct request_session* rs, char* data, size_t maxPost) {
    struct request* request = rs->request;
    request->add_to_cache = 0;
    char* temp = data;
    char* eol1 = strchr(temp, '\n');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    eol1 = strchr(temp, ' ');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    request->method = str_dup(temp, 0, rs->pool);
    temp = eol1 + 1;
    eol1 = strchr(temp, ' ');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    size_t temp_len = strlen(temp) + 1;
    request->path = pmalloc(rs->pool, temp_len);
    memcpy(request->path, temp, temp_len);
    temp = eol1 + 1;
    temp = str_trim(temp);
    temp_len = strlen(temp) + 1;
    request->http_version = pmalloc(rs->pool, temp_len);
    memcpy(request->http_version, temp, temp_len);
    temp += temp_len + 1;
    request->headers = pcalloc(rs->pool, sizeof(struct headers));
    header_parse(request->headers, temp, 0, rs->pool);
    request->body = NULL;

    //TODO: for streaming posts (large posts or chunked posts), return a streamed type provision
    const char* content_length = header_get(request->headers, "Content-Length");
    if (str_eq(request->method, "POST") && content_length != NULL && str_isunum(content_length)) {
        size_t cli = strtoull(content_length, NULL, 10);
        if (cli > 0 && (maxPost == 0 || cli < maxPost)) {
            request->body = pcalloc(rs->pool, sizeof(struct provision));
            request->body->pool = rs->pool;
            request->body->type = PROVISION_DATA;
            const char* tmp = header_get(request->headers, "Content-Type");
            request->body->content_type = (char*) (tmp == NULL ? "application/x-www-form-urlencoded" : tmp);
            request->body->data.data.data = pmalloc(rs->pool, cli);
            request->body->data.data.size = cli;
        }
    }
    return 0;
}

unsigned char* serializeRequest(struct request_session* rs, size_t* out_len) {
    *out_len = 0;
    size_t method_length = strlen(rs->request->method);
    size_t path_length = strlen(rs->request->path);
    size_t http_version_length = strlen(rs->request->http_version);
    *out_len = method_length + 1 + path_length + 1 + http_version_length + 2;
    size_t headers_length = 0;
    char* headers = header_serialize(rs->request->headers, &headers_length);
    *out_len += headers_length;
    if (rs->request->body != NULL && rs->request->body->type == PROVISION_DATA) {
        *out_len += rs->request->body->data.data.size;
    }
    unsigned char* output = pmalloc(rs->pool, *out_len);
    size_t written = 0;
    memcpy(output, rs->request->method, method_length);
    written += method_length;
    output[written++] = ' ';
    memcpy(output + written, rs->request->path, path_length);
    written += path_length;
    output[written++] = ' ';
    memcpy(output + written, rs->request->http_version, http_version_length);
    written += http_version_length;
    output[written++] = '\r';
    output[written++] = '\n';
    memcpy(output + written, headers, headers_length);
    written += headers_length;
    // TODO: don't copy body here
    if (rs->request->body != NULL && rs->request->body->type == PROVISION_DATA) {
        memcpy(output + written, rs->request->body->data.data.data, rs->request->body->data.data.size);
        written += rs->request->body->data.data.size;
    }
    return output;
}

int parseResponse(struct request_session* rs, struct sub_conn* sub_conn, char* data) {
    char* current_data = data;
    char* eol = strchr(current_data, '\n');
    if (eol == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol[0] = 0;
    char* headers = eol + 1;
    eol = strchr(current_data, ' ');
    if (eol == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol[0] = 0;
    eol++;
    rs->response->http_version = str_dup(current_data, 0, rs->pool);
    size_t eol_length = strlen(eol);
    if (eol[eol_length - 1] == '\r') eol[eol_length - 1] = 0;
    rs->response->code = str_dup(eol, 0, rs->pool);
    header_parse(rs->response->headers, headers, 3, rs->pool);
    const char* content_length = header_get(rs->response->headers, "Content-Length");
    if (content_length != NULL && str_isunum(content_length)) {
        size_t content_length_int = strtoull(content_length, NULL, 10);
        rs->response->body = pcalloc(rs->pool, sizeof(struct provision));
        rs->response->body->pool = mempool_new();
        pchild(rs->pool, rs->response->body->pool);
        rs->response->body->type = PROVISION_DATA;
        rs->response->body->data.data.size = content_length_int;
        rs->response->body->content_type = (char*) header_get(rs->response->headers, "Content-Type");
        if (rs->response->body->content_type == NULL) {
            rs->response->body->content_type = "text/html";
        }
    }
    const char* transfer_encoding = header_get(rs->response->headers, "Transfer-Encoding");
    if (transfer_encoding != NULL) {
        rs->response->body = pcalloc(rs->pool, sizeof(struct provision));
        rs->response->body->pool = mempool_new();
        pchild(rs->pool, rs->response->body->pool);
        rs->response->body->type = PROVISION_STREAM;
        rs->response->body->data.stream.stream_fd = -1;
        rs->response->body->data.stream.known_length = -1;
        rs->response->body->data.stream.read = chunked_read;
        struct chunked_stream_extra* extra = rs->response->body->data.stream.extra = pcalloc(rs->response->body->pool, sizeof(struct chunked_stream_extra));
        extra->sub_conn = sub_conn;
        extra->remaining = -1;
        rs->response->body->content_type = (char*) header_get(rs->response->headers, "Content-Type");
        if (rs->response->body->content_type == NULL) {
            rs->response->body->content_type = "text/html";
        }
    }
    return 0;
}

unsigned char* serializeResponse(struct request_session* rs, size_t* out_len) {
    *out_len = 0;
    size_t http_version_length = strlen(rs->response->http_version);
    size_t response_code_length = strlen(rs->response->code);
    *out_len = http_version_length + 1 + response_code_length + 2;
    size_t header_length = 0;
    char* headers = header_serialize(rs->response->headers, &header_length);
    *out_len += header_length;
    if (rs->response->body != NULL && rs->response->body->type == PROVISION_DATA) {
        *out_len += rs->response->body->data.data.size;
    }
    unsigned char* out = pmalloc(rs->conn->pool, *out_len);
    size_t written = 0;
    memcpy(out, rs->response->http_version, http_version_length);
    written += http_version_length;
    out[written++] = ' ';
    memcpy(out + written, rs->response->code, response_code_length);
    written += response_code_length;
    out[written++] = '\r';
    out[written++] = '\n';
    memcpy(out + written, headers, header_length);
    written += header_length;
    // TODO: don't copy body here
    if (!str_eq(rs->request->method, "HEAD") && rs->response->body != NULL && rs->response->body->type == PROVISION_DATA) {
        memcpy(out + written, rs->response->body->data.data.data, rs->response->body->data.data.size);
        written += rs->response->body->data.data.size;
    }
    return out;
}
