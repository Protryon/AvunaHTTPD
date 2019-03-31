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

    //TODO: stream posts?
    const char* cl = header_get(request->headers, "Content-Length");
    if (str_eq(request->method, "POST") && cl != NULL && str_isunum(cl)) {
        size_t cli = strtoull(cl, NULL, 10);
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

unsigned char* serializeRequest(struct request_session* rs, size_t* len) {
    *len = 0;
    size_t vl = strlen(rs->request->method);
    size_t cl = strlen(rs->request->path);
    size_t rvl = strlen(rs->request->http_version);
    *len = vl + 1 + cl + 1 + rvl + 2;
    size_t hl = 0;
    char* headers = header_serialize(rs->request->headers, &hl);
    *len += hl;
    if (rs->response->body != NULL && rs->response->body->type == PROVISION_DATA) {
        *len += rs->response->body->data.data.size;
    }
    unsigned char* ret = pmalloc(rs->pool, *len);
    size_t wr = 0;
    memcpy(ret, rs->request->method, vl);
    wr += vl;
    ret[wr++] = ' ';
    memcpy(ret + wr, rs->request->path, cl);
    wr += cl;
    ret[wr++] = ' ';
    memcpy(ret + wr, rs->request->http_version, rvl);
    wr += rvl;
    ret[wr++] = '\r';
    ret[wr++] = '\n';
    memcpy(ret + wr, headers, hl);
    wr += hl;
    if (rs->response->body != NULL && rs->response->body->type == PROVISION_DATA) {
        memcpy(ret + wr, rs->response->body->data.data.data, rs->response->body->data.data.size);
        wr += rs->response->body->data.data.size;
    }
    return ret;
}

int parseResponse(struct request_session* rs, char* data) {
    rs->response->parsed = 1;
    char* cd = data;
    char* eol1 = strchr(cd, '\n');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    char* hdrs = eol1 + 1;
    eol1 = strchr(cd, ' ');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    eol1++;
    rs->response->http_version = str_dup(cd, 0, rs->pool);
    size_t eols = strlen(eol1);
    if (eol1[eols - 1] == '\r') eol1[eols - 1] = 0;
    rs->response->code = str_dup(eol1, 0, rs->pool);
    header_parse(rs->response->headers, hdrs, 3, rs->pool);
    const char* cl = header_get(rs->response->headers, "Content-Length");
    if (cl != NULL && str_isunum(cl)) {
        size_t cli = strtoull(cl, NULL, 10);
        rs->response->body = pmalloc(rs->pool, sizeof(struct body));
        rs->response->body->len = cli;
        rs->response->body->data = NULL;
        rs->response->body->mime_type = header_get(rs->response->headers, "Content-Type");
        if (rs->response->body->mime_type == NULL) {
            rs->response->body->mime_type = "text/html";
        }
        rs->response->body->stream_fd = rs->conn->forward_conn->fd;
        rs->response->body->stream_type = STREAM_TYPE_RAW;
    }
    const char* te = header_get(rs->response->headers, "Transfer-Encoding");
    if (te != NULL) {
        rs->response->body = pmalloc(rs->pool, sizeof(struct body));
        rs->response->body->len = 0;
        rs->response->body->data = NULL;
        rs->response->body->mime_type = header_get(rs->response->headers, "Content-Type");
        if (rs->response->body->mime_type == NULL) {
            rs->response->body->mime_type = "text/html";
        }
        rs->response->body->stream_fd = rs->conn->forward_conn->fd;
        rs->response->body->stream_type = STREAM_TYPE_CHUNKED;
    }
    return 0;
}

unsigned char* serializeResponse(struct request_session* rs, size_t* len) {
    *len = 0;
    size_t vl = strlen(rs->response->http_version);
    size_t cl = strlen(rs->response->code);
    *len = vl + 1 + cl + 2;
    size_t hl = 0;
    char* headers = header_serialize(rs->response->headers, &hl);
    *len += hl;
    if (rs->response->body != NULL && rs->response->body->stream_type < 0) *len += rs->response->body->len;
    unsigned char* ret = pmalloc(rs->conn->pool, *len);
    size_t wr = 0;
    memcpy(ret, rs->response->http_version, vl);
    wr += vl;
    ret[wr++] = ' ';
    memcpy(ret + wr, rs->response->code, cl);
    wr += cl;
    ret[wr++] = '\r';
    ret[wr++] = '\n';
    memcpy(ret + wr, headers, hl);
    wr += hl;
    if (rs->request->method != METHOD_HEAD && rs->response->body != NULL && rs->response->body->stream_type < 0) {
        memcpy(ret + wr, rs->response->body->data, rs->response->body->len);
        wr += rs->response->body->len;
    }
    return ret;
}
