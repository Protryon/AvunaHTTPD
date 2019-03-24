/*
 * http.c
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

#include "http.h"
#include "xstring.h"
#include <errno.h>

const char* getMethod(int m) {
    if (m == METHOD_GET) {
        return "GET";
    } else if (m == METHOD_POST) {
        return "POST";
    } else if (m == METHOD_HEAD) {
        return "HEAD";
    } else {
        return "UNKNOWN";
    }
}

int parseRequest(struct request_session* rs, char* data, size_t maxPost) {
    struct request* req = rs->request;
    req->add_to_cache = 0;
    char* cd = data;
    char* eol1 = strchr(cd, '\n');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    eol1 = strchr(cd, ' ');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    if (str_eq_case(cd, "GET")) {
        req->method = METHOD_GET;
    } else if (str_eq_case(cd, "POST")) {
        req->method = METHOD_POST;
    } else if (str_eq_case(cd, "HEAD")) {
        req->method = METHOD_HEAD;
    } else {
        req->method = METHOD_UNK;
    }
    cd = eol1 + 1;
    eol1 = strchr(cd, ' ');
    if (eol1 == NULL) {
        errno = EINVAL;
        return -1;
    }
    eol1[0] = 0;
    size_t pl = strlen(cd) + 1;
    req->path = pmalloc(rs->pool, pl);
    memcpy(req->path, cd, pl);
    cd = eol1 + 1;
    cd = str_trim(cd);
    pl = strlen(cd) + 1;
    req->version = pmalloc(rs->pool, pl);
    memcpy(req->version, cd, pl);
    cd += pl + 1;
    req->headers = pcalloc(rs->pool, sizeof(struct headers));
    header_parse(req->headers, cd, 0, rs->pool);
    req->body = NULL;
    const char* cl = header_get(req->headers, "Content-Length");
    if (req->method == METHOD_POST && cl != NULL && str_isunum(cl)) {
        size_t cli = strtoull(cl, NULL, 10);
        if (cli > 0 && (maxPost == 0 || cli < maxPost)) {
            req->body = pmalloc(rs->pool, sizeof(struct body));
            req->body->len = cli;
            req->body->data = pmalloc(rs->pool, cli);
            const char* tmp = header_get(req->headers, "Content-Type");
            req->body->mime_type = tmp == NULL ? "application/x-www-form-urlencoded" : tmp;
            req->body->stream_fd = -1;
            req->body->stream_type = STREAM_TYPE_INVALID;
        }
    }
    return 0;
}

unsigned char* serializeRequest(struct request_session* rs, size_t* len) {
    *len = 0;
    const char* ms = getMethod(rs->request->method);
    size_t vl = strlen(ms);
    size_t cl = strlen(rs->request->path);
    size_t rvl = strlen(rs->request->version);
    *len = vl + 1 + cl + 1 + rvl + 2;
    size_t hl = 0;
    char* headers = header_serialize(rs->request->headers, &hl);
    *len += hl;
    if (rs->response->body != NULL) *len += rs->response->body->len;
    unsigned char* ret = pmalloc(rs->pool, *len);
    size_t wr = 0;
    memcpy(ret, ms, vl);
    wr += vl;
    ret[wr++] = ' ';
    memcpy(ret + wr, rs->request->path, cl);
    wr += cl;
    ret[wr++] = ' ';
    memcpy(ret + wr, rs->request->version, rvl);
    wr += rvl;
    ret[wr++] = '\r';
    ret[wr++] = '\n';
    memcpy(ret + wr, headers, hl);
    wr += hl;
    if (rs->request->method == METHOD_POST && rs->request->body != NULL) {
        memcpy(ret + wr, rs->response->body->data, rs->response->body->len);
        wr += rs->response->body->len;
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
    rs->response->version = str_dup(cd, 0, rs->pool);
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
    size_t vl = strlen(rs->response->version);
    size_t cl = strlen(rs->response->code);
    *len = vl + 1 + cl + 2;
    size_t hl = 0;
    char* headers = header_serialize(rs->response->headers, &hl);
    *len += hl;
    if (rs->response->body != NULL && rs->response->body->stream_type < 0) *len += rs->response->body->len;
    unsigned char* ret = pmalloc(rs->conn->pool, *len);
    size_t wr = 0;
    memcpy(ret, rs->response->version, vl);
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
