/*
 * util.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */
#include <avuna/http_util.h>
#include <avuna/string.h>
#include <avuna/http.h>
#include <avuna/globals.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/limits.h>
#include <errno.h>
#include <sys/stat.h>

char* escapehtml(struct mempool* pool, const char* orig) {
    size_t len = strlen(orig);
    size_t clen = len + 1;
    size_t ioff = 0;
    char* ns = pmalloc(pool, clen);
    for (int i = 0; i < len; i++) {
        if (orig[i] == '&') {
            clen += 4;
            ns = prealloc(pool, ns, clen);
            ns[i + ioff] = '&';
            ns[i + ioff++] = 'a';
            ns[i + ioff++] = 'm';
            ns[i + ioff++] = 'p';
            ns[i + ioff++] = ';';
        } else if (orig[i] == '\"') {
            clen += 5;
            ns = prealloc(pool, ns, clen);
            ns[i + ioff] = '&';
            ns[i + ioff++] = 'q';
            ns[i + ioff++] = 'u';
            ns[i + ioff++] = 'o';
            ns[i + ioff++] = 't';
            ns[i + ioff++] = ';';
        } else if (orig[i] == '\'') {
            clen += 5;
            ns = prealloc(pool, ns, clen);
            ns[i + ioff] = '&';
            ns[i + ioff++] = '#';
            ns[i + ioff++] = '0';
            ns[i + ioff++] = '3';
            ns[i + ioff++] = '9';
            ns[i + ioff++] = ';';
        } else if (orig[i] == '<') {
            clen += 3;
            ns = prealloc(pool, ns, clen);
            ns[i + ioff] = '&';
            ns[i + ioff++] = 'l';
            ns[i + ioff++] = 't';
            ns[i + ioff++] = ';';
        } else if (orig[i] == '>') {
            clen += 3;
            ns = prealloc(pool, ns, clen);
            ns[i + ioff] = '&';
            ns[i + ioff++] = 'g';
            ns[i + ioff++] = 't';
            ns[i + ioff++] = ';';
        } else {
            ns[i + ioff] = orig[i];
        }
    }
    ns[clen - 1] = 0;
    return ns;
}


void generateBaseErrorPage(struct request_session* rs, const char* msg) {
    if (rs->response->body == NULL) {
        rs->response->body = pcalloc(rs->pool, sizeof(struct provision));
    }
    char* rmsg = escapehtml(rs->pool, msg);
    size_t ml = strlen(rmsg);
    size_t cl = strlen(rs->response->code);
    size_t len = 120 + ml + (2 * cl);
    rs->response->body->type = PROVISION_DATA;
    rs->response->body->content_type = "text/html";
    rs->response->body->data.data.size = len;
    void* data = rs->response->body->data.data.data = pmalloc(rs->pool, len);
    static char* d1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>";
    size_t d1s = strlen(d1);
    size_t wr = 0;
    memcpy(data + wr, d1, d1s);
    wr += d1s;
    size_t cs = strlen(rs->response->code);
    memcpy(data + wr, rs->response->code, cs);
    wr += cs;
    static char* d2 = "</title></head><body><h1>";
    size_t d2s = strlen(d2);
    memcpy(data + wr, d2, d2s);
    wr += d2s;
    memcpy(data + wr, rs->response->code, cs);
    wr += cs;
    static char* d3 = "</h1><p>";
    size_t d3s = strlen(d3);
    memcpy(data + wr, d3, d3s);
    wr += d3s;
    memcpy(data + wr, rmsg, ml);
    wr += ml;
    static char* d4 = "</p></body></html>";
    size_t d4s = strlen(d4);
    memcpy(data + wr, d4, d4s);
    wr += d4s;
}


char* config_get_default(struct config_node* node, char* key, char* def) {
    char* result = (char*) config_get(node, key);
    if (result == NULL) {
        if (def == NULL) {
            errlog(delog, "No %s at vhost %s, no default is available.", key, node->name);
        } else {
            result = def;
            errlog(delog, "No %s at vhost %s, assuming default \"%s\".", key, node->name, def);
        }
    }
    return result;
}
