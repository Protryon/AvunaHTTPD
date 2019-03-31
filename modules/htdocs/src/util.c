//
// Created by p on 3/30/19.
//

#include <mod_htdocs/util.h>
#include <mod_htdocs/vhost_htdocs.h>
#include <avuna/pmem.h>
#include <avuna/string.h>
#include <avuna/http.h>
#include <avuna/provider.h>
#include <avuna/globals.h>
#include <stdlib.h>
#include <zlib.h>

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


void generateDefaultErrorPage(struct request_session* rs, const char* msg) {
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
    if (rs->vhost == NULL) {
        return;
    }
    char* page = hashmap_getptr(HTBASE(rs->vhost)->error_pages, (void*) strtoul(rs->response->code, NULL, 10));
    if (page != NULL) {
        header_add(rs->response->headers, "Location", page);
    }
}

int check_cache(struct request_session* rs) {
    struct vhost* vhost = rs->vhost;
    struct scache* osc = cache_get(HTBASE(vhost)->cache, rs->request->path,
                                   str_contains(header_get(rs->request->headers, "Accept-Encoding"), "gzip"));
    if (osc != NULL) {
        rs->response->body = osc->body;
        rs->request->add_to_cache = 1;
        rs->response->headers = osc->headers;
        rs->response->code = osc->code;
        if (rs->response->body != NULL && rs->response->body->data.data.size > 0 && rs->response->code != NULL &&
            rs->response->code[0] == '2') {
            if (str_eq_case(osc->etag, header_get(rs->request->headers, "If-None-Match"))) {
                rs->response->code = "304 Not Modified";
                rs->response->body = NULL;
            }
        }
        return 1;
    }
    return 0;
}

void check_client_cache(struct request_session* rs) {
    struct vhost* vhost = rs->vhost;
    struct vhost_htbase* base = HTBASE(vhost);
    if (base->maxAge > 0 && rs->response->body != NULL) {
        int cache_found = 0;
        for (size_t i = 0; i < base->cache_types->count; i++) {
            if (str_eq(base->cache_types->data[i], rs->response->body->content_type)) {
                cache_found = 1;
                break;
            } else if (str_suffixes_case(base->cache_types->data[i], "/*")) {
                char* nct = str_dup(base->cache_types->data[i], 0, rs->pool);
                nct[strlen(nct) - 1] = 0;
                if (str_prefixes_case(rs->response->body->content_type, nct)) {
                    cache_found = 1;
                    break;
                }
            }
        }

        char ccbuf[64];
        memcpy(ccbuf, "max-age=", 8);
        int snr = snprintf(ccbuf + 8, 18, "%lu", base->maxAge);
        if (cache_found) {
            memcpy(ccbuf + 8 + snr, ", no-cache", 11);
        } else {
            ccbuf[8 + snr] = 0;
        }
        header_add(rs->response->headers, "Cache-Control", ccbuf);
    }
}


char* load_default(struct config_node* node, char* key, char* def) {
    char* result = getConfigValue(node, key);
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