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
#include <avuna/http_util.h>
#include <stdlib.h>
#include <zlib.h>

void generateDefaultErrorPage(struct request_session* rs, const char* msg) {
    generateBaseErrorPage(rs, msg);
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