//
// Created by p on 2/10/19.
//

#include "http_pipeline.h"
#include "http2_network.h"
#include <avuna/string.h>
#include <avuna/http_util.h>
#include <avuna/version.h>
#include <avuna/mime.h>
#include <avuna/pmem_hooks.h>
#include <avuna/provider.h>
#include <avuna/module.h>
#include <errno.h>

int domeq(const char* dom1, const char* dom2) {
    if (str_eq_case(dom1, "@") || str_eq_case(dom1, "*")) return 1;
    char* d1 = str_dup(dom1, 1, NULL);
    size_t d1l = strlen(dom1);
    for (size_t i = 0; i < d1l; i++) {
        if (d1[i] == '.') d1[i] = 0;
    }
    d1[d1l + 1] = 0;
    char* od1 = d1;
    char* d2 = str_dup((char*) dom2, 0, NULL);
    char* sp2 = NULL;
    char* m2 = NULL;
    while (strlen(d1) > 0) {
        m2 = strtok_r(m2 == NULL ? d2 : NULL, ".", &sp2);
        if (str_eq_case(d1, "*")) goto cont;
        if (str_eq_case(d1, "**")) {
            char* nd = d1 + strlen(d1) + 1;
            if (m2 == NULL && strlen(nd) == 0) break;
            else if (m2 == NULL) {
                free(od1);
                free(d2);
                return 0;
            }
            if (strlen(nd) > 0 && (!str_eq_case(nd, "*") && !str_eq(nd, m2))) {
                continue;
            } else {
                d1 = nd;
                goto cont;
            }
        }
        if (m2 == NULL || !str_eq(d1, m2)) {
            free(od1);
            free(d2);
            return 0;
        }
        cont:;
        d1 = d1 + strlen(d1) + 1;
    }
    free(od1);
    free(d2);
    return 1;
}

int generateResponse(struct request_session* rs) {
    restart:;
    rs->response->body = NULL;
    header_add(rs->response->headers, "Server", "Avuna/" VERSION);
    header_add(rs->response->headers, "Connection", "keep-alive");
    int vhost_action = VHOST_ACTION_NONE;
    if (rs->vhost == NULL) {
        rs->response->code = "500 Internal Server Error";
        generateBaseErrorPage(rs,
                                 "There was no website found at this domain! If you believe this to be an error, please contact your system administrator.");
    } else {
        vhost_action = rs->vhost->sub->handle_request(rs);
    }
    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_request_processed) {
            module->events.on_request_processed(module, rs);
        }
        ITER_LLIST_END();
    }
    if (vhost_action == VHOST_ACTION_RESTART) {
        goto restart;
    }

    // content update
    if (vhost_action != VHOST_ACTION_NO_CONTENT_UPDATE && rs->response->body != NULL) {
        updateContentHeaders(rs);
    }
    return 0;
}
