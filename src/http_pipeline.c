//
// Created by p on 2/10/19.
//

#include "http_pipeline.h"
#include <avuna/string.h>
#include <avuna/util.h>
#include <avuna/version.h>
#include <avuna/mime.h>
//#include "../modules/fcgi/src/fcgi_connection_manager.h"
//#include "../modules/fcgi/src/fcgi.h"
#include <avuna/pmem_hooks.h>
#include <errno.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <fcntl.h>


void init_response(struct request_session* rs) {
    rs->response->parsed = 0;
    rs->response->version = rs->request->version;
    rs->response->code = "200 OK";
    rs->response->headers->count = 0;
    rs->response->headers->names = NULL;
    rs->response->headers->values = NULL;
    const char* host = header_get(rs->request->headers, "Host");
    if (host == NULL) host = "";
    struct vhost* vhost = NULL;
    for (size_t i = 0; i < rs->worker->server->vhosts->count; i++) {
        struct vhost* iter_vhost = rs->worker->server->vhosts->data[i];
        if (iter_vhost->hosts->count == 0) {
            vhost = iter_vhost;
            break;
        } else
            for (size_t x = 0; x < iter_vhost->hosts->count; x++) {
                if (domeq(iter_vhost->hosts->data[x], host)) {
                    vhost = iter_vhost;
                    break;
                }
            }
        if (vhost != NULL) break;
    }
    rs->request->vhost = vhost;
}


void handle_vhost_redirect(struct request_session* rs) {
    struct vhost* vhost = rs->request->vhost;
    rs->response->code = "302 Found";
    header_add(rs->response->headers, "Location", vhost->sub.redirect.redir);
}

void handle_vhost_mount(struct request_session* rs) {
    struct vhost* vhost = rs->request->vhost;
    struct vhost_mount* vhm = &vhost->sub.mount;
    char* oid = vhost->id;
    vhost = NULL;
    for (int i = 0; i < vhm->mounts->count; i++) {
        struct mountpoint* mount = vhm->mounts->data[i];
        if (str_prefixes_case(rs->request->path, mount->path)) {
            for (size_t x = 0; x < rs->worker->server->vhosts->count; x++) {
                struct vhost* iter_vhost = rs->worker->server->vhosts->data[x];
                if (str_eq(mount->vhost, iter_vhost->id) && !str_eq(iter_vhost->id, oid)) {
                    if (!vhm->keep_prefix) {
                        size_t vhpls = strlen(mount->path);
                        char* tmpp = str_dup(rs->request->path, 0, rs->pool);
                        char* tmpp2 = tmpp + vhpls;
                        if (tmpp2[0] != '/') {
                            tmpp2--;
                            tmpp2[0] = '/';
                        }
                        rs->request->path = tmpp2;
                    }
                    vhost = iter_vhost;
                    rs->request->vhost = vhost;
                    break;
                }
            }
            if (vhost != NULL) break;
        }
    }
}

int generateResponse(struct request_session* rs) {
    init_response(rs);
    restart:;
    struct vhost* vhost = rs->request->vhost;
    const char* upg = header_get(rs->request->headers, "Upgrade");
    if (!str_eq_case(rs->response->version, "HTTP/2.0")) {
        if (upg != NULL && str_eq_case(upg, "h2")) {
            //header_set(rs->response->headers, "Upgrade", "h2");
            //printf("upgrade: %s\n", header_get(rs->response->headers, "HTTP2-Settings"));
        }
    }
    header_add(rs->response->headers, "Server", "Avuna/" VERSION);
    rs->response->body = NULL;
    header_add(rs->response->headers, "Connection", "keep-alive");
    int rp = vhost->type == VHOST_RPROXY;
    if (vhost == NULL) {
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "There was no website found at this domain! If you believe this to be an error, please contact your system administrator.");
    } else if (vhost->type == VHOST_HTDOCS) {
        handle_vhost_htdocs(rs);
    } else if (rp) {
        handle_vhost_rproxy(rs);
    } else if (vhost->type == VHOST_REDIRECT) {
        handle_vhost_redirect(rs);
    } else if (vhost->type == VHOST_MOUNT) {
        handle_vhost_mount(rs);
        goto restart; // mount always restarts
    }
//body stuff
    if (!rp && rs->response->body != NULL && rs->response->body->mime_type != NULL) {
        header_setoradd(rs->response->headers, "Content-Type", rs->response->body->mime_type);
    }
    if (!rp) {
        char l[16];
        if (rs->response->body != NULL) sprintf(l, "%lu", rs->response->body->len);
        header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
    }
    return 0;
}
