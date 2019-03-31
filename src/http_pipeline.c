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

void handle_vhost_rproxy(struct request_session* rs) {
    struct vhost* vhost = rs->request->vhost;
    int isStatic = 1;
    size_t htdl = 0;
    size_t pl = strlen(rs->request->path);
    char* tp = pmalloc(rs->pool, htdl + pl);
    memcpy(tp + htdl, rs->request->path + 1, pl);
    tp[htdl + pl - 1] = 0;
    char* ttp = strchr(tp, '#');
    if (ttp != NULL) ttp[0] = 0;
    ttp = strchr(tp, '?');
    if (ttp != NULL) ttp[0] = 0;
    if (vhost->sub.htdocs.scacheEnabled) {
        if(check_cache(rs)) {
            return;
        }
    }
    if (pl < 1 || rs->request->path[0] != '/') {
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "Malformed Request! If you believe this to be an error, please contact your system administrator.");
        goto epage;
    }

    int ff = (pl > 1 && tp[htdl + pl - 2] != '/');

    int indf = 0;
    if (!ff) {
        char* tt = str_dup(rs->request->path, 2, rs->pool);
        char* ppl = strrchr(tt, '/'); // no extra path because extra paths dont work on directories
        size_t ppll = strlen(ppl);

        if (ppl != NULL && (ppll > 1 && ppl[1] != '?' && ppl[1] != '#')) {
            rs->response->code = "302 Found";
            char* el = strpbrk(ppl, "?#");
            if (el != NULL) {
                memmove(el, el + 1, strlen(el) + 1);
                el[0] = '/';
            } else {
                size_t ttl = strlen(tt);
                tt[ttl] = '/';
                tt[ttl + 1] = 0;
            }
            header_add(rs->response->headers, "Location", tt);
            return;
        }

        if (!indf) {
            rs->response->code = "404 Not Found";
            generateDefaultErrorPage(rs,
                                     "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
            goto epage;
        }
    }
    //TODO: overrides
    if (rs->conn->forward_conn == NULL) {
        rs->conn->forward_conn = pcalloc(rs->pool, sizeof(struct sub_conn));
        rs->conn->forward_conn->fd = -1;
        buffer_init(&rs->conn->forward_conn->read_buffer, rs->conn->pool);
        //todo: TLS
    }
    resrp:;
    if (rs->conn->forward_conn->fd < 0) {
        rs->conn->forward_conn->fd = socket(vhost->sub.rproxy.fwaddr->sa_family == AF_INET ? PF_INET : PF_LOCAL,
                                            SOCK_STREAM, 0);
        if (rs->conn->forward_conn->fd < 0 ||
            connect(rs->conn->forward_conn->fd, vhost->sub.rproxy.fwaddr, vhost->sub.rproxy.fwaddrlen) < 0) {
            errlog(rs->worker->server->logsess, "Failed to create/connect to forwarding socket: %s",
                   strerror(errno));
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
            goto epage;
        }
        phook(rs->pool, close_hook, (void*) rs->conn->forward_conn->fd);
    }
    size_t sreql = 0;
    unsigned char* sreq = serializeRequest(rs, &sreql);
    size_t wr = 0;
    while (wr < sreql) {
        ssize_t x = write(rs->conn->forward_conn->fd, sreq + wr, sreql - wr);
        if (x < 1) {
            // we should ideally close the current connection here, but it will have to wait until the connection closes due to the `phook` call above.
            rs->conn->forward_conn->fd = -1;
            goto resrp;
        }
        wr += x;
    }

    if (rs->conn->fw_queue == NULL) {
        rs->conn->fw_queue = queue_new(0, 1, rs->pool);
    }
    // why do we copy here?
    struct request_session* rs2 = pmalloc(rs->pool, sizeof(struct request_session));
    memcpy(rs2, rs, sizeof(struct request_session));
    queue_push(rs->conn->fw_queue, rs2);

    check_client_cache(rs);

    //TODO: CGI
    //TODO: SCGI
    //TODO: SO-CGI
    //TODO: SSI
    epage:;

    maybe_gzip(rs);

    if (isStatic && vhost->sub.htdocs.scacheEnabled &&
        (vhost->sub.htdocs.maxCache <= 0 || vhost->sub.htdocs.maxCache < vhost->sub.htdocs.cache->max_size)) {
            rs->request->add_to_cache = 1;
    }
    //TODO: Chunked
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
