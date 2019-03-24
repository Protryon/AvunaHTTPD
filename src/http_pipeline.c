//
// Created by p on 2/10/19.
//

#include "http_pipeline.h"
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <zlib.h>
#include <fcntl.h>
#include "xstring.h"
#include "util.h"
#include "pmem.h"
#include "work.h"
#include "vhost.h"
#include "version.h"
#include "mime.h"
#include "fcgi_connection_manager.h"
#include "fcgi.h"
#include "hash.h"
#include "pmem.h"
#include "pmem_hooks.h"
#include "accept.h"
#include "server.h"

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


void generateDefaultErrorPage(struct request_session* rs, struct vhost* vh, const char* msg) {
    if (rs->response->body == NULL) {
        rs->response->body = pmalloc(rs->pool, sizeof(struct body));
    }
    char* rmsg = escapehtml(rs->pool, msg);
    size_t ml = strlen(rmsg);
    size_t cl = strlen(rs->response->code);
    size_t len = 120 + ml + (2 * cl);
    rs->response->body->len = len;
    rs->response->body->mime_type = "text/html";
    rs->response->body->stream_fd = -1;
    rs->response->body->stream_type = -1;
    rs->response->body->data = pmalloc(rs->pool, len);
    static char* d1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>";
    size_t d1s = strlen(d1);
    size_t wr = 0;
    memcpy(rs->response->body->data + wr, d1, d1s);
    wr += d1s;
    size_t cs = strlen(rs->response->code);
    memcpy(rs->response->body->data + wr, rs->response->code, cs);
    wr += cs;
    static char* d2 = "</title></head><body><h1>";
    size_t d2s = strlen(d2);
    memcpy(rs->response->body->data + wr, d2, d2s);
    wr += d2s;
    memcpy(rs->response->body->data + wr, rs->response->code, cs);
    wr += cs;
    static char* d3 = "</h1><p>";
    size_t d3s = strlen(d3);
    memcpy(rs->response->body->data + wr, d3, d3s);
    wr += d3s;
    memcpy(rs->response->body->data + wr, rmsg, ml);
    wr += ml;
    static char* d4 = "</p></body></html>";
    size_t d4s = strlen(d4);
    memcpy(rs->response->body->data + wr, d4, d4s);
    wr += d4s;
    if (vh == NULL) {
        return;
    }
    char* page = hashmap_getptr(vh->sub.htdocs.error_pages, (void*) strtoul(rs->response->code, NULL, 10));
    if (page != NULL) {
        header_add(rs->response->headers, "Location", page);
    }
}

int generateResponse(struct request_session* rs) {
    int eh = 1;
    rs->response->parsed = 0;
    rs->response->version = rs->request->version;
    rs->response->code = "200 OK";
    rs->response->headers->count = 0;
    rs->response->headers->names = NULL;
    rs->response->headers->values = NULL;
    const char* host = header_get(rs->request->headers, "Host");
    if (host == NULL) host = "";
    struct vhost* vhost = NULL;
    for (size_t i = 0; i < rs->wp->server->vhosts->count; i++) {
        struct vhost* iter_vhost = rs->wp->server->vhosts->data[i];
        if (iter_vhost->hosts->count == 0) {
            vhost = iter_vhost;
            break;
        } else for (size_t x = 0; x < iter_vhost->hosts->count; x++) {
            if (domeq(iter_vhost->hosts->data[x], host)) {
                vhost = iter_vhost;
                break;
            }
        }
        if (vhost != NULL) break;
    }
    rs->request->vhost = vhost;
    jpvh: ;
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
    int rp = 0;
    if (vhost == NULL) {
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs, NULL, "There was no website found at this domain! If you believe this to be an error, please contact your system administrator.");
    } else if (vhost->type == VHOST_HTDOCS || vhost->type == VHOST_RPROXY) {
        char* extraPath = NULL;
        rp = vhost->type == VHOST_RPROXY;
        int isStatic = 1;
        size_t htdl = rp ? 0 : strlen(vhost->sub.htdocs.htdocs);
        size_t pl = strlen(rs->request->path);
        char* tp = pmalloc(rs->pool, htdl + pl);
        if (!rp) memcpy(tp, vhost->sub.htdocs.htdocs, htdl);
        memcpy(tp + htdl, rs->request->path + 1, pl);
        tp[htdl + pl - 1] = 0;
        char* ttp = strchr(tp, '#');
        if (ttp != NULL) ttp[0] = 0;
        ttp = strchr(tp, '?');
        if (ttp != NULL) ttp[0] = 0;
        char* rtp = NULL;
        if (vhost->sub.htdocs.scacheEnabled) {
            struct scache* osc = cache_get(vhost->sub.htdocs.cache, rs->request->path,
                                           str_contains(header_get(rs->request->headers, "Accept-Encoding"), "gzip"));
            if (osc != NULL) {
                rs->response->body = osc->body;
                rs->request->atc = 1;
                rs->response->headers = osc->headers;
                rs->response->code = osc->code;
                if (rs->response->body != NULL && rs->response->body->len > 0 && rs->response->code != NULL && rs->response->code[0] == '2') {
                    if (str_eq_case(osc->etag, header_get(rs->request->headers, "If-None-Match"))) {
                        rs->response->code = "304 Not Modified";
                        rs->response->body = NULL;
                    }
                }
                goto pcacheadd;
            }
        }
        if (pl < 1 || rs->request->path[0] != '/') {
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs, vhost, "Malformed Request! If you believe this to be an error, please contact your system administrator.");
            goto epage;
        }

        int ff = !rp ? 0 : (pl > 1 && tp[htdl + pl - 2] != '/');
        if (!rp) {
            char* nxtp = str_dup(tp + 1, 1, rs->pool);
            nxtp[strlen(nxtp) + 1] = 0;
            size_t nxtpl = strlen(nxtp);
            size_t lx = 0;
            for (size_t x = 0; x < nxtpl; x++) {
                if (nxtp[x] == '/') {
                    nxtp[x] = 0;
                    if (lx == x - 1) {
                        memmove(nxtp + x, nxtp + x + 1, nxtpl - x);
                    }
                    lx = x;
                }
            }

            char* rstp = pmalloc(rs->pool, 1);
            rstp[0] = 0;
            size_t cstp = 0;
            size_t extp = 0;
            size_t clt = 0;
            while ((clt = strlen(nxtp)) > 0) {
                if (ff) {
                    if (extraPath == NULL) extraPath = pmalloc(rs->pool, extp + clt + 2);
                    else extraPath = prealloc(rs->pool, extraPath, extp + clt + 2);
                    extraPath[extp++] = '/';
                    memcpy(extraPath + extp, nxtp, clt + 1);
                    extp += clt;
                    nxtp += clt + 1;
                } else {
                    rstp = prealloc(rs->pool, rstp, cstp + clt + 2);
                    rstp[cstp++] = '/';
                    memcpy(rstp + cstp, nxtp, clt + 1);
                    cstp += clt;
                    nxtp += clt + 1;
                    struct stat cs;
                    if (stat(rstp, &cs) < 0) {
                        if (errno == ENOENT || errno == ENOTDIR) {
                            rs->response->code = "404 Not Found";
                            generateDefaultErrorPage(rs, vhost, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
                        } else if (errno == EACCES) {
                            rs->response->code = "403 Forbidden";
                            generateDefaultErrorPage(rs, vhost, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
                        } else {
                            errlog(rs->wp->server->logsess, "Error while stating file: %s", strerror(errno));
                            rs->response->code = "500 Internal Server Error";
                            generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                        }
                        goto epage;
                    }
                    if ((cs.st_mode & S_IFDIR) != S_IFDIR) {
                        ff = 1;
                    }
                }
            }
            if (!ff) {
                rstp = prealloc(rs->pool, rstp, cstp + 2);
                rstp[cstp] = '/';
                rstp[cstp + 1] = 0;
            }
            tp = rstp;
        }

        int indf = 0;
        if (!rp && !ff && !access(tp, R_OK)) { // TODO: extra paths?
            for (size_t ii = 0; ii < vhost->sub.htdocs.index->count; ii++) {
                size_t cl = strlen(vhost->sub.htdocs.index->data[ii]);
                char* tp2 = pmalloc(rs->pool, htdl + pl + cl);
                size_t l2 = strlen(tp);
                memcpy(tp2, tp, l2);
                memcpy(tp2 + l2, vhost->sub.htdocs.index->data[ii], cl + 1);
                if (!access(tp2, R_OK)) {
                    tp = tp2;
                    indf = 1;
                    break;
                }
            }
        }
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
                goto pvh;
            }

            if (!indf) {
                rs->response->code = "404 Not Found";
                generateDefaultErrorPage(rs, vhost, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
        }
        //TODO: overrides
        struct stat st;
        if (rp) {
            rtp = tp;
            tp = NULL;
        } else {
            rtp = realpath(tp, NULL);
            tp = NULL;
            if (rtp == NULL) {
                if (errno == ENOENT || errno == ENOTDIR) {
                    rs->response->code = "404 Not Found";
                    generateDefaultErrorPage(rs, vhost, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
                } else if (errno == EACCES) {
                    rs->response->code = "403 Forbidden";
                    generateDefaultErrorPage(rs, vhost, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
                } else {
                    errlog(rs->wp->server->logsess, "Error while getting the realpath of a file: %s", strerror(errno));
                    rs->response->code = "500 Internal Server Error";
                    generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                }
                goto epage;
            }
            if (stat(rtp, &st) != 0) {
                errlog(rs->wp->server->logsess, "Failed stat on <%s>: %s", rtp, strerror(errno));
                rs->response->code = "500 Internal Server Error";
                generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
            size_t rtpl = strlen(rtp);
            if ((st.st_mode & S_IFDIR) && rtp[rtpl - 1] != '/') {
                rtp = prealloc(rs->pool, rtp, ++rtpl + 1);
                rtp[rtpl - 1] = '/';
                rtp[rtpl] = 0;
            }
            if (vhost->sub.htdocs.symlock && !str_prefixes_case(rtp, vhost->sub.htdocs.htdocs)) {
                rs->response->code = "404 Not Found";
                generateDefaultErrorPage(rs, vhost, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
            if (vhost->sub.htdocs.nohardlinks && st.st_nlink != 1 && !(st.st_mode & S_IFDIR)) {
                rs->response->code = "403 Forbidden";
                generateDefaultErrorPage(rs, vhost, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
        }
        if (rp) {
            resrp: if (rs->sender->fw_fd < 0) {
            rs->sender->fw_fd = socket(vhost->sub.rproxy.fwaddr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
            if (rs->sender->fw_fd < 0 || connect(rs->sender->fw_fd, vhost->sub.rproxy.fwaddr, vhost->sub.rproxy.fwaddrlen) < 0) {
                errlog(rs->wp->server->logsess, "Failed to create/connect to forwarding socket: %s", strerror(errno));
                rs->response->code = "500 Internal Server Error";
                generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
            phook(rs->sender->pool, close_hook, (void*) rs->sender->fw_fd);
        }
            size_t sreql = 0;
            unsigned char* sreq = serializeRequest(rs, &sreql);
            size_t wr = 0;
            while (wr < sreql) {
                ssize_t x = write(rs->sender->fw_fd, sreq + wr, sreql - wr);
                if (x < 1) {
                    close(rs->sender->fw_fd);
                    rs->sender->fw_fd = -1;
                    goto resrp;
                }
                wr += x;
            }

            if (rs->sender->fwqueue == NULL) {
                rs->sender->fwqueue = queue_new(0, 1, rs->pool);
            }
            rs->sender->fwed = 1;
            eh = 0;
            struct request_session* rs2 = pmalloc(rs->pool, sizeof(struct request_session));
            memcpy(rs2, rs, sizeof(struct request_session));
            queue_push(rs->sender->fwqueue, rs2);
        } else {
            rs->response->body = pmalloc(rs->pool, sizeof(struct body));
            rs->response->body->len = 0;
            rs->response->body->data = NULL;
            const char* ext = strrchr(rtp, '.');
            if (ext == NULL) {
                rs->response->body->mime_type = "application/octet-stream";
            } else {
                const char* mime = getMimeForExt(ext + 1);
                if (mime == NULL) {
                    rs->response->body->mime_type = "application/octet-stream";
                } else {
                    rs->response->body->mime_type = mime;
                }
            }
            rs->response->body->stream_fd = -1;
            rs->response->body->stream_type = -1;
        }
        if (!rp && rs->response->body != NULL && rs->response->body->mime_type != NULL) {
            struct fcgi* fcgi = hashmap_get(vhost->sub.htdocs.fcgis, rs->response->body->mime_type);
            if (fcgi != NULL) {
                isStatic = 0;
                int attempt_count = 0;
                int fcgi_fd;
                char* rq = str_dup(rs->request->path, 0, rs->pool);
                {
                    char* ht = strchr(rq, '#');
                    if (ht != NULL) ht[0] = 0;
                }
                char* get = strchr(rq, '?');
                if (get != NULL) {
                    get[0] = 0;
                    get++;
                } else {
                    get = "";
                }
                char content_len_str[16];
                if (rs->request->body != NULL) {
                    snprintf(content_len_str, 16, "%lu", rs->request->body->len);
                } else {
                    content_len_str[0] = '0';
                    content_len_str[1] = 0;
                }
                char port_str[16];
                if (rs->sender->addr.tcp6.sin6_family == AF_INET) {
                    snprintf(port_str, 16, "%i", ntohs(rs->sender->addr.tcp4.sin_port));
                } else if (rs->sender->addr.tcp6.sin6_family == AF_INET6) {
                    snprintf(port_str, 16, "%i", ntohs(rs->sender->addr.tcp6.sin6_port));
                } else {
                    port_str[0] = '0';
                    port_str[1] = 0;
                }
                char sport_str[16];
                struct server_binding* incoming_binding = rs->sender->incoming_binding;
                if (incoming_binding->binding_type == BINDING_TCP4) {
                    snprintf(sport_str, 16, "%i", htons(incoming_binding->binding.tcp4.sin_port));
                } else if (incoming_binding->binding_type == BINDING_TCP6) {
                    snprintf(sport_str, 16, "%i", htons(incoming_binding->binding.tcp6.sin6_port));
                } else if (incoming_binding->binding_type == BINDING_UNIX) {
                    snprintf(sport_str, 16, "UNIX");
                } else {
                    snprintf(sport_str, 16, "UNKNOWN");
                }

                goto start_fcgi;
                restart_fcgi: ;
                if (fcgi_fd >= 0) {
                    close(fcgi_fd);
                }
                attempt_count++;
                errlog(rs->wp->server->logsess, "Failed to read/write to FCGI Server! File: %s Error: %s, restarting connection!", rtp, strerror(errno));
                start_fcgi: ;
                if (attempt_count >= 2) {
                    errlog(rs->wp->server->logsess, "Too many FCGI connection attempts, aborting.");
                    rs->response->code = "500 Internal Server Error";
                    generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                    goto epage;
                }
                fcgi_fd = fcgi_request_connection(fcgi);
                if (fcgi_fd < 0) {
                    errlog(rs->wp->server->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
                    rs->response->code = "500 Internal Server Error";
                    generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                    goto epage;
                }

                struct fcgiframe ff;
                ff.type = FCGI_BEGIN_REQUEST;
                ff.reqID = fcgi->req_id_counter++ % 65535;
                if (fcgi->req_id_counter > 65535) fcgi->req_id_counter = 0;
                ff.len = 8;
                unsigned char pkt[8];
                pkt[0] = 0;
                pkt[1] = 1;
                pkt[2] = 1;
                memset(pkt + 3, 0, 5);
                ff.data = pkt;
                if (writeFCGIFrame(fcgi_fd, &ff)) goto restart_fcgi;
                //TODO: SERVER_ADDR
                struct hashmap* fcgi_params = hashmap_new(16, rs->pool);
                hashmap_put(fcgi_params, "REQUEST_URI", rs->request->path);
                hashmap_put(fcgi_params, "CONTENT_LENGTH", content_len_str);
                if (rs->request->body != NULL && rs->request->body->mime_type != NULL) {
                    hashmap_put(fcgi_params, "CONTENT_TYPE", rs->request->body->mime_type);
                }
                hashmap_put(fcgi_params, "GATEWAY_INTERFACE", "CGI/1.1");
                hashmap_put(fcgi_params, "PATH", getenv("PATH"));
                hashmap_put(fcgi_params, "QUERY_STRING", get);
                hashmap_put(fcgi_params, "REQUEST_URI", rs->request->path);
                {
                    char tip[48];
                    char* mip = tip;
                    if (rs->sender->addr.tcp6.sin6_family == AF_INET) {
                        inet_ntop(AF_INET, &rs->sender->addr.tcp4.sin_addr, tip, 48);
                    } else if (rs->sender->addr.tcp6.sin6_family == AF_INET6) {
                        if (memseq((unsigned char*) &rs->sender->addr.tcp6.sin6_addr, 10, 0) && memseq((unsigned char*) &rs->sender->addr.tcp6.sin6_addr + 10, 2, 0xff)) {
                            inet_ntop(AF_INET, ((unsigned char*) &rs->sender->addr.tcp6.sin6_addr) + 12, tip, 48);
                        } else inet_ntop(AF_INET6, &rs->sender->addr.tcp6.sin6_addr, tip, 48);
                    } else if (rs->sender->addr.tcp6.sin6_family == AF_LOCAL) {
                        mip = "UNIX";
                    } else {
                        mip = "UNKNOWN";
                    }
                    if (mip == NULL) mip = "INVALID";
                    hashmap_put(fcgi_params, "REMOTE_ADDR", mip);
                    hashmap_put(fcgi_params, "REMOTE_HOST", mip);
                }
                hashmap_put(fcgi_params, "REMOTE_PORT", port_str);

                if (extraPath != NULL) {
                    hashmap_put(fcgi_params, "PATH_INFO", extraPath);
                    size_t epl = strlen(extraPath);
                    char* trns = pmalloc(rs->pool, htdl + epl);
                    memcpy(trns, vhost->sub.htdocs.htdocs, htdl);
                    memcpy(trns + htdl, extraPath + 1, epl);
                    trns[htdl + epl - 1] = 0;
                    hashmap_put(fcgi_params, "PATH_TRANSLATED", trns);
                } else {
                    hashmap_put(fcgi_params, "PATH_INFO", "");
                    hashmap_put(fcgi_params, "PATH_TRANSLATED", "");
                }
                hashmap_put(fcgi_params, "REQUEST_METHOD", (void*) getMethod(rs->request->method));
                char rss[4];
                rss[3] = 0;
                memcpy(rss, rs->response->code, 3);
                hashmap_put(fcgi_params, "REDIRECT_STATUS", rss);
                size_t htl = strlen(vhost->sub.htdocs.htdocs);
                int htes = vhost->sub.htdocs.htdocs[htl - 1] == '/';
                size_t rtpl = strlen(rtp);
                if (rtpl < htl) errlog(rs->wp->server->logsess, "Setting FCGI SCRIPT_NAME requires the file to be in htdocs! @ %s", rtp);
                else {
                    hashmap_put(fcgi_params, "SCRIPT_NAME", rtp + htl + (htes ? -1 : 0));
                }
                if (host != NULL) {
                    hashmap_put(fcgi_params, "SERVER_NAME", (void*) host);
                }
                hashmap_put(fcgi_params, "SERVER_PORT", sport_str);
                hashmap_put(fcgi_params, "SERVER_PROTOCOL", rs->request->version);
                hashmap_put(fcgi_params, "SERVER_SOFTWARE", "Avuna/" VERSION);
                hashmap_put(fcgi_params, "DOCUMENT_ROOT", vhost->sub.htdocs.htdocs);
                hashmap_put(fcgi_params, "SCRIPT_FILENAME", rtp);

                for (int i = 0; i < rs->request->headers->count; i++) {
                    const char* name = rs->request->headers->names[i];
                    if (str_eq(name, "Accept-Encoding")) continue;
                    const char* value = rs->request->headers->values[i];
                    size_t name_length = strlen(name);
                    char* nname = pmalloc(rs->pool, name_length + 6);
                    memcpy(nname, "HTTP_", 5);
                    memcpy(nname + 5, name, name_length + 1);
                    name_length += 5;
                    for (int x = 5; x < name_length; x++) {
                        if (nname[x] >= 'a' && nname[x] <= 'z') nname[x] -= ' ';
                        else if (nname[x] == '-') nname[x] = '_';
                    }
                    hashmap_put(fcgi_params, nname, value);
                }
                ITER_MAP(fcgi_params) {
                    writeFCGIParam(fcgi_fd, ff.reqID, str_key, (char*) value);
                    ITER_MAP_END();
                }

                ff.type = FCGI_PARAMS;
                ff.len = 0;
                ff.data = NULL;
                writeFCGIFrame(fcgi_fd, &ff);
                ff.type = FCGI_STDIN;
                if (rs->request->body != NULL && rs->request->body->len > 0) {
                    size_t cr = 0;
                    size_t left = rs->request->body->len;
                    while (left > 0) {
                        ff.len = left > 0xFFFF ? 0xFFFF : (uint16_t) left;
                        ff.data = rs->request->body->data + cr;
                        cr += ff.len;
                        left -= ff.len;
                        writeFCGIFrame(fcgi_fd, &ff);
                    }
                }
                ff.len = 0;
                writeFCGIFrame(fcgi_fd, &ff);
                if (rs->response->body != NULL) {
                    rs->response->body = NULL;
                }

                char* ct = NULL;
                int hd = 0;
                char* hdd = NULL;
                size_t hddl = 0;
                int eid = ff.reqID;

                while (ff.type != FCGI_END_REQUEST) {
                    if (readFCGIFrame(fcgi_fd, &ff, rs->pool)) {
                        errlog(rs->wp->server->logsess, "Error reading from FCGI server: %s", strerror(errno));
                        goto restart_fcgi;
                    }
                    if (ff.reqID != eid) {
                        //printf("unx name %i wanted: %i\n", ff.reqID, eid);
                        if (ff.type == FCGI_END_REQUEST) {
                            ff.type = FCGI_STDERR;
                            //printf("rewr\n");
                        }
                        continue;
                    }
                    //printf("recv %i\n", ff.type);
                    if (ff.type == FCGI_END_REQUEST) {
                        //printf("er!\n");
                        continue;
                    }
                    if (ff.type == FCGI_STDERR) {
                        errlog(rs->wp->server->logsess, "FCGI STDERR <%s>: %s", rtp, ff.data);
                    }
                    if (ff.type == FCGI_STDOUT || ff.type == FCGI_STDERR) {
                        int hr = 0;
                        if (!hd && ff.type == FCGI_STDOUT) {
                            int ml = 0;
                            char* tm = "\r\n\r\n";
                            for (int i = 0; i < ff.len; i++) {
                                if (((char*) ff.data)[i] == tm[ml]) {
                                    ml++;
                                    if (ml == 4) {
                                        hd = 1;
                                        hr = i + 1;
                                        if (hdd == NULL) {
                                            hdd = pmalloc(rs->pool, i + 1);
                                            hdd[i] = 0;
                                            memcpy(hdd, ff.data, i);
                                            hddl = i;
                                        } else {
                                            hdd = prealloc(rs->pool, hdd, hddl + i + 1);
                                            hdd[hddl + i] = 0;
                                            memcpy(hdd + hddl, ff.data, i);
                                            hddl += i;
                                        }
                                        break;
                                    }
                                } else ml = 0;
                            }
                            if (!hd) {
                                hr = ff.len;
                                if (hdd == NULL) {
                                    hdd = pmalloc(rs->pool, ff.len);
                                    hdd[ff.len] = 0;
                                    memcpy(hdd, ff.data, ff.len);
                                    hddl = ff.len;
                                } else {
                                    hdd = prealloc(rs->pool, hdd, hddl + ff.len);
                                    hdd[hddl + ff.len] = 0;
                                    memcpy(hdd + hddl, ff.data, ff.len);
                                    hddl += ff.len;
                                }
                            }
                        }

                        if (hd == 1 && ff.type == FCGI_STDOUT) {
                            hd = 2;
                            struct headers* hdrs = pcalloc(rs->pool, sizeof(struct headers));
                            hdrs->pool = rs->pool;
                            header_parse(hdrs, hdd, 0, rs->pool);
                            for (int i = 0; i < hdrs->count; i++) {
                                const char* name = hdrs->names[i];
                                const char* value = hdrs->values[i];
                                if (str_eq(name, "Content-Type")) {
                                    ct = value;
                                } else if (str_eq(name, "Status")) {
                                    if (!rs->response->parsed) {
                                        rs->response->parsed = 2;
                                    }
                                    rs->response->code = value;
                                } else if (str_eq(name, "ETag")) {
                                    // we handle ETags, ignore FCGI-given ones
                                } else header_add(rs->response->headers, name, value);
                            }
                        }

                        if (hr <= ff.len) {
                            unsigned char* ffd = ff.data + hr;
                            ff.len -= hr;
                            if (rs->response->body == NULL) {
                                rs->response->body = pmalloc(rs->pool, sizeof(struct body));
                                rs->response->body->data = pmalloc(rs->pool, ff.len);
                                memcpy(rs->response->body->data, ffd, ff.len);
                                rs->response->body->len = ff.len;
                                rs->response->body->mime_type = ct == NULL ? "text/html" : ct;
                                rs->response->body->stream_fd = -1;
                                rs->response->body->stream_type = -1;
                            } else {
                                rs->response->body->len += ff.len;
                                rs->response->body->data = prealloc(rs->pool, rs->response->body->data, rs->response->body->len);
                                memcpy(rs->response->body->data + rs->response->body->len - ff.len, ffd, ff.len);
                            }
                        }
                    }
                }

                close(fcgi_fd);

            }
        }
        if (isStatic) {
            if (vhost->sub.htdocs.maxAge > 0 && rs->response->body != NULL) {
                int cache_found = 0;
                for (size_t i = 0; i < vhost->sub.htdocs.cache_types->count; i++) {
                    if (str_eq(vhost->sub.htdocs.cache_types->data[i], rs->response->body->mime_type)) {
                        cache_found = 1;
                        break;
                    } else if (str_suffixes_case(vhost->sub.htdocs.cache_types->data[i], "/*")) {
                        char* nct = str_dup(vhost->sub.htdocs.cache_types->data[i], 0, rs->pool);
                        nct[strlen(nct) - 1] = 0;
                        if (str_prefixes_case(rs->response->body->mime_type, nct)) {
                            cache_found = 1;
                            break;
                        }
                    }
                }

                char ccbuf[64];
                memcpy(ccbuf, "max-age=", 8);
                int snr = snprintf(ccbuf + 8, 18, "%lu", vhost->sub.htdocs.maxAge);
                if (cache_found) {
                    memcpy(ccbuf + 8 + snr, ", no-cache", 11);
                } else {
                    ccbuf[8 + snr] = 0;
                }
                header_add(rs->response->headers, "Cache-Control", ccbuf);
            }
        }
        if (!rp && isStatic) {
            int ffd = open(rtp, O_RDONLY);
            if (ffd < 0) {
                errlog(rs->wp->server->logsess, "Failed to open file %s! %s", rtp, strerror(errno));
                rs->response->code = "500 Internal Server Error";
                generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
            rs->response->body->data = pmalloc(rs->pool, st.st_size);
            ssize_t r = 0;
            while ((r = read(ffd, rs->response->body->data + rs->response->body->len, st.st_size - rs->response->body->len)) > 0) {
                rs->response->body->len += r;
            }
            if (r < 0) {
                close(ffd);
                errlog(rs->wp->server->logsess, "Failed to read file %s! %s", rtp, strerror(errno));
                rs->response->code = "500 Internal Server Error";
                generateDefaultErrorPage(rs, vhost, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                goto epage;
            }
            close(ffd);
        }
        //TODO: CGI
        //TODO: SCGI
        //TODO: SO-CGI
        //TODO: SSI
        epage: ;
        char etag[35];
        int hetag = 0;
        int nm = 0;
        if (!rp && rs->response->body != NULL && rs->response->body->len > 0 && rs->response->code != NULL && rs->response->code[0] == '2') {
            MD5_CTX md5ctx;
            MD5_Init(&md5ctx);
            MD5_Update(&md5ctx, rs->response->body->data, rs->response->body->len);
            unsigned char rawmd5[16];
            MD5_Final(rawmd5, &md5ctx);
            hetag = 1;
            etag[34] = 0;
            etag[0] = '\"';
            for (int i = 0; i < 16; i++) {
                snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
            }
            etag[33] = '\"';
            header_add(rs->response->headers, "ETag", etag);
            if (str_eq_case(etag, header_get(rs->request->headers, "If-None-Match"))) {
                nm = 1;
                if (!isStatic) {
                    rs->response->code = "304 Not Modified";
                    rs->response->body = NULL;
                }
            }
        }
        const char* cce = header_get(rs->response->headers, "Content-Encoding");
        int wgz = str_eq_case(cce, "gzip");
        if (rs->response->body != NULL && rs->response->body->len > 1024 && cce == NULL) {
            const char* accenc = header_get(rs->request->headers, "Accept-Encoding");
            if (str_contains(accenc, "gzip")) {
                z_stream strm;
                strm.zalloc = Z_NULL;
                strm.zfree = Z_NULL;
                strm.opaque = Z_NULL;
                int dr = 0;
                if ((dr = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY)) != Z_OK) { // TODO: configurable level?
                    errlog(rs->wp->server->logsess, "Error with zlib defaultInit: %i", dr);
                    goto pgzip;
                }
                strm.avail_in = rs->response->body->len;
                strm.next_in = rs->response->body->data;
                void* cdata = pmalloc(rs->pool, 16384);
                size_t ts = 0;
                size_t cc = 16384;
                strm.avail_out = cc - ts;
                strm.next_out = cdata + ts;
                do {
                    strm.avail_out = cc - ts;
                    strm.next_out = cdata + ts;
                    dr = deflate(&strm, Z_FINISH);
                    ts = strm.total_out;
                    if (ts >= cc - 8192) {
                        cc = ts + 16384;
                        cdata = prealloc(rs->pool, cdata, cc);
                    }
                    if (dr == Z_STREAM_ERROR) {
                        errlog(rs->wp->server->logsess, "Stream error with zlib deflate");
                        goto pgzip;
                    }
                } while (strm.avail_out == 0);
                deflateEnd(&strm);
                cdata = prealloc(rs->pool, cdata, ts); // shrink
                rs->response->body->data = cdata;
                rs->response->body->len = ts;
                header_add(rs->response->headers, "Content-Encoding", "gzip");
                header_add(rs->response->headers, "Vary", "Accept-Encoding");
                wgz = 1;
            }
        }
        pgzip: ;
        if (isStatic && vhost->sub.htdocs.scacheEnabled && (vhost->sub.htdocs.maxCache <= 0 || vhost->sub.htdocs.maxCache < vhost->sub.htdocs.cache->max_size)) {
            if (rp) {
                rs->request->atc = 1;
            } else {
                struct mempool* scpool = mempool_new();
                struct scache* sc = pmalloc(scpool, sizeof(struct scache));
                sc->pool = scpool;
                pchild(vhost->sub.htdocs.cache->pool, sc->pool);
                sc->body = pxfer(rs->pool, sc->pool, rs->response->body);
                pxfer(rs->pool, sc->pool, sc->body->data);
                pxfer(rs->pool, sc->pool, sc->body->mime_type);
                sc->content_encoding = wgz;
                sc->code = pxfer(rs->pool, sc->pool, rs->response->code);
                if (eh) {
                    if (rs->response->body != NULL) header_setoradd(rs->response->headers, "Content-Type", rs->response->body->mime_type);
                    char l[16];
                    if (rs->response->body != NULL) sprintf(l, "%u", (unsigned int) rs->response->body->len);
                    header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
                }
                sc->headers = pxfer(rs->pool, sc->pool, rs->response->headers);
                sc->headers->pool = sc->pool;
                pxfer(rs->pool, sc->pool, sc->headers->names);
                pxfer(rs->pool, sc->pool, sc->headers->values);
                for (size_t i = 0; i < sc->headers->count; ++i) {
                    pxfer(rs->pool, sc->pool, sc->headers->names[i]);
                    pxfer(rs->pool, sc->pool, sc->headers->values[i]);
                }
                sc->request_path = pxfer(rs->pool, sc->pool, rs->request->path);
                if (!hetag) {
                    if (rs->response->body == NULL) {
                        hetag = 1;
                        etag[0] = '\"';
                        memset(etag + 1, '0', 32);
                        etag[33] = '\"';
                        etag[34] = 0;
                    } else {
                        MD5_CTX md5ctx;
                        MD5_Init(&md5ctx);
                        MD5_Update(&md5ctx, rs->response->body->data, rs->response->body->len);
                        unsigned char rawmd5[16];
                        MD5_Final(rawmd5, &md5ctx);
                        hetag = 1;
                        etag[34] = 0;
                        etag[0] = '\"';
                        for (int i = 0; i < 16; i++) {
                            snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
                        }
                        etag[33] = '\"';
                    }
                }
                memcpy(sc->etag, etag, 35);
                cache_add(vhost->sub.htdocs.cache, sc);
                rs->response->fromCache = sc;
                rs->request->atc = 1;
                if (nm) {
                    rs->response->body = NULL;
                    rs->response->code = "304 Not Modified";
                }
            }
        }
        pcacheadd: ;
        //TODO: Chunked
    } else if (vhost->type == VHOST_REDIRECT) {
        rs->response->code = "302 Found";
        header_add(rs->response->headers, "Location", vhost->sub.redirect.redir);
    } else if (vhost->type == VHOST_MOUNT) {
        struct vhost_mount* vhm = &vhost->sub.mount;
        char* oid = vhost->id;
        vhost = NULL;
        for (int i = 0; i < vhm->mounts->count; i++) {
            struct mountpoint* mount = vhm->mounts->data[i];
            if (str_prefixes_case(rs->request->path, mount->path)) {
                for (size_t x = 0; x < rs->wp->server->vhosts->count; x++) {
                    struct vhost* iter_vhost = rs->wp->server->vhosts->data[x];
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
        goto jpvh;
    }
    pvh:
//body stuff
    if (eh && !rp && rs->response->body != NULL && rs->response->body->mime_type != NULL) {
        header_setoradd(rs->response->headers, "Content-Type", rs->response->body->mime_type);
    }
    if (eh && !rp) {
        char l[16];
        if (rs->response->body != NULL) sprintf(l, "%lu", rs->response->body->len);
        header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
    }
    return 0;
}
