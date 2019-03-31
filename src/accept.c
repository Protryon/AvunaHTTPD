/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#include "accept.h"
#include "http_pipeline.h"
#include <avuna/connection.h>
#include <avuna/tls.h>
#include <avuna/vhost.h>
#include <avuna/globals.h>
#include <avuna/pmem_hooks.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <poll.h>

int accept_sni_callback(SSL* ssl, int* ad, struct accept_param* param) {
    if (ssl == NULL || param == NULL) return SSL_TLSEXT_ERR_NOACK;
    const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL) return SSL_TLSEXT_ERR_NOACK;
    struct vhost* selected = NULL;
    for (size_t i = 0; i < param->server->vhosts->count; i++) {
        struct vhost* vhost = ((struct vhost*) param->server->vhosts->data[i]);
        if (vhost->hosts->count == 0) {
            selected = vhost;
            break;
        } else
            for (size_t x = 0; x < vhost->hosts->count; x++) {
                if (domeq(vhost->hosts->data[x], servername)) {
                    selected = vhost;
                    goto outer_break;
                }
            }
    }
    outer_break:;
    if (selected == NULL || selected->ssl_cert == NULL) {
        if (!param->binding->ssl_cert->isDummy &&
            SSL_set_SSL_CTX(ssl, param->binding->ssl_cert->ctx) != param->binding->ssl_cert->ctx) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    } else if (SSL_set_SSL_CTX(ssl, selected->ssl_cert->ctx) != selected->ssl_cert->ctx) return SSL_TLSEXT_ERR_NOACK;
    return SSL_TLSEXT_ERR_OK;
}

void shutdown_ssl_hook(SSL* ssl) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

void run_accept(struct accept_param* param) {
    struct mempool* accept_pool = mempool_new();
    static int one = 1;
    struct timeval timeout;
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;
    struct pollfd spfd;
    spfd.events = POLLIN;
    spfd.revents = 0;
    spfd.fd = param->binding->fd;
    int ssl = (param->binding->mode & BINDING_MODE_HTTPS) != 0;
    if (ssl && param->binding->ssl_cert == NULL) {
        param->binding->ssl_cert = pclaim(param->binding->pool, dummyCert(accept_pool));
    }
    if (ssl) {
        SSL_CTX_set_tlsext_servername_callback(param->binding->ssl_cert->ctx, accept_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(param->binding->ssl_cert->ctx, param);
    }
    while (1) {
        struct mempool* pool = mempool_new();
        struct conn* conn = pcalloc(pool, sizeof(struct conn));
        conn->manager = NULL;
        conn->pool = pool;
        conn->incoming_binding = param->binding;
        conn->sub_conns = llist_new(pool);
        conn->server = param->server;
        struct sub_conn* sub_conn = pcalloc(pool, sizeof(struct sub_conn));
        llist_append(conn->sub_conns, sub_conn);
        buffer_init(&sub_conn->read_buffer, conn->pool);
        buffer_init(&sub_conn->write_buffer, conn->pool);
        sub_conn->tls = ssl;
        if (ssl) {
            sub_conn->tls_session = SSL_new(param->binding->ssl_cert->ctx);
            phook(conn->pool, shutdown_ssl_hook, sub_conn->tls_session);
            SSL_set_mode(sub_conn->tls_session, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
            SSL_set_accept_state(sub_conn->tls_session);
        }

        //conn->proto = (param->binding->mode & BINDING_MODE_HTTP2_ONLY != 0) &&
        //              (param->binding->mode & BINDING_MODE_HTTP11_ONLY == 0) ? PROTO_HTTP2 : PROTO_HTTP1;

        if (poll(&spfd, 1, -1) < 0) {
            errlog(param->server->logsess, "Error while polling server: %s", strerror(errno));
            pfree(pool);
            continue;
        }
        if ((spfd.revents ^ POLLIN) != 0) {
            errlog(param->server->logsess, "Error after polling server: %i (poll revents), closing server!",
                   spfd.revents);
            pfree(pool);
            break;
        }
        spfd.revents = 0;
        socklen_t temp = sizeof(struct sockaddr_in6);
        int cfd = accept(param->binding->fd, (struct sockaddr*) &conn->addr.tcp6, &temp);
        if (cfd < 0) {
            if (errno == EAGAIN) continue;
            errlog(param->server->logsess, "Error while accepting client: %s", strerror(errno));
            pfree(pool);
            continue;
        }
        conn->fd = cfd;
        phook(pool, close_hook, (void*) cfd);
        if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout)))
            errlog(param->server->logsess, "Setting recv timeout failed! %s", strerror(errno));
        if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char*) &timeout, sizeof(timeout)))
            errlog(param->server->logsess, "Setting send timeout failed! %s", strerror(errno));
        if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void*) &one, sizeof(one)))
            errlog(param->server->logsess, "Setting TCP_NODELAY failed! %s", strerror(errno));
        if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
            errlog(param->server->logsess,
                   "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.", strerror(errno));
            pfree(pool);
            continue;
        }
        if (ssl) {
            SSL_set_fd(sub_conn->tls_session, conn->fd);
            int r = SSL_accept(sub_conn->tls_session);
            if (r == 1) {
                sub_conn->tls_handshaked = 1;
            } else if (r == 2) {
                pfree(pool);
                continue;
            } else {
                int err = SSL_get_error(sub_conn->tls_session, r);
                if (err == SSL_ERROR_WANT_READ) sub_conn->tls_next_direction = 1;
                else if (err == SSL_ERROR_WANT_WRITE) sub_conn->tls_next_direction = 2;
                else {
                    pfree(pool);
                    continue;
                }
            }
        }
        if (ssl && param->binding->ssl_cert->isDummy &&
            SSL_get_SSL_CTX(sub_conn->tls_session) == param->binding->ssl_cert->ctx) {
            pfree(pool);
            continue;
        }

        queue_push(param->server->prepared_connections, conn);
    }
    pfree(accept_pool);
}
