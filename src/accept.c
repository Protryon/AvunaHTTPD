/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#include "accept.h"
#include "http_network.h"
#include "http2_network.h"
#include "http_pipeline.h"
#include <avuna/hpack.h>
#include <avuna/connection.h>
#include <avuna/tls.h>
#include <avuna/vhost.h>
#include <avuna/globals.h>
#include <avuna/pmem_hooks.h>
#include <avuna/module.h>
#include <avuna/string.h>
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

void conn_disconnect_handler(struct conn* conn) {
    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_disconnect) {
            module->events.on_disconnect(module, conn);
        }
        ITER_LLIST_END();
    }
}

int alpn_select_callback (SSL* ssl,
           const unsigned char** out,
           unsigned char* outlen,
           const unsigned char* in,
           unsigned int inlen,
           void* arg) {
    size_t i = 0;
    const unsigned char* http11 = NULL;
    while (i < inlen) {
        uint8_t length = in[i++];
        if (i + length > inlen) {
            break;
        }
        char protocol[length + 1];
        memcpy(protocol, in + i, length);
        protocol[length] = 0;
        if (str_eq_case(protocol, "h2")) {
            *out = in + i;
            *outlen = (unsigned char) (length);
            return 0;
        } else if (str_eq_case(protocol, "http/1.1")) {
            http11 = in + i;
        }
        i += length;
    }
    if (http11 != NULL) {
        *out = http11;
        *outlen = 8;
    }
    return 0;
}

void run_accept(struct accept_param* param) {
    struct mempool* accept_pool = mempool_new();
    struct pollfd spfd;
    spfd.events = POLLIN;
    spfd.revents = 0;
    spfd.fd = param->binding->fd;
    int ssl = (param->binding->mode & BINDING_MODE_HTTPS) != 0;
    if (ssl && param->binding->ssl_cert == NULL) {
        param->binding->ssl_cert = pclaim(param->binding->pool, dummyCert(accept_pool));
    }
    int http2 = param->binding->mode & BINDING_MODE_HTTP2_ONLY;
    if (ssl) {
        SSL_CTX_set_tlsext_servername_callback(param->binding->ssl_cert->ctx, accept_sni_callback);
        SSL_CTX_set_tlsext_servername_arg(param->binding->ssl_cert->ctx, param);
        if (http2) {
            SSL_CTX_set_alpn_select_cb(param->binding->ssl_cert->ctx, alpn_select_callback, NULL);
        }
    }
    while (1) {
        struct mempool* pool = mempool_new();
        struct conn* conn = pcalloc(pool, sizeof(struct conn));
        conn->manager = NULL;
        conn->pool = pool;
        conn->incoming_binding = param->binding;
        conn->sub_conns = llist_new(pool);
        conn->server = param->server;
        pool = mempool_new();
        pchild(conn->pool, pool);
        struct sub_conn* sub_conn = pcalloc(pool, sizeof(struct sub_conn));
        sub_conn->pool = pool;
        sub_conn->read = http2 ? handle_http2_server_read : handle_http_server_read;
        if (http2) {
            struct http2_server_extra* extra = sub_conn->extra = pcalloc(sub_conn->pool, sizeof(struct http2_server_extra));
            extra->other_min_next_stream = 3;
            extra->streams = hashmap_new(32, sub_conn->pool);
            extra->our_max_frame_size = 65536;
            extra->other_max_frame_size = 65536;
            extra->frame_buffer = pmalloc(sub_conn->pool, 65536 + 9);
            extra->our_next_stream = 2;
            extra->remote_idle_streams = llist_new(sub_conn->pool);
            extra->send_hpack_ctx = hpack_init(sub_conn->pool, 4096);
            extra->recv_hpack_ctx = hpack_init(sub_conn->pool, 4096);
            sub_conn->notifier = http2_stream_notify;
        } else {
            sub_conn->extra = pcalloc(sub_conn->pool, sizeof(struct http_server_extra));
            sub_conn->notifier = http_stream_notify;
        }
        sub_conn->conn = conn;
        sub_conn->on_closed = http_on_closed;
        buffer_init(&sub_conn->read_buffer, sub_conn->pool);
        buffer_init(&sub_conn->write_buffer, sub_conn->pool);
        llist_append(conn->sub_conns, sub_conn);

        sub_conn->tls = ssl;
        if (ssl) {
            sub_conn->tls_session = SSL_new(param->binding->ssl_cert->ctx);
            phook(conn->pool, shutdown_ssl_hook, sub_conn->tls_session);
            SSL_set_mode(sub_conn->tls_session, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
            SSL_set_accept_state(sub_conn->tls_session);
        }

        if (poll(&spfd, 1, -1) < 0) {
            errlog(param->server->logsess, "Error while polling server: %s", strerror(errno));
            pfree(pool);
            continue;
        }
        if ((spfd.revents ^ POLLIN) != 0) {
            errlog(param->server->logsess, "Error after polling server: %i (poll revents)!",
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
        sub_conn->fd = cfd;
        phook(pool, close_hook, (void*) cfd);
        if (configure_fd(param->server->logsess, cfd, param->binding->binding_type != BINDING_UNIX)) {
            pfree(pool);
            continue;
        }
        if (ssl) {
            SSL_set_fd(sub_conn->tls_session, sub_conn->fd);
            int r = SSL_accept(sub_conn->tls_session);
            if (r == 1) {
                sub_conn->tls_handshaked = 1;
            } else if (r == 2) {
                pfree(pool);
                continue;
            } else {
                int err = SSL_get_error(sub_conn->tls_session, r);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
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

        ITER_LLIST(loaded_modules, value) {
            struct module* module = value;
            if (module->events.on_connect && module->events.on_connect(module, conn)) {
                pfree(pool);
                break;
            }
            ITER_LLIST_END();
        }

        phook(pool, (void (*)(void*)) conn_disconnect_handler, conn);

        queue_push(param->server->prepared_connections, conn);
    }
    pfree(accept_pool);
}
