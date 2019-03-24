/*
 * accept.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */
#include "accept.h"
#include "util.h"
#include <sys/socket.h>
#include <errno.h>
#include <stdio.h>
#include "xstring.h"
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdlib.h>
#include <poll.h>
#include "work.h"
#include <unistd.h>
#include <openssl/ssl.h>
#include "tls.h"
#include "vhost.h"
#include "pmem.h"
#include "globals.h"
#include "pmem_hooks.h"

int accept_sni_callback(SSL* ssl, int *ad, struct accept_param* param) {
	if (ssl == NULL || param == NULL) return SSL_TLSEXT_ERR_NOACK;
	const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (servername == NULL) return SSL_TLSEXT_ERR_NOACK;
	struct vhost* selected = NULL;
	for (size_t i = 0; i < param->server->vhosts->count; i++) {
		struct vhost* vhost = ((struct vhost*)param->server->vhosts->data[i]);
		if (vhost->hosts->count == 0) {
			selected = vhost;
			break;
		} else for (size_t x = 0; x < vhost->hosts->count; x++) {
			if (domeq(vhost->hosts->data[x], servername)) {
				selected = vhost;
				goto outer_break;
			}
		}
	}
	outer_break:;
	if (selected == NULL || selected->ssl_cert == NULL) {
		if (!param->binding->ssl_cert->isDummy && SSL_set_SSL_CTX(ssl, param->binding->ssl_cert->ctx) != param->binding->ssl_cert->ctx) {
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
		struct conn* conn = pmalloc(pool, sizeof(struct conn));
		memset(&conn->addr, 0, sizeof(conn->addr));
		conn->incoming_binding = param->binding;
		buffer_init(&conn->read_buffer, pool, 0);
		conn->readBuffer_checked = 0;
		buffer_init(&conn->write_buffer, pool, 0);
		conn->postLeft = 0;
		conn->currently_posting = NULL;
		conn->handshaked = 0;
		conn->fw_fd = -1;
		conn->fwqueue = NULL;
		conn->fwed = 0;
		buffer_init(&conn->fw_read_buffer, pool, 0);
		conn->fw_readBuffer_checked = 0;
		conn->fw_tls = 0;
		conn->fw_handshaked = 0;
		conn->stream_type = -1;
		conn->stream_fd = -1;
		conn->stream_len = 0;
		conn->streamed = 0;
		conn->stream_md5 = NULL;
		buffer_init(&conn->cache_buffer, pool, 0);
		conn->proto = (param->binding->mode & BINDING_MODE_HTTP2_ONLY != 0) && (param->binding->mode & BINDING_MODE_HTTP11_ONLY == 0) ? PROTO_HTTP2 : PROTO_HTTP1;
		conn->http2_stream = NULL;
		conn->http2_stream_size = 0;
		conn->nextStream = 2;
		conn->ssl_nextdir = 0;
		conn->fw_ssl_nextdir = 0;
		conn->forwarding_request = NULL;
		conn->pool = pool;
		conn->tls = ssl;
		if (ssl) {
			conn->session = SSL_new(param->binding->ssl_cert->ctx);
			phook(conn->pool, shutdown_ssl_hook, conn->session);
			SSL_set_mode(conn->session, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
			SSL_set_accept_state(conn->session);
		}
		if (poll(&spfd, 1, -1) < 0) {
			errlog(param->server->logsess, "Error while polling server: %s", strerror(errno));
			pfree(pool);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			errlog(param->server->logsess, "Error after polling server: %i (poll revents), closing server!", spfd.revents);
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
		if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout))) errlog(param->server->logsess, "Setting recv timeout failed! %s", strerror(errno));
		if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout))) errlog(param->server->logsess, "Setting send timeout failed! %s", strerror(errno));
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void *) &one, sizeof(one))) errlog(param->server->logsess, "Setting TCP_NODELAY failed! %s", strerror(errno));
		if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
			errlog(param->server->logsess, "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.", strerror(errno));
            pfree(pool);
			continue;
		}
		if (ssl) {
			SSL_set_fd(conn->session, conn->fd);
			int r = SSL_accept(conn->session);
			if (r == 1) {
				conn->handshaked = 1;
			} else if (r == 2) {
                pfree(pool);
				continue;
			} else {
				int err = SSL_get_error(conn->session, r);
				if (err == SSL_ERROR_WANT_READ) conn->ssl_nextdir = 1;
				else if (err == SSL_ERROR_WANT_WRITE) conn->ssl_nextdir = 2;
				else {
                    pfree(pool);
					continue;
				}
			}
		}
		if (ssl && param->binding->ssl_cert->isDummy && SSL_get_SSL_CTX(conn->session) == param->binding->ssl_cert->ctx) {
            pfree(pool);
			continue;
		}

		queue_push(param->server->prepared_connections, conn);
	}
	pfree(accept_pool);
}
