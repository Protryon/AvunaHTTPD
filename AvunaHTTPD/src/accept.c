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

int accept_sni_callback(SSL* ssl, int *ad, struct accept_param* param) {
	if (ssl == NULL || param->works_count == 0 || param->works[0] == NULL) return SSL_TLSEXT_ERR_NOACK;
	const char* servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	if (servername == NULL) return SSL_TLSEXT_ERR_NOACK;
	struct vhost* vh = NULL;
	for (int i = 0; i < param->works[0]->vhosts_count; i++) {
		if (param->works[0]->vhosts[i]->host_count == 0) {
			vh = param->works[0]->vhosts[i];
			break;
		} else for (int x = 0; x < param->works[0]->vhosts[i]->host_count; x++) {
			if (domeq(param->works[0]->vhosts[i]->hosts[x], servername)) {
				vh = param->works[0]->vhosts[i];
				break;
			}
		}
		if (vh != NULL) break;
	}
	if (vh == NULL || vh->cert == NULL) return SSL_TLSEXT_ERR_OK;
	if (SSL_set_SSL_CTX(ssl, vh->cert->ctx) != vh->cert->ctx) return SSL_TLSEXT_ERR_NOACK;
	return SSL_TLSEXT_ERR_OK;
}

void run_accept(struct accept_param* param) {
	static int one = 1;
	static unsigned char onec = 1;
	struct timeval timeout;
	timeout.tv_sec = 60;
	timeout.tv_usec = 0;
	struct pollfd spfd;
	spfd.events = POLLIN;
	spfd.revents = 0;
	spfd.fd = param->server_fd;
	if (param->cert != NULL) {
		SSL_CTX_set_tlsext_servername_callback(param->cert->ctx, accept_sni_callback);
		SSL_CTX_set_tlsext_servername_arg(param->cert->ctx, param);
	}
	while (1) {
		struct conn* c = xmalloc(sizeof(struct conn));
		memset(&c->addr, 0, sizeof(struct sockaddr_in6));
		c->addrlen = sizeof(struct sockaddr_in6);
		c->readBuffer = NULL;
		c->readBuffer_size = 0;
		c->readBuffer_checked = 0;
		c->writeBuffer = NULL;
		c->writeBuffer_size = 0;
		c->postLeft = 0;
		c->reqPosting = NULL;
		c->handshaked = 0;
		c->fw_fd = -1;
		c->fwqueue = NULL;
		c->fwed = 0;
		c->fw_readBuffer = NULL;
		c->fw_readBuffer_size = 0;
		c->fw_readBuffer_checked = 0;
		c->fw_tls = 0;
		c->fw_handshaked = 0;
		c->stream_type = -1;
		c->stream_fd = -1;
		c->stream_len = 0;
		c->streamed = 0;
		c->stream_md5 = NULL;
		c->sscbl = 0;
		c->staticStreamCacheBuffer = NULL;
		c->proto = PROTO_HTTP1;
		c->http2_stream = NULL;
		c->http2_stream_size = 0;
		c->nextStream = 2;
		c->ssl_nextdir = 0;
		c->fw_ssl_nextdir = 0;
		c->frs = NULL;
		if (param->cert != NULL) {
			c->session = SSL_new(param->cert->ctx);
			SSL_set_mode(c->session, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_ENABLE_PARTIAL_WRITE);
			SSL_set_accept_state(c->session);
			c->tls = 1;
		} else {
			c->tls = 0;
		}
		if (poll(&spfd, 1, -1) < 0) {
			errlog(param->logsess, "Error while polling server: %s", strerror(errno));
			if (param->cert != NULL) SSL_free(c->session);
			xfree(c);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			errlog(param->logsess, "Error after polling server: %i (poll revents), closing server!", spfd.revents);
			if (param->cert != NULL) SSL_free(c->session);
			xfree(c);
			close(param->server_fd);
			break;
		}
		spfd.revents = 0;
		int cfd = accept(param->server_fd, (struct sockaddr*) &c->addr, &c->addrlen);
		if (cfd < 0) {
			if (param->cert != NULL) SSL_free(c->session);
			if (errno == EAGAIN) continue;
			errlog(param->logsess, "Error while accepting client: %s", strerror(errno));
			xfree(c);
			continue;
		}
		c->fd = cfd;
		if (setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout))) errlog(param->logsess, "Setting recv timeout failed! %s", strerror(errno));
		if (setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout))) errlog(param->logsess, "Setting send timeout failed! %s", strerror(errno));
		if (setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (void *) &one, sizeof(one))) errlog(param->logsess, "Setting TCP_NODELAY failed! %s", strerror(errno));
		if (fcntl(cfd, F_SETFL, fcntl(cfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (param->cert != NULL) SSL_free(c->session);
			errlog(param->logsess, "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.", strerror(errno));
			close(cfd);
			xfree(c);
			continue;
		}
		if (param->cert != NULL) {
			SSL_set_fd(c->session, c->fd);
			/*if (sniCallback != NULL) {
			 struct sni_data* ld = xmalloc(sizeof(struct sni_data));
			 ld->this = this;
			 ld->sniCallback = sniCallback;
			 lsd = ld;
			 gnutls_handshake_set_post_client_hello_function(sessiond, handleSNI);
			 }*/
			int r = SSL_accept(c->session);
			if (r == 1) {
				c->handshaked = 1;
			} else if (r == 2) {
				SSL_free(c->session);
				close(c->fd);
				xfree(c);
				continue;
			} else {
				int err = SSL_get_error(c->session, r);
				if (err == SSL_ERROR_WANT_READ) c->ssl_nextdir = 1;
				else if (err == SSL_ERROR_WANT_WRITE) c->ssl_nextdir = 2;
				else {
					SSL_free(c->session);
					close(c->fd);
					xfree(c);
					continue;
				}
			}
		}
		if (param->cert != NULL && param->cert->isDummy && SSL_get_SSL_CTX(c->session) == param->cert->ctx) {
			SSL_free(c->session);
			close(c->fd);
			xfree(c);
			continue;
		}
		//printf("%16lX connected.\n", c);
		struct work_param* work = param->works[rand() % param->works_count];
		if (add_collection(work->conns, c)) { // TODO: send to lowest load, not random
			if (errno == EINVAL) {
				errlog(param->logsess, "Too many open connections! Closing client.");
			} else {
				errlog(param->logsess, "Collection failure! Closing client. %s", strerror(errno));
			}
			SSL_free(c->session);
			close(cfd);
			continue;
		}
		if (write(work->pipes[1], &onec, 1) < 1) {
			errlog(param->logsess, "Failed to write to wakeup pipe! Connection may hang. %s", strerror(errno));
		}
	}
}
