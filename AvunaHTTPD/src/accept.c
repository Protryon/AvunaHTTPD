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
#include <gnutls/gnutls.h>
#include "tls.h"

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
	while (1) {
		struct conn* c = xmalloc(sizeof(struct conn));
		memset(&c->addr, 0, sizeof(struct sockaddr));
		c->addrlen = sizeof(struct sockaddr);
		c->readBuffer = NULL;
		c->readBuffer_size = 0;
		c->readBuffer_checked = 0;
		c->writeBuffer = NULL;
		c->writeBuffer_size = 0;
		c->postLeft = 0;
		c->reqPosting = NULL;
		c->handshaked = 0;
		if (param->cert != NULL) {
			gnutls_init(&c->session, GNUTLS_SERVER | GNUTLS_NONBLOCK);
			gnutls_priority_set(c->session, param->cert->priority);
			gnutls_credentials_set(c->session, GNUTLS_CRD_CERTIFICATE, param->cert->cert);
			gnutls_certificate_server_set_request(c->session, GNUTLS_CERT_IGNORE);
			//gnutls_certificate_send_x509_rdn_sequence(c->session, 1);
			c->tls = 1;
		} else {
			c->tls = 0;
		}
		if (poll(&spfd, 1, -1) < 0) {
			errlog(param->logsess, "Error while polling server: %s", strerror(errno));
			if (param->cert != NULL) gnutls_deinit(c->session);
			xfree(c);
			continue;
		}
		if ((spfd.revents ^ POLLIN) != 0) {
			errlog(param->logsess, "Error after polling server: %i (poll revents), closing server!", spfd.revents);
			if (param->cert != NULL) gnutls_deinit(c->session);
			xfree(c);
			close(param->server_fd);
			break;
		}
		spfd.revents = 0;
		int cfd = accept(param->server_fd, &c->addr, &c->addrlen);
		if (cfd < 0) {
			if (param->cert != NULL) gnutls_deinit(c->session);
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
			if (param->cert != NULL) gnutls_deinit(c->session);
			errlog(param->logsess, "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.", strerror(errno));
			close(cfd);
			xfree(c);
			continue;
		}
		if (param->cert != NULL) {
			gnutls_transport_set_int2(c->session, cfd, cfd);
			/*if (sniCallback != NULL) {
			 struct sni_data* ld = xmalloc(sizeof(struct sni_data));
			 ld->this = this;
			 ld->sniCallback = sniCallback;
			 lsd = ld;
			 gnutls_handshake_set_post_client_hello_function(sessiond, handleSNI);
			 }*/
			int r = gnutls_handshake(c->session);
			if (gnutls_error_is_fatal(r)) {
				gnutls_deinit(c->session);
				close(c->fd);
				xfree(c);
				continue;
			} else if (r == GNUTLS_E_SUCCESS) {
				c->handshaked = 1;
			}
		}
		struct work_param* work = param->works[rand() % param->works_count];
		if (add_collection(work->conns, c)) { // TODO: send to lowest load, not random
			if (errno == EINVAL) {
				errlog(param->logsess, "Too many open connections! Closing client.");
			} else {
				errlog(param->logsess, "Collection failure! Closing client. %s", strerror(errno));
			}
			close(cfd);
			continue;
		}
		if (write(work->pipes[1], &onec, 1) < 1) {
			errlog(param->logsess, "Failed to write to wakeup pipe! Things may slow down. %s", strerror(errno));
		}
	}
}
