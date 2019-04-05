/*
 * work.c
 *
 *  Created on: Nov 18, 2015
 *      Author: root
 */

#include "network.h"
#include "http_pipeline.h"
#include <avuna/util.h>
#include <avuna/vhost.h>
#include <avuna/http.h>
#include <avuna/pmem.h>
#include <avuna/connection.h>
#include <avuna/pmem_hooks.h>
#include <avuna/provider.h>
#include <avuna/globals.h>
#include <avuna/network.h>
#include <avuna/module.h>
#include <errno.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

void send_request_session(struct request_session* rs, struct timespec* start) {
    struct conn* conn = rs->conn;
    struct response* resp = rs->response;
    struct request* req = rs->request;
    size_t response_length = 0;
    unsigned char* serialized_response = serializeResponse(rs, &response_length);
    struct timespec stt2;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt2);
    double msp =
        (stt2.tv_nsec / 1000000.0 + stt2.tv_sec * 1000.0) - (start->tv_nsec / 1000000.0 + start->tv_sec * 1000.0);
    const char* mip = NULL;
    char tip[48];
    if (conn->addr.tcp6.sin6_family == AF_INET) {
        struct sockaddr_in* sip4 = &conn->addr.tcp4;
        mip = inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
    } else if (conn->addr.tcp6.sin6_family == AF_INET6) {
        struct sockaddr_in6* sip6 = &conn->addr.tcp6;
        if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) &&
            memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
            mip = inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
        } else mip = inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
    } else if (conn->addr.tcp6.sin6_family == AF_LOCAL) {
        mip = "UNIX";
    } else {
        mip = "UNKNOWN";
    }
    if (mip == NULL) {
        errlog(conn->server->logsess, "Invalid IP Address: %s", strerror(errno));
    }
    acclog(conn->server->logsess, "%s %s %s/%s%s returned %s took: %f ms", mip, req->method,
           conn->server->id, rs->vhost->name, req->path, resp->code, msp);
    buffer_push(&rs->src_conn->write_buffer, serialized_response, response_length);
    ITER_LLIST(loaded_modules, value) {
        struct module* module = value;
        if (module->events.on_request_completed) {
            module->events.on_request_completed(module, rs);
        }
        ITER_LLIST_END();
    }
}

void determine_vhost(struct request_session* rs) {
    const char* host = header_get(rs->request->headers, "Host");
    if (host == NULL) host = "";
    struct vhost* vhost = NULL;
    for (size_t i = 0; i < rs->conn->server->vhosts->count; i++) {
        struct vhost* iter_vhost = rs->conn->server->vhosts->data[i];
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
    rs->vhost = vhost;
}

void http_on_closed(struct sub_conn* sub_conn) {
    pfree(sub_conn->conn->pool);
}

int handle_http_server_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    struct http_server_extra* extra = sub_conn->extra;
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    restart:;

    // active post reading
    if (extra->currently_posting != NULL) {
        struct provision* provision = extra->currently_posting->request->body;
        if (provision->type == PROVISION_DATA && sub_conn->read_buffer.size >= provision->data.data.size) {
            struct timespec stt;
            clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);
            pxfer(provision->pool, sub_conn->pool, provision->data.data.data);
            buffer_pop(&sub_conn->read_buffer, provision->data.data.size, provision->data.data.data);
            ITER_LLIST(loaded_modules, value) {
                struct module* module = value;
                if (module->events.on_request_post_received && module->events.on_request_post_received(module, extra->currently_posting)) {
                    return 1;
                }
                ITER_LLIST_END();
            }
            if (!extra->skip_generate_response) {
                generateResponse(extra->currently_posting);
            }
            if (extra->currently_posting->response->body != NULL && extra->currently_posting->response->body->type == PROVISION_STREAM) {
                extra->currently_streaming = extra->currently_posting;
                if (extra->currently_posting->response->body->data.stream.delay_header_output) {
                    memcpy(&extra->currently_posting->response->body->data.stream.delayed_start, &stt, sizeof(struct timespec));
                    extra->currently_posting->response->body->data.stream.delay_finish = send_request_session;
                } else {
                    send_request_session(extra->currently_posting, &stt);
                }
                extra->currently_posting = NULL;
                goto restart;
            } else {
                send_request_session(extra->currently_posting, &stt);
                pfree(extra->currently_posting->pool);
                extra->currently_posting = NULL;
            }
        } else { // PROVISION_STREAM
            errlog(delog, "Invalid state! STREAM found during active post read");
            return 0;
        }
    }

    if (extra->currently_streaming != NULL) {
        //TODO: this could causes a block-until-receive after a stream, fix
        //TODO: set to NULL when done
        //TODO:  if stream is done free currently_streaming
        return 0;
    }

    //TODO: while the HTTP spec doesn't allow \n\n, we should probably accept it similar to other implementations
    size_t match_length = 0;
    static unsigned char newlines[4] = {0x0D, 0x0A, 0x0D, 0x0A};

    // shrink read_buf if it was part header
    if (sub_conn->read_buffer.size < read_buf_len) {
        size_t shrink = read_buf_len - sub_conn->read_buffer.size;
        read_buf += shrink;
        read_buf_len -= shrink;
    }

    if (read_buf_len == 0) {
        return 0;
    }

    // prepare match_length from previous buffer
    struct llist_node* read_tail = sub_conn->read_buffer.buffers->tail;
    if (read_tail != NULL) {
        struct buffer_entry* entry = read_tail->data;
        if (entry->data == read_buf) {
            if (read_tail->prev == NULL) { // could be popped above
                goto post_precheck;
            }
            entry = read_tail->prev->data;
        }
        ssize_t checking_index = entry->size - 3;
        if (checking_index < 0)
            checking_index = 0;
        for (; checking_index < entry->size; ++checking_index) {
            char c = ((char*) entry->data)[checking_index];
            if (c == newlines[match_length]) {
                match_length++;
                if (match_length == 4) {
                    errlog(sub_conn->conn->server->logsess, "Invalid state! This should never happen.");
                }
            } else if (c == newlines[0]) {
                match_length = 1;
            } else {
                match_length = 0;
            }
        }
    }
    post_precheck:;

    // match double newline
    for (size_t checking_index = 0; checking_index < read_buf_len; ++checking_index) {
        char c = read_buf[checking_index];
        if (c == newlines[match_length]) {
            match_length++;
            if (match_length == 4) {
                struct mempool* req_pool = mempool_new();
                pchild(sub_conn->pool, req_pool);
                size_t req_size = sub_conn->read_buffer.size + checking_index + 1 - read_buf_len;
                unsigned char* request_headers = pmalloc(req_pool, req_size + 1);
                buffer_pop(&sub_conn->read_buffer, req_size, request_headers);
                request_headers[req_size] = 0;

                struct timespec stt;
                clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &stt);

                struct request_session* rs = pcalloc(req_pool, sizeof(struct request_session));
                rs->conn = sub_conn->conn;
                rs->src_conn = sub_conn;
                rs->request = pcalloc(req_pool, sizeof(struct request));
                rs->pool = req_pool;
                if (parseRequest(rs, (char*) request_headers, sub_conn->conn->server->max_post) < 0) {
                    errlog(sub_conn->conn->server->logsess, "Malformed Request!\n%s", request_headers);
                    sub_conn->on_closed(sub_conn);
                    return 1;
                }
                rs->response = pcalloc(rs->pool, sizeof(struct response));
                rs->response->headers = pcalloc(rs->pool, sizeof(struct headers));
                rs->response->headers->pool = rs->pool;
                rs->response->http_version = "HTTP/1.1";
                rs->response->http_version = rs->request->http_version;
                rs->response->code = "200 OK";
                int skip_generate_response = 0;
                ITER_LLIST(loaded_modules, value) {
                        struct module* module = value;
                        if (module->events.on_request_received) {
                            int status = module->events.on_request_received(module, rs);
                            if (status == 1) {
                                skip_generate_response = 1;
                                break;
                            } else if (status == -1) {
                                return 1;
                            }
                        }
                    ITER_LLIST_END();
                }
                determine_vhost(rs);
                ITER_LLIST(loaded_modules, value) {
                        struct module* module = value;
                        if (module->events.on_request_vhost_resolved) {
                            rs->vhost = module->events.on_request_vhost_resolved(module, rs, rs->vhost);
                        }
                    ITER_LLIST_END();
                }
                if (rs->request->body != NULL && rs->request->body->type == PROVISION_DATA) {
                    extra->currently_posting = rs;
                    extra->skip_generate_response = skip_generate_response;
                    goto restart;
                }
                if (!skip_generate_response) {
                    generateResponse(rs);
                }
                if (rs->response->body != NULL && rs->response->body->type == PROVISION_STREAM) {
                    extra->currently_streaming = rs;
                    if (rs->response->body->data.stream.delay_header_output) {
                        memcpy(&rs->response->body->data.stream.delayed_start, &stt, sizeof(struct timespec));
                        rs->response->body->data.stream.delay_finish = send_request_session;
                    } else {
                        send_request_session(rs, &stt);
                    }
                    goto restart;
                } else {
                    send_request_session(rs, &stt);
                    pfree(req_pool);
                }
            }
        } else if (c == newlines[0])
            match_length = 1;
        else
            match_length = 0;
    }
    return 0;
}

struct conn_node_arg {
    struct llist* list;
    struct llist_node* node;
};

void remove_conn_node(struct conn_node_arg* node) {
    llist_del(node->list, node->node);
}

void add_conn_node(struct conn_node_arg* node) {
    llist_append(node->list, node->node);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

void run_work(struct work_param* param) {
    if (pipe(param->pipes) != 0) {
        errlog(param->server->logsess, "Failed to create pipe! %s", strerror(errno));
        return;
    }
    struct mempool* pool = mempool_new();
    unsigned char wb;
    struct connection_manager* manager = pcalloc(pool, sizeof(struct connection_manager));
    manager->pending_sub_conns = llist_new(pool);
    struct llist* claimed_connections = llist_new(pool);
    struct llist* flattened_connections = llist_new(pool);
    struct llist* to_remove_flattened = llist_new(pool);
    struct pollfd* poll_fds = pmalloc(pool, sizeof(struct pollfd) * 64);
    size_t poll_fds_cap = 64;
    while (1) {
        // by only doing one pop per loop, we effectively create a QoS in which serving existing connections is prioritized over new ones, but also so some better load balancing.
        struct conn* new_conn = queue_maybepop(param->server->prepared_connections);
        if (new_conn != NULL) {
            new_conn->manager = manager;
            {
                struct conn_node_arg* arg = pmalloc(new_conn->pool, sizeof(struct conn_node_arg));
                arg->list = claimed_connections;
                arg->node = llist_append(claimed_connections, new_conn);
                phook(new_conn->pool, remove_conn_node, arg);
            }
            // assumes only 1 sub connection at this point!
            {
                struct sub_conn* base_conn = new_conn->sub_conns->head->data;
                struct conn_node_arg* arg = pmalloc(base_conn->pool, sizeof(struct conn_node_arg));
                arg->list = to_remove_flattened;
                arg->node = llist_append(flattened_connections, base_conn);
                phook(base_conn->pool, add_conn_node, arg);
            }
            // TODO: module connection initiated hook
        }
        for (struct llist_node* node = manager->pending_sub_conns->head; node != NULL; ) {
            struct sub_conn* sub_conn = node->data;
            llist_append(sub_conn->conn->sub_conns, sub_conn);
            struct conn_node_arg* arg = pmalloc(sub_conn->pool, sizeof(struct conn_node_arg));
            arg->list = to_remove_flattened;
            arg->node = llist_append(flattened_connections, sub_conn);
            phook(sub_conn->pool, add_conn_node, arg);
            struct llist_node* next = node->next;
            llist_del(manager->pending_sub_conns, node);
            node = next;
        }
        size_t poll_fd_count = flattened_connections->size + 1;
        struct mempool* iter_pool = mempool_new();
        size_t poll_fd_index = 0;
        if (poll_fds_cap < poll_fd_count + 1) {
            while (poll_fds_cap < poll_fd_count + 1) {
                poll_fds_cap *= 2;
            }
            poll_fds = prealloc(pool, poll_fds, sizeof(struct pollfd) * poll_fds_cap);
        }
        ITER_LLIST(flattened_connections, value) {
                struct sub_conn* sub_conn = value;
                struct pollfd* pollfd = &poll_fds[poll_fd_index++];
                pollfd->fd = sub_conn->fd;
                pollfd->events = (short) (POLLIN | ((sub_conn->write_buffer.size > 0 ||
                                                     (sub_conn->tls && !sub_conn->tls_handshaked &&
                                                                sub_conn->tls_next_direction == 2)) ? POLLOUT : 0));
                pollfd->revents = 0;
            ITER_LLIST_END();
        }
        struct pollfd* pollfd = &poll_fds[poll_fd_index++];
        pollfd->fd = param->pipes[0];
        pollfd->events = POLLIN;
        pollfd->revents = 0;
        int polled_count = poll(poll_fds, poll_fd_count, -1);
        if (polled_count < 0) {
            errlog(param->server->logsess, "Poll error in worker thread! %s", strerror(errno));
        } else if (polled_count == 0) {
            pfree(iter_pool);
            continue;
        } else if ((poll_fds[poll_fd_count - 1].revents & POLLIN) == POLLIN) {
            if (read(param->pipes[0], &wb, 1) < 1)
                errlog(param->server->logsess, "Error reading from pipe, infinite loop COULD happen here.");
            if (polled_count-- == 1) {
                pfree(iter_pool);
                continue;
            }
        }
        struct llist_node* flat_node = flattened_connections->head;
        for (int i = 0; i < poll_fd_count - 1 && polled_count > 0; i++) {
            int revents = poll_fds[i].revents;
            struct sub_conn* sub_conn = flat_node->data;
            flat_node = flat_node->next;
            if (revents == 0) continue;

            polled_count--;

            if ((revents & POLLHUP) == POLLHUP) {
                sub_conn->on_closed(sub_conn);
                continue;
            }
            if ((revents & POLLERR) == POLLERR) {
                sub_conn->on_closed(sub_conn);
                continue;
            }
            if ((revents & POLLNVAL) == POLLNVAL) {
                errlog(param->server->logsess, "Invalid FD in worker poll! This is bad!");
                sub_conn->on_closed(sub_conn);
                continue;
            }

            if (sub_conn->tls && !sub_conn->tls_handshaked) {
                int r = SSL_accept(sub_conn->tls_session);
                if (r == 1) {
                    sub_conn->tls_handshaked = 1;
                } else if (r == 2) {
                    sub_conn->on_closed(sub_conn);
                    continue;
                } else {
                    int err = SSL_get_error(sub_conn->tls_session, r);
                    if (err == SSL_ERROR_WANT_READ) sub_conn->tls_next_direction = 1;
                    else if (err == SSL_ERROR_WANT_WRITE) sub_conn->tls_next_direction = 2;
                    else {
                        sub_conn->on_closed(sub_conn);
                        continue;
                    }
                }
                continue;
            }
            if ((revents & POLLIN) == POLLIN) {
                size_t guessed_read_total = 0;
                int arbitrary_read_total = 0;
                if (sub_conn->tls) {
                    guessed_read_total = (size_t) SSL_pending(sub_conn->tls_session);
                    if (guessed_read_total == 0) {
                        guessed_read_total += 4096;
                        arbitrary_read_total = 1;
                    }
                } else {
                    ioctl(poll_fds[i].fd, FIONREAD, &guessed_read_total);
                }
                void* read_buf = pmalloc(sub_conn->pool, guessed_read_total);
                ssize_t read_total = 0;
                if (guessed_read_total == 0) { // nothing to read, but wont block.
                    ssize_t x = 0;
                    if (sub_conn->tls) {
                        x = SSL_read(sub_conn->tls_session, read_buf + read_total, (int) (guessed_read_total - read_total));
                        if (x <= 0) {
                            int serr = SSL_get_error(sub_conn->tls_session, (int) x);
                            if (serr == SSL_ERROR_WANT_WRITE || serr == SSL_ERROR_WANT_READ) continue;
                            sub_conn->on_closed(sub_conn);
                            continue;
                        }
                    } else {
                        x = read(poll_fds[i].fd, read_buf + read_total, guessed_read_total - read_total);
                        if (x <= 0) {
                            sub_conn->on_closed(sub_conn);
                            continue;
                        }
                    }
                    read_total += x;
                }
                while (read_total < guessed_read_total) {
                    ssize_t x = 0;
                    if (sub_conn->tls) {
                        x = SSL_read(sub_conn->tls_session, read_buf + read_total, (int) (guessed_read_total - read_total));
                        if (x <= 0) {
                            int serr = SSL_get_error(sub_conn->tls_session, (int) x);
                            if (serr == SSL_ERROR_WANT_WRITE || serr == SSL_ERROR_WANT_READ) goto cont;
                            sub_conn->on_closed(sub_conn);
                            goto cont;
                        }
                        read_total += x;
                        if (arbitrary_read_total) break;
                    } else {
                        x = read(poll_fds[i].fd, read_buf + read_total, guessed_read_total - read_total);
                        if (x <= 0) {
                            sub_conn->on_closed(sub_conn);
                            goto cont;
                        }
                    }
                    read_total += x;
                }
                int p = sub_conn->read(sub_conn, read_buf, (size_t) read_total);
                if (p == 1) {
                    sub_conn->on_closed(sub_conn);
                    continue;
                }
            }
            if ((revents & POLLOUT) == POLLOUT) {
                for (struct llist_node* node = sub_conn->write_buffer.buffers->head; node != NULL; ) {
                    struct buffer_entry* entry = node->data;
                    ssize_t mtr = sub_conn->tls ?
                                  SSL_write(sub_conn->tls_session, entry->data, (int) entry->size) :
                                  write(poll_fds[i].fd, entry->data, entry->size);
                    int serr = (sub_conn->tls && mtr < 0) ? SSL_get_error(sub_conn->tls_session, mtr) : 0;
                    if (mtr < 0 && (sub_conn->tls ? ((serr != SSL_ERROR_SYSCALL || errno != EAGAIN) &&
                                                  serr != SSL_ERROR_WANT_WRITE && serr != SSL_ERROR_WANT_READ) :
                                    errno != EAGAIN)) { // use error queue?
                        sub_conn->on_closed(sub_conn);
                        break;
                    } else if (mtr < 0) {
                        break;
                    } else if (mtr < entry->size) {
                        entry->data += mtr;
                        entry->size -= mtr;
                        sub_conn->write_buffer.size -= mtr;
                        break;
                    } else {
                        sub_conn->write_buffer.size -= mtr;
                        pprefree_strict(sub_conn->write_buffer.pool, entry->data_root);
                        struct llist_node* next = node->next;
                        llist_del(sub_conn->write_buffer.buffers, node);
                        node = next;
                        if (node == NULL) {
                            break;
                        } else {
                            continue;
                        }
                    }
                }
            }
            cont:;
        }
        for (struct llist_node* node = to_remove_flattened->head; node != NULL; ) {
            struct llist_node* next = node->next;
            struct llist_node* proper_node = node->data;
            llist_del(to_remove_flattened, node);
            llist_del(flattened_connections, proper_node);
            node = next;
        }
        pfree(iter_pool);
    }
}


/*
int finalizeHeaders2(struct conn* conn, struct work_param* param) {

	return 0;
}

int writeFrame(struct conn* conn, struct frame* frame, struct work_param* param) {
	unsigned char head[9];
	memcpy(head, &frame->length + sizeof(size_t) - 3, 3);
	head[3] = frame->type;
	head[4] = frame->flags;
	memcpy(head + 5, &frame->stream, sizeof(uint32_t));
	if (conn->writeBuffer == NULL) {
		conn->writeBuffer = smalloc(frame->length + 9);
		conn->writeBuffer_size = 0;
	} else {
		conn->writeBuffer = srealloc(conn->writeBuffer, conn->writeBuffer_size + frame->length + 9);
	}
	memcpy(conn->writeBuffer + conn->writeBuffer_size, head, 9);
	memcpy(conn->writeBuffer + conn->writeBuffer_size + 9, frame->uf, frame->length);
	return 0;
}

void freeFrame(struct frame* frame) {
	free(frame->uf);
}

int handleRead2(struct conn* conn, int ct, struct work_param* param) {
	if (conn->readBuffer_size >= 9) {
		size_t len = 0;
		memcpy(&len + sizeof(len) - 3, conn->readBuffer, 3);
		if (conn->readBuffer_size >= 9 + len) {
			struct frame* frame = smalloc(sizeof(struct frame));
			frame->length = len;
			frame->type = conn->readBuffer[3];
			frame->flags = conn->readBuffer[4];
			frame->stream = 0;
			frame->strobj = NULL;
			memcpy(&frame->stream + sizeof(size_t) - 4, conn->readBuffer + 5, 4);
			if (frame->stream > 0) for (int i = 0; i < conn->http2_stream_size; i++) {
				if (conn->http2_stream[i]->name == frame->stream) {
					frame->strobj = conn->http2_stream[i];
					break;
				}
			}
			printf("%i\n", frame->type);
			unsigned char* lframe = conn->readBuffer + 9;
			if (frame->type == FRAME_DATA_ID) {
				if (frame->strobj == NULL) {
					errno = EINVAL;
					return -1;
				}
				unsigned char pad = 0;
				size_t dl = len;
				if (frame->flags & 0x8 == 0x8) {
					if (len < 1) {
						errno = EINVAL;
						return -1;
					}
					pad = lframe[0];
					if (len < pad + 1) {
						errno = EINVAL;
						return -1;
					}
					lframe++;
					len -= 1 + pad;
				}
				if (frame->strobj->http2_dataBuffer == NULL) {
					frame->strobj->http2_dataBuffer = smalloc(len);
					frame->strobj->http2_dataBuffer_size = 0;
				} else {
					frame->strobj->http2_dataBuffer = srealloc(frame->strobj->http2_dataBuffer, frame->strobj->http2_dataBuffer_size + len);
				}
				memcpy(frame->strobj->http2_dataBuffer, frame->strobj->http2_dataBuffer_size + lframe, len);
				frame->strobj->http2_dataBuffer_size += len;
			} else if (frame->type == FRAME_HEADERS_ID) {
				if (frame->strobj == NULL) {
					frame->strobj = smalloc(sizeof(struct http2_stream)); //TODO reuse mem space in conn->http2_stream
					frame->strobj->name = frame->stream;
					frame->strobj->http2_dataBuffer = NULL;
					frame->strobj->http2_headerBuffer = NULL;
					frame->strobj->http2_dataBuffer_size = 0;
					frame->strobj->http2_headerBuffer_size = 0;
					if (conn->http2_stream == NULL) {
						conn->http2_stream = smalloc(sizeof(struct http2_stream*));
						conn->http2_stream_size = 0;
					} else {
						conn->http2_stream = srealloc(conn->http2_stream, sizeof(struct http2_stream*) * (conn->http2_stream_size + 1));
					}
					conn->http2_stream[conn->http2_stream_size] = frame->strobj;
					conn->http2_stream_size++;
				}
				unsigned char pad = 0;
				size_t dl = len;
				if (frame->flags & 0x8 == 0x8) {
					if (len < 1) {
						errno = EINVAL;
						return -1;
					}
					pad = lframe[0];
					if (len < pad + 1) {
						errno = EINVAL;
						return -1;
					}
					lframe++;
					len -= 1 + pad;
				}
				if (frame->flags & 0x20 == 0x20) {
					if (len < 5) {
						errno = EINVAL;
						return -1;
					}
					len -= 5; //TODO: stream dependency
				}
				if (frame->strobj->http2_headerBuffer == NULL) {
					frame->strobj->http2_headerBuffer = smalloc(len);
					frame->strobj->http2_headerBuffer_size = 0;
				} else {
					frame->strobj->http2_headerBuffer = srealloc(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + len);
				}
				memcpy(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + lframe, len);
				frame->strobj->http2_headerBuffer_size += len;
				if (frame->flags & 0x4 == 0x4) {
					if (finalizeHeaders2(conn, param) == -1) return -1;
				}
			} else if (frame->type == FRAME_PRIORITY_ID) {
				//TODO: impl
			} else if (frame->type == FRAME_RST_STREAM_ID) {
				//TODO: impl
			} else if (frame->type == FRAME_SETTINGS_ID) {
				if (len % 6 == 0) {
					for (int i = 0; i < len / 6; i++) {
						int name = 0;
						memcpy(&name + sizeof(int) - 2, lframe + len + (i * 6), 2);
						uint32_t val = 0;
						memcpy(&val, lframe + len + (i * 6) + 2, 4);

					}
				}
			} else if (frame->type == FRAME_PUSH_PROMISE_ID) {
				//TODO impl
			} else if (frame->type == FRAME_PING_ID) {

			} else if (frame->type == FRAME_GOAWAY_ID) {
				closeConn(param, conn);
				errno = ECONNRESET;
				return -1;
			} else if (frame->type == FRAME_WINDOW_UPDATE_ID) {

			} else if (frame->type == FRAME_CONTINUATION_ID) {
				if (frame->strobj == NULL) {
					closeConn(param, conn);
					errno = ECONNRESET;
					return -1;
				}
				size_t dl = len;
				if (frame->strobj->http2_headerBuffer == NULL) {
					frame->strobj->http2_headerBuffer = smalloc(len);
					frame->strobj->http2_headerBuffer_size = 0;
				} else {
					frame->strobj->http2_headerBuffer = srealloc(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + len);
				}
				memcpy(frame->strobj->http2_headerBuffer, frame->strobj->http2_headerBuffer_size + lframe, len);
				frame->strobj->http2_headerBuffer_size += len;
				if (frame->flags & 0x4 == 0x4) {
					if (finalizeHeaders2(conn, param) == -1) return -1;
				}
			}
			if (frame->flags & 0x1 == 0x1) {
				//close stream
			}
			conn->readBuffer_size -= 9 + len;
			memmove(conn->readBuffer, conn->readBuffer + 9 + len, conn->readBuffer_size);
		}
	}
	return 0;
}*/

#pragma clang diagnostic pop
