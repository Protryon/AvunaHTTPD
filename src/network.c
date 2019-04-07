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
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

void trigger_write(struct sub_conn* sub_conn) {
    if (sub_conn->write_available && sub_conn->write_buffer.size > 0) {
        for (struct llist_node* node = sub_conn->write_buffer.buffers->head; node != NULL; ) {
            struct buffer_entry* entry = node->data;
            size_t written;
            if (sub_conn->tls) {
                ssize_t mtr = SSL_write(sub_conn->tls_session, entry->data, (int) entry->size);
                if (mtr < 0 && errno == EAGAIN) {
                    sub_conn->write_available = 0;
                    break;
                } else if (mtr < 0) {
                    sub_conn->safe_close = 1;
                    break;
                }
                written = (size_t) mtr;

            } else {
                ssize_t mtr = write(sub_conn->fd, entry->data, entry->size);
                if (mtr < 0) {
                    int ssl_error = SSL_get_error(sub_conn->tls_session, (int) mtr);
                    if (ssl_error == SSL_ERROR_SYSCALL && errno == EAGAIN) {
                        sub_conn->write_available = 0;
                        break;
                    } else if (ssl_error != SSL_ERROR_WANT_WRITE && ssl_error != SSL_ERROR_WANT_READ) {
                        sub_conn->safe_close = 1;
                        return;
                    }
                }
                written = (size_t) mtr;
            }
            if (written < entry->size) {
                entry->data += written;
                entry->size -= written;
                sub_conn->write_available = 1;
                sub_conn->write_buffer.size -= written;
                break;
            } else {
                sub_conn->write_buffer.size -= written;
                pprefree_strict(sub_conn->write_buffer.pool, entry->data_root);
                struct llist_node* next = node->next;
                llist_del(sub_conn->write_buffer.buffers, node);
                node = next;
                if (node == NULL) {
                    sub_conn->write_available = 1;
                    break;
                } else {
                    continue;
                }
            }
        }
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

void run_work(struct work_param* param) {
    struct mempool* pool = mempool_new();
    param->manager = pcalloc(pool, sizeof(struct connection_manager));
    param->manager->pending_sub_conns = llist_new(pool);
    struct epoll_event events[128];
    while (1) {
        for (struct llist_node* node = param->manager->pending_sub_conns->head; node != NULL; ) {
            struct sub_conn* sub_conn = node->data;
            llist_append(sub_conn->conn->sub_conns, sub_conn);
            struct epoll_event event;
            event.events = EPOLLIN | EPOLLOUT | EPOLLET;
            event.data.ptr = sub_conn;
            if (epoll_ctl(param->epoll_fd, EPOLL_CTL_ADD, sub_conn->fd, &event)) {
                errlog(param->server->logsess, "Failed to add fd to epoll! %s", strerror(errno));
            }
            struct llist_node* next = node->next;
            llist_del(param->manager->pending_sub_conns, node);
            node = next;
        }
        int epoll_status = epoll_wait(param->epoll_fd, events, 128, -1);
        if (epoll_status < 0) {
            errlog(param->server->logsess, "Epoll error in worker thread! %s", strerror(errno));
        } else if (epoll_status == 0) {
            continue;
        }
        for (int i = 0; i < epoll_status; ++i) {
            struct epoll_event* event = &events[i];
            struct sub_conn* sub_conn = event->data.ptr;
            if (sub_conn->safe_close) {
                sub_conn->on_closed(sub_conn);
                continue;
            }
            if (event->events == 0) continue;

            if (event->events & EPOLLHUP) {
                sub_conn->on_closed(sub_conn);
                continue;
            }
            if (event->events & EPOLLERR) {
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
                    if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                        sub_conn->on_closed(sub_conn);
                        continue;
                    }
                }
                continue;
            }


            if (event->events & EPOLLOUT) {
                sub_conn->write_available = 1;
                trigger_write(sub_conn);
            }

            if (event->events & EPOLLIN) {
                void* read_buf = NULL;
                size_t read_total = 0;
                if (sub_conn->tls) {
                    size_t read_capacity = (size_t) SSL_pending(sub_conn->tls_session);
                    if (read_capacity == 0) {
                        ioctl(sub_conn->fd, FIONREAD, &read_capacity);
                        if (read_capacity < 64) {
                            read_capacity = 1024;
                        }
                    }
                    ++read_capacity;
                    read_buf = pmalloc(sub_conn->pool, read_capacity);
                    ssize_t r;
                    while ((r = SSL_read(sub_conn->tls_session, read_buf + read_total, (int) (read_capacity - read_total))) > 0) {
                        read_total += r;
                        if (read_total == read_capacity) {
                            read_capacity *= 2;
                            read_buf = prealloc(sub_conn->pool, read_buf, read_capacity);
                        }
                    }
                    if (r == 0) {
                        sub_conn->on_closed(sub_conn);
                        continue;
                    } else { // < 0
                        int ssl_error = SSL_get_error(sub_conn->tls_session, (int) r);
                        if (!(ssl_error == SSL_ERROR_SYSCALL && errno == EAGAIN) && ssl_error != SSL_ERROR_WANT_WRITE && ssl_error != SSL_ERROR_WANT_READ) {
                            sub_conn->on_closed(sub_conn);
                            continue;
                        }
                    }
                } else {
                    size_t read_capacity = 0;
                    ioctl(sub_conn->fd, FIONREAD, &read_capacity);
                    ++read_capacity;
                    read_buf = pmalloc(sub_conn->pool, read_capacity);
                    ssize_t r;
                    while ((r = read(sub_conn->fd, read_buf + read_total, read_capacity - read_total)) > 0) {
                        read_total += r;
                        if (read_total == read_capacity) {
                            read_capacity *= 2;
                            read_buf = prealloc(sub_conn->pool, read_buf, read_capacity);
                        }
                    }
                    if (r == 0 || (r < 0 && errno != EAGAIN)) {
                        sub_conn->on_closed(sub_conn);
                        continue;
                    }
                }
                int p = sub_conn->read(sub_conn, read_buf, read_total);
                if (p == 1) {
                    sub_conn->on_closed(sub_conn);
                    continue;
                }
            }

            cont:;
        }
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
	memcpy(head + 5, &frame->stream_id, sizeof(uint32_t));
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
			frame->stream_id = 0;
			frame->stream = NULL;
			memcpy(&frame->stream_id + sizeof(size_t) - 4, conn->readBuffer + 5, 4);
			if (frame->stream_id > 0) for (int i = 0; i < conn->http2_stream_size; i++) {
				if (conn->http2_stream[i]->name == frame->stream_id) {
					frame->stream = conn->http2_stream[i];
					break;
				}
			}
			printf("%i\n", frame->type);
			unsigned char* lframe = conn->readBuffer + 9;
			if (frame->type == FRAME_DATA_ID) {
				if (frame->stream == NULL) {
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
				if (frame->stream->http2_dataBuffer == NULL) {
					frame->stream->http2_dataBuffer = smalloc(len);
					frame->stream->http2_dataBuffer_size = 0;
				} else {
					frame->stream->http2_dataBuffer = srealloc(frame->stream->http2_dataBuffer, frame->stream->http2_dataBuffer_size + len);
				}
				memcpy(frame->stream->http2_dataBuffer, frame->stream->http2_dataBuffer_size + lframe, len);
				frame->stream->http2_dataBuffer_size += len;
			} else if (frame->type == FRAME_HEADERS_ID) {
				if (frame->stream == NULL) {
					frame->stream = smalloc(sizeof(struct http2_stream)); //TODO reuse mem space in conn->http2_stream
					frame->stream->name = frame->stream_id;
					frame->stream->http2_dataBuffer = NULL;
					frame->stream->http2_headerBuffer = NULL;
					frame->stream->http2_dataBuffer_size = 0;
					frame->stream->http2_headerBuffer_size = 0;
					if (conn->http2_stream == NULL) {
						conn->http2_stream = smalloc(sizeof(struct http2_stream*));
						conn->http2_stream_size = 0;
					} else {
						conn->http2_stream = srealloc(conn->http2_stream, sizeof(struct http2_stream*) * (conn->http2_stream_size + 1));
					}
					conn->http2_stream[conn->http2_stream_size] = frame->stream;
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
					len -= 5; //TODO: stream_id dependency
				}
				if (frame->stream->http2_headerBuffer == NULL) {
					frame->stream->http2_headerBuffer = smalloc(len);
					frame->stream->http2_headerBuffer_size = 0;
				} else {
					frame->stream->http2_headerBuffer = srealloc(frame->stream->http2_headerBuffer, frame->stream->http2_headerBuffer_size + len);
				}
				memcpy(frame->stream->http2_headerBuffer, frame->stream->http2_headerBuffer_size + lframe, len);
				frame->stream->http2_headerBuffer_size += len;
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
				if (frame->stream == NULL) {
					closeConn(param, conn);
					errno = ECONNRESET;
					return -1;
				}
				size_t dl = len;
				if (frame->stream->http2_headerBuffer == NULL) {
					frame->stream->http2_headerBuffer = smalloc(len);
					frame->stream->http2_headerBuffer_size = 0;
				} else {
					frame->stream->http2_headerBuffer = srealloc(frame->stream->http2_headerBuffer, frame->stream->http2_headerBuffer_size + len);
				}
				memcpy(frame->stream->http2_headerBuffer, frame->stream->http2_headerBuffer_size + lframe, len);
				frame->stream->http2_headerBuffer_size += len;
				if (frame->flags & 0x4 == 0x4) {
					if (finalizeHeaders2(conn, param) == -1) return -1;
				}
			}
			if (frame->flags & 0x1 == 0x1) {
				//close stream_id
			}
			conn->readBuffer_size -= 9 + len;
			memmove(conn->readBuffer, conn->readBuffer + 9 + len, conn->readBuffer_size);
		}
	}
	return 0;
}*/

#pragma clang diagnostic pop
