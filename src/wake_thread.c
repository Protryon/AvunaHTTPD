//
// Created by p on 3/23/19.
//

#include "wake_thread.h"
#include "network.h"
#include <avuna/queue.h>
#include <avuna/log.h>
#include <avuna/llist.h>
#include <unistd.h>
#include <errno.h>
#include <sys/epoll.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"

void wake_thread(struct wake_thread_arg* arg) {
    size_t counter = 0;
    while (1) {
        struct conn* conn = queue_pop(arg->server->prepared_connections);
        struct work_param* param = arg->work_params->data[counter];
        counter = (counter + 1) % arg->work_params->count;
        conn->manager = param->manager;
        ITER_LLIST(conn->sub_conns, value) {
            struct sub_conn* sub_conn = value;
            struct epoll_event event;
            event.events = EPOLLIN | EPOLLOUT | EPOLLET;
            event.data.ptr = sub_conn;
            if (epoll_ctl(param->epoll_fd, EPOLL_CTL_ADD, sub_conn->fd, &event)) {
                errlog(param->server->logsess, "Failed to add fd to epoll! %s", strerror(errno));
                continue;
            }
            ITER_LLIST_END();
        }
    }
}

#pragma clang diagnostic pop