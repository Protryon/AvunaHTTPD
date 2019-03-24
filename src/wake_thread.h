//
// Created by p on 3/23/19.
//

#ifndef AVUNA_HTTPD_WAKE_THREAD_H
#define AVUNA_HTTPD_WAKE_THREAD_H

#include "list.h"
#include "server.h"

struct wake_thread_arg {
    struct list* work_params;
    struct server_info* server;
};

void wake_thread(struct wake_thread_arg* arg);

#endif //AVUNA_HTTPD_WAKE_THREAD_H
