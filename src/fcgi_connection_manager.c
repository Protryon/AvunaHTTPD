//
// Created by p on 2/10/19.
//

#include "fcgi_connection_manager.h"

int fcgi_request_connection(struct fcgi* fcgi) {
    int fd = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (connect(fd, fcgi->addr, fcgi->addrlen)) {
        close(fd);
        return -1;
    }
    return fd;
}