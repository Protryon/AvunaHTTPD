//
// Created by p on 3/31/19.
//

#include <avuna/connection.h>
#include <avuna/pmem.h>
#include <avuna/log.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <sys/socket.h>


int configure_fd(struct logsess* logger, int fd, int is_tcp) {
    static struct timeval timeout;
    timeout.tv_sec = 60;
    timeout.tv_usec = 0;
    static int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*) &timeout, sizeof(timeout)))
        errlog(logger, "Setting recv timeout failed! %s", strerror(errno));
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*) &timeout, sizeof(timeout)))
        errlog(logger, "Setting send timeout failed! %s", strerror(errno));
    if (is_tcp && setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*) &one, sizeof(one)))
        errlog(logger, "Setting TCP_NODELAY failed! %s", strerror(errno));
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK) < 0) {
        errlog(logger, "Setting O_NONBLOCK failed! %s, this error cannot be recovered, closing client.", strerror(errno));
        return 1;
    }
    return 0;
}