/*
 * vhost.h
 *
 *  Created on: Dec 13, 2015
 *      Author: root
 */

#ifndef VHOST_H_
#define VHOST_H_

#define VHOST_HTDOCS 0
#define VHOST_RPROXY 1
#define VHOST_REDIRECT 2
#define VHOST_MOUNT 3

#include <avuna/cache.h>
#include <sys/socket.h>
#include <stdint.h>
#include <avuna/tls.h>



struct vhost {
    uint8_t type;
    struct cert* ssl_cert;
    struct list* hosts;
    char* id;
    struct mempool* pool;
    union {
        struct vhost_htdocs htdocs;
        struct vhost_rproxy rproxy;
        struct vhost_redirect redirect;
        struct vhost_mount mount;
    } sub;
};

int domeq(const char* dom1, const char* dom2);

#endif /* VHOST_H_ */
