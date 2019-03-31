//
// Created by p on 3/30/19.
//


#ifndef AVUNA_HTTPD_VHOST_MOUNT_H
#define AVUNA_HTTPD_VHOST_MOUNT_H

#include <stdint.h>

struct mountpoint {
    char* path;
    char* vhost;
};

struct vhost_mount {
    struct list* mounts;
    uint8_t keep_prefix;
};


#endif //AVUNA_HTTPD_VHOST_MOUNT_H
