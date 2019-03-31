//
// Created by p on 3/30/19.
//

#ifndef AVUNA_HTTPD_VHOST_REVERSE_PROXY_H
#define AVUNA_HTTPD_VHOST_REVERSE_PROXY_H

#include <mod_htdocs/vhost_htdocs.h>

struct vhost_reverse_proxy {
    struct vhost_htbase base;
    struct sockaddr* forward_address;
    socklen_t forward_address_length;
    char* forward_prefix_path; // TODO: use
    struct headers* appended_headers;
    struct hashset* dynamic_types;
    int xforwarded_header; // TODO: use
};


#endif //AVUNA_HTTPD_VHOST_REVERSE_PROXY_H
