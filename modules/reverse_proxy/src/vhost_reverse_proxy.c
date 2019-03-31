//
// Created by p on 3/30/19.
//

#include "vhost_reverse_proxy.h"
#include <avuna/http.h>
#include <avuna/vhost.h>
#include <avuna/pmem_hooks.h>
#include <avuna/util.h>
#include <avuna/module.h>
#include <avuna/string.h>
#include <avuna/globals.h>
#include <mod_htdocs/vhost_htdocs.h>
#include <mod_htdocs/util.h>
#include <mod_htdocs/gzip.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>


void handle_vhost_reverse_proxy(struct request_session* rs) {
    struct vhost_reverse_proxy* rproxy = ((struct vhost_reverse_proxy*) rs->vhost->sub->extra);
    if (rproxy->base.scacheEnabled && check_cache(rs)) {
        return;
    }
    // remove leading slash
    char* htpath;
    {
        size_t path_length = strlen(rs->request->path);
        if (path_length < 1 || rs->request->path[0] != '/') {
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "Malformed Request! If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
        htpath = pmalloc(rs->pool, path_length);
        memcpy(htpath, rs->request->path + 1, path_length);
        htpath[path_length - 1] = 0;
    }
    // remove query parameters, if any
    {
        char* htpath_part = strchr(htpath, '#');
        if (htpath_part != NULL) htpath_part[0] = 0;
        htpath_part = strchr(htpath, '?');
        if (htpath_part != NULL) htpath_part[0] = 0;
    }

    // directory fix no applicable?
    if (rs->conn->forward_conn == NULL) {
        rs->conn->forward_conn = pcalloc(rs->pool, sizeof(struct sub_conn));
        rs->conn->forward_conn->fd = -1;
        buffer_init(&rs->conn->forward_conn->read_buffer, rs->conn->pool);
        //todo: TLS
    }
    init_forward_connection:;
    if (rs->conn->forward_conn->fd < 0) {
        rs->conn->forward_conn->fd = socket(rproxy->forward_address->sa_family == AF_INET ? PF_INET : PF_LOCAL,
                                            SOCK_STREAM, 0);
        if (rs->conn->forward_conn->fd < 0 ||
            connect(rs->conn->forward_conn->fd, rproxy->forward_address, rproxy->forward_address_length) < 0) {
            errlog(rs->conn->server->logsess, "Failed to create/connect to forwarding socket: %s",
                   strerror(errno));
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
        phook(rs->pool, close_hook, (void*) rs->conn->forward_conn->fd);
    }

    size_t sreql = 0;
    unsigned char* sreq = serializeRequest(rs, &sreql);
    size_t wr = 0;
    while (wr < sreql) {
        ssize_t x = write(rs->conn->forward_conn->fd, sreq + wr, sreql - wr);
        if (x < 1) {
            // we should ideally close the current connection here, but it will have to wait until the connection closes due to the `phook` call above.
            rs->conn->forward_conn->fd = -1;
            goto init_forward_connection;
        }
        wr += x;
    }

    if (rs->conn->fw_queue == NULL) {
        rs->conn->fw_queue = queue_new(0, 1, rs->pool);
    }
    // why do we copy here?
    struct request_session* rs2 = pmalloc(rs->pool, sizeof(struct request_session));
    memcpy(rs2, rs, sizeof(struct request_session));
    queue_push(rs->conn->fw_queue, rs2);

    check_client_cache(rs);

    return_error:;

    int do_gzip = should_gzip(rs);

    if (do_gzip == 1) {
        if (rs->response->body->type == PROVISION_DATA) {
            if (gzip_total(rs)) {
                // gzip failed, continue without it
                do_gzip = 0;
            }
        } else { // PROVISION_STREAM
            struct provision* gzip_overlay = xcopy(rs->response->body, sizeof(struct provision), 0, rs->response->body->pool);
            init_gzip_stream(rs, rs->response->body, gzip_overlay);
            rs->response->body = gzip_overlay;
        }
    }

    if (rproxy->base.scacheEnabled && rs->response->body->type == PROVISION_DATA &&
        (rproxy->base.maxCache <= 0 || rproxy->base.maxCache < rproxy->base.cache->max_size) &&
        !hashset_has(rproxy->dynamic_types, rs->response->body->content_type)) {
        rs->request->add_to_cache = 1;
    }
    //TODO: Chunked
}


int rproxy_parse_config(struct vhost* vhost, struct config_node* node) {
    struct vhost_reverse_proxy* rproxy = vhost->sub->extra = pcalloc(vhost->pool, sizeof(struct vhost_reverse_proxy));
    rproxy->base.error_pages = hashmap_new(8, vhost->pool);
    rproxy->base.enableGzip = 1;
    rproxy->base.cache_types = list_new(8, vhost->pool);
    rproxy->base.maxAge = 604800;
    rproxy->base.scacheEnabled = (uint8_t) str_eq(load_default(node, "scache", "true"), "true");
    rproxy->dynamic_types = hashset_new(8, vhost->pool);

    char* temp = load_default(node, "cache-maxage", "604800");
    if (!str_isunum(temp)) {
        errlog(delog, "Invalid cache-maxage at vhost: %s, assuming '604800'", node->name);
        temp = "604800";
    }
    rproxy->base.maxAge = strtoul(temp, NULL, 10);
    temp = load_default(node, "maxSCache", "0");
    if (!str_isunum(temp)) {
        errlog(delog, "Invalid maxSCache at vhost: %s, assuming '0'", node->name);
        temp = "0";
    }
    rproxy->base.cache = cache_new(strtoul(temp, NULL, 10));
    pchild(vhost->pool, rproxy->base.cache->pool);
    rproxy->base.enableGzip = (uint8_t) str_eq(load_default(node, "enable-gzip", "true"), "true");
    rproxy->xforwarded_header = (uint8_t) str_eq(load_default(node, "X-Forwarded", "true"), "true");
    rproxy->forward_prefix_path = (char*) getConfigValue(node, "forward-prefix");

    const char* forward_mode = load_default(node, "forward-mode", "tcp");
    if (str_eq(forward_mode, "tcp")) {
        rproxy->forward_address_length = sizeof(struct sockaddr_in);
        struct sockaddr_in* ina = pmalloc(vhost->pool, sizeof(struct sockaddr_in));
        rproxy->forward_address = (struct sockaddr*) ina;
        ina->sin_family = AF_INET;
        const char* forward_ip = getConfigValue(node, "forward-ip");
        const char* forward_port = getConfigValue(node, "forward-port");
        if (forward_ip == NULL || !inet_aton(forward_ip, &ina->sin_addr)) {
            errlog(delog, "Invalid IP for Reverse Proxy vhost: %s", node->name);
            return 1;
        }
        if (forward_port == NULL || !str_isunum(forward_port)) {
            errlog(delog, "Invalid Port for Reverse Proxy vhost: %s", node->name);
            return 1;
        }
        ina->sin_port = (uint16_t) strtoul(forward_port, NULL, 10);
    } else if (str_eq(forward_mode, "unix")) {
        rproxy->forward_address_length = sizeof(struct sockaddr_un);
        struct sockaddr_un* ina = pmalloc(vhost->pool, sizeof(struct sockaddr_un));
        rproxy->forward_address = ina;
        ina->sun_family = AF_LOCAL;
        const char* ffile = getConfigValue(node, "file");
        if (ffile == NULL || strlen(ffile) >= 107) {
            errlog(delog, "Invalid Unix Socket for Reverse Proxy vhost: %s", node->name);
            return 1;
        }
        memcpy(ina->sun_path, ffile, strlen(ffile) + 1);
    } else {
        errlog(delog, "Invalid mode for Reverse Proxy vhost: %s", node->name);
        return 1;
    }

    temp = load_default(node, "cache-types", "text/css,application/javascript,image/*");
    char* temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", rproxy->base.cache_types);
    for (size_t i = 0; i < rproxy->base.cache_types->count; ++i) {
        rproxy->base.cache_types->data[i] = str_trim(rproxy->base.cache_types->data[i]);
    }

    temp = load_default(node, "dynamic-types", "application/x-php");
    temp2 = str_dup(temp, 0, vhost->pool);
    struct list* dynamic_list = list_new(8, vhost->pool);
    str_split(temp2, ",", dynamic_list);
    for (size_t i = 0; i < dynamic_list->count; ++i) {
        hashset_add(rproxy->dynamic_types, str_trim(dynamic_list->data[i]));
    }

    ITER_MAP(node->map) {
        if (str_prefixes(str_key, "error-")) {
            const char* en = str_key + 6;
            if (!str_isunum(en)) {
                errlog(delog, "Invalid error page specifier at vhost: %s", node->name);
                continue;
            }
            hashmap_putptr(rproxy->base.error_pages, (void*) strtoul(en, NULL, 10), value);
        }
        ITER_MAP_END();
    }

    rproxy->appended_headers = NULL;
    ITER_MAP(node->map) {
        if (str_prefixes(str_key, "header-")) {
            if (rproxy->appended_headers == NULL) {
                rproxy->appended_headers = pcalloc(vhost->pool, sizeof(struct headers));
                rproxy->appended_headers->pool = vhost->pool;
            }
            header_add(rproxy->appended_headers, str_key + 7, value);
        }
        ITER_MAP_END();
    }

    return 0;
}


void initialize(struct module* module) {
    struct vhost_type* vhost_type = pcalloc(module->pool, sizeof(struct vhost_type));
    vhost_type->handle_request = handle_vhost_reverse_proxy;
    vhost_type->load_config = rproxy_parse_config;
    vhost_type->name = "reverse_proxy";
    hashmap_put(registered_vhost_types, "reverse_proxy", vhost_type);
}