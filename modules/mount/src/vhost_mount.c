//
// Created by p on 3/30/19.
//

#include "vhost_mount.h"
#include <avuna/http.h>
#include <avuna/vhost.h>
#include <avuna/string.h>
#include <avuna/module.h>

int handle_vhost_mount(struct request_session* rs) {
    struct vhost* vhost = rs->vhost;
    struct vhost_mount* vhm = vhost->sub->extra;
    char* oid = vhost->name;
    vhost = NULL;
    for (int i = 0; i < vhm->mounts->count; i++) {
        struct mountpoint* mount = vhm->mounts->data[i];
        if (str_prefixes_case(rs->request->path, mount->path)) {
            for (size_t x = 0; x < rs->conn->server->vhosts->count; x++) {
                struct vhost* iter_vhost = rs->conn->server->vhosts->data[x];
                if (str_eq(mount->vhost, iter_vhost->name) && !str_eq(iter_vhost->name, oid)) {
                    if (!vhm->keep_prefix) {
                        size_t vhpls = strlen(mount->path);
                        char* tmpp = str_dup(rs->request->path, 0, rs->pool);
                        char* tmpp2 = tmpp + vhpls;
                        if (tmpp2[0] != '/') {
                            tmpp2--;
                            tmpp2[0] = '/';
                        }
                        rs->request->path = tmpp2;
                    }
                    vhost = iter_vhost;
                    rs->vhost = vhost;
                    break;
                }
            }
            if (vhost != NULL) break;
        }
    }
    return VHOST_ACTION_RESTART;
}

int mount_parse_config(struct vhost* vhost, struct config_node* node) {
    struct vhost_mount* mount = vhost->sub->extra = pcalloc(vhost->pool, sizeof(struct vhost_mount));
    mount->mounts = list_new(8, vhost->pool);
    ITER_MAP(node->map) {
        if (str_prefixes_case(str_key, "/")) {
            struct mountpoint* point = pmalloc(vhost->pool, sizeof(struct mountpoint));
            point->path = str_key;
            point->vhost = value;
            list_add(mount->mounts, point);
        }
        ITER_MAP_END();
    }
    mount->keep_prefix = (uint8_t) str_eq(config_get_default(node, "keep-prefix", "false"), "true");
    return 0;
}


void initialize(struct module* module) {
    struct vhost_type* vhost_type = pcalloc(module->pool, sizeof(struct vhost_type));
    vhost_type->handle_request = handle_vhost_mount;
    vhost_type->load_config = mount_parse_config;
    vhost_type->name = "mount";
    hashmap_put(registered_vhost_types, "mount", vhost_type);
}