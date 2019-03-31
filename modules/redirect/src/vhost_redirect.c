//
// Created by p on 3/30/19.
//

#include "vhost_redirect.h"
#include <avuna/http.h>
#include <avuna/vhost.h>
#include <avuna/string.h>
#include <avuna/module.h>
#include <avuna/globals.h>

void handle_vhost_redirect(struct request_session* rs) {
    struct vhost* vhost = rs->vhost;
    struct vhost_redirect* redirect = vhost->sub->extra;
    rs->response->code = "302 Found";
    header_add(rs->response->headers, "Location", redirect->redir);
}

int redirect_parse_config(struct vhost* vhost, struct config_node* node) {
    struct vhost_redirect* redirect = vhost->sub->extra = pcalloc(vhost->pool, sizeof(struct vhost_mount));
    redirect->redir = (char*) getConfigValue(node, "redirect");
    if (redirect->redir == NULL) {
        errlog(delog, "No redirect at vhost: %s", node->name);
        return 1;
    }
    return 0;
}


void initialize(struct module* module) {
    struct vhost_type* vhost_type = pcalloc(module->pool, sizeof(struct vhost_type));
    vhost_type->handle_request = handle_vhost_redirect;
    vhost_type->load_config = redirect_parse_config;
    vhost_type->name = "reverse_proxy";
    hashmap_put(registered_vhost_types, "reverse_proxy", vhost_type);
}