//
// Created by p on 3/29/19.
//

#ifndef AVUNA_HTTPD_MODULE_H
#define AVUNA_HTTPD_MODULE_H

#include <avuna/pmem.h>
#include <avuna/hash.h>
#include <avuna/config.h>
#include <avuna/http.h>
#include <avuna/connection.h>
#include <stdint.h>

struct hashmap* loaded_modules_by_name;
struct llist* loaded_modules;

// modules add providers, provider types, and vhost types
struct module {
    struct mempool* pool;
    void* handle;
    char* name;
    void* extra;
    void (*initialize)(struct module* module);
    void (*uninitialize)(struct module* module);
    struct {
        int (*on_connect)(struct module* module, struct conn* conn); // 0 = do nothing, 1 = reject
        void (*on_disconnect)(struct module* module, struct conn* conn);
        int (*on_request_received)(struct module* module, struct request_session* rs); // 0 = do nothing, 1 = no further processing (i.e. error page return), -1 = drop connection. POST data not yet available
        struct vhost* (*on_request_vhost_resolved)(struct module* module, struct request_session* rs, struct vhost* vhost); // overrides default vhost identification
        int (*on_request_post_received)(struct module* module, struct request_session* rs); // 0 = do nothing, 1 = drop connection
        char* (*on_mime_type_resolved)(struct module* module, struct request_session* rs, char* mime_type); // overrides mime types
        struct provider* (*on_request_handler_found)(struct module* module, struct request_session* rs, struct provider* provider); // allows provider overwriting before provision is returned.
        void (*on_request_handled)(struct module* module, struct request_session* rs); // called after provision is called
        void (*on_request_processed)(struct module* module, struct request_session* rs); // called after vhost logic is terminated
        void (*on_request_completed)(struct module* module, struct request_session* rs); // called after request headers but not necessarily accompanying body have been dispatched
    } events;
};

#endif //AVUNA_HTTPD_MODULE_H
