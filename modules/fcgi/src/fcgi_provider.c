//
// Created by p on 3/30/19.
//

#include "fcgi_protocol.h"
#include <avuna/provider.h>
#include <avuna/config.h>
#include <avuna/http.h>
#include <avuna/module.h>
#include <avuna/pmem.h>
#include <avuna/string.h>
#include <avuna/globals.h>
#include <avuna/http_util.h>
#include <avuna/version.h>
#include <avuna/pmem_hooks.h>
#include <avuna/util.h>
#include <mod_htdocs/util.h>
#include <mod_htdocs/vhost_htdocs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

struct fcgi_config {
    socklen_t addrlen;
    struct sockaddr* addr;
    uint16_t req_id_counter;
};

int fcgi_load_config(struct provider* provider, struct config_node* node) {
    struct fcgi_config* fcgi = provider->extra = pcalloc(provider->pool, sizeof(struct fcgi_config));
    const char* mode = config_get(node, "mode");
    if (str_eq(mode, "tcp")) {
        fcgi->addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in* ina = pmalloc(provider->pool, sizeof(struct sockaddr_in));
        fcgi->addr = (struct sockaddr*) ina;
        ina->sin_family = AF_INET;
        const char* ip = config_get(node, "ip");
        const char* port = config_get(node, "port");
        if (ip == NULL || !inet_aton(ip, &ina->sin_addr)) {
            errlog(delog, "Invalid IP for FCGI node %s", node->name);
            return 1;
        }
        if (port == NULL || !str_isunum(port)) {
            errlog(delog, "Invalid Port for FCGI node %s", node->name);
            return 1;
        }
        ina->sin_port = htons((uint16_t) strtoul(port, NULL, 10));
    } else if (str_eq(mode, "unix")) {
        fcgi->addrlen = sizeof(struct sockaddr_un);
        struct sockaddr_un* ina = pmalloc(provider->pool, sizeof(struct sockaddr_un));
        fcgi->addr = (struct sockaddr*) ina;
        ina->sun_family = AF_LOCAL;
        const char* file = config_get(node, "file");
        if (file == NULL || strlen(file) >= 107) {
            errlog(delog, "Invalid Unix Socket for FCGI node %s", node->name);
            return 1;
        }
        memcpy(ina->sun_path, file, strlen(file) + 1);
    } else {
        errlog(delog, "Invalid mode for FCGI node %s", node->name);
        return 1;
    }
    return 0;
}


int fcgi_request_connection(struct request_session* rs, struct fcgi_config* fcgi) {
    int fd = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    if (configure_fd(rs->conn->server->logsess, fd, fcgi->addr->sa_family != AF_UNIX)) {
        return -1;
    }
    if (connect(fd, fcgi->addr, fcgi->addrlen) && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    return fd;
}

struct fcgi_stream_data {
    struct request_session* rs;
    struct provision* provision;
    uint16_t request_id;
    int stdout_state; // 0 = headers, 1 = errors, 2 = headers read finished, 3 = body
    struct buffer headers;
    struct buffer* output;
    int complete;
};

int fcgi_read(struct sub_conn* sub_conn, uint8_t* read_buf, size_t read_buf_len) {
    buffer_push(&sub_conn->read_buffer, read_buf, read_buf_len);
    struct fcgi_stream_data* extra = sub_conn->extra;
    struct fcgi_frame frame;
    frame.type = FCGI_BEGIN_REQUEST;
    int output_ready = 0;
    while (frame.type != FCGI_END_REQUEST) {
        ssize_t status = fcgi_readFrame(&sub_conn->read_buffer, &frame, extra->output->pool);
        if (status == -2) {
            if (output_ready && extra->provision->data.stream.notify(extra->rs)) {
                return 1;
            }
            return 0;
        } else if (status == -1) {
            return 1;
        }

        // fcgi server messed up and replied to wrong request on wrong connection
        if (frame.request_id != extra->request_id) {
            frame.type = FCGI_BEGIN_REQUEST; // to prevent termination of loop
            errlog(sub_conn->conn->server->logsess, "FCGI server returned invalid request name.");
            continue;
        }

        if (frame.type == FCGI_END_REQUEST) {
            continue;
        }

        if (frame.type == FCGI_STDERR) {
            errlog(sub_conn->conn->server->logsess, "FCGI STDERR <%s>: %s", extra->rs->request_htpath, frame.data);
        }

        if (frame.type == FCGI_STDOUT || frame.type == FCGI_STDERR) {
            size_t headers_read = 0;
            if (frame.type == FCGI_STDOUT) {
                if (extra->stdout_state == 0) {
                    int match_length = 0;
                    char* tm = "\r\n\r\n";
                    for (size_t i = 0; i < frame.len; i++) {
                        if (((char*) frame.data)[i] == tm[match_length]) {
                            match_length++;
                            if (match_length == 4) {
                                extra->stdout_state = 1;
                                headers_read = i + 1;
                                buffer_push(&extra->headers, frame.data, i);
                                break;
                            }
                        } else match_length = 0;
                    }
                    if (extra->stdout_state == 0) { // state unchanged
                        headers_read = frame.len;
                        buffer_push(&extra->headers, frame.data, frame.len);
                    }
                }

                if (extra->stdout_state == 1) {
                    extra->stdout_state = 2;
                    char* headers = pmalloc(extra->rs->pool, extra->headers.size + 1);
                    headers[extra->headers.size] = 0;
                    buffer_pop(&extra->headers, extra->headers.size, (uint8_t*) headers);
                    struct headers* hdrs = header_parse(headers, extra->rs->pool);
                    ITER_LLIST(hdrs->header_list, value) {
                        struct header_entry* entry = value;
                        if (str_eq(entry->name, "Content-Type")) {
                            extra->rs->response->body->content_type = entry->value;
                        } else if (str_eq(entry->name, "Status")) {
                            extra->rs->response->code = entry->value;
                        } else if (str_eq(entry->name, "ETag")) {
                            // we handle ETags, ignore FCGI-given ones
                        } else header_add(extra->rs->response->headers, entry->name, entry->value);
                        ITER_LLIST_END();
                    }
                }
            }

            if (headers_read <= frame.len) {
                if (extra->stdout_state == 2) {
                    updateContentHeaders(extra->rs);
                    extra->rs->response->body->data.stream.delay_finish(extra->rs, &extra->rs->response->body->data.stream.delayed_start);
                    extra->stdout_state = 3;
                }

                void* offset_data = frame.data + headers_read;
                size_t len = frame.len - headers_read;
                buffer_push(extra->output, offset_data, len);
                output_ready = 1;
            }
        }
    }


    if (output_ready && extra->provision->data.stream.notify(extra->rs)) {
        return 1;
    }

    extra->complete = 1;

    while (!extra->provision->data.stream.notify(extra->rs)) { }

    return 1;
}

ssize_t fcgi_provision_read(struct provision* provision, struct provision_data* buffer) {
    struct fcgi_stream_data* extra = provision->extra;
    if (extra->complete) {
        return 0;
    } else if (extra->output->size == 0) {
        return -2;
    }
    buffer->size = extra->output->size;
    buffer->data = pmalloc(provision->pool, buffer->size);
    return buffer->size = buffer_pop(extra->output, buffer->size, buffer->data);
}

void fcgi_on_closed(struct sub_conn* sub_conn) {
    struct fcgi_stream_data* extra = sub_conn->extra;
    extra->complete = 1;
    pfree(sub_conn->pool);
}

void safe_close_fcgi(struct sub_conn* sub_conn) {
    sub_conn->safe_close = 1;
}

struct provision* fcgi_provide_data(struct provider* provider, struct request_session* rs) {
    char* request_path = str_dup(rs->request->path, 0, rs->pool);
    {
        char* hashtag = strchr(request_path, '#');
        if (hashtag != NULL) hashtag[0] = 0;
    }
    char* get_parameters = strchr(request_path, '?');
    if (get_parameters != NULL) {
        get_parameters[0] = 0;
        get_parameters++;
    } else {
        get_parameters = "";
    }

    char port_str[16];
    if (rs->conn->addr.tcp6.sin6_family == AF_INET) {
        snprintf(port_str, 16, "%i", ntohs(rs->conn->addr.tcp4.sin_port));
    } else if (rs->conn->addr.tcp6.sin6_family == AF_INET6) {
        snprintf(port_str, 16, "%i", ntohs(rs->conn->addr.tcp6.sin6_port));
    } else {
        port_str[0] = '0';
        port_str[1] = 0;
    }
    char sport_str[16];
    struct server_binding* incoming_binding = rs->conn->incoming_binding;
    if (incoming_binding->binding_type == BINDING_TCP4) {
        snprintf(sport_str, 16, "%i", htons(incoming_binding->binding.tcp4.sin_port));
    } else if (incoming_binding->binding_type == BINDING_TCP6) {
        snprintf(sport_str, 16, "%i", htons(incoming_binding->binding.tcp6.sin6_port));
    } else if (incoming_binding->binding_type == BINDING_UNIX) {
        snprintf(sport_str, 16, "UNIX");
    } else {
        snprintf(sport_str, 16, "UNKNOWN");
    }

    struct fcgi_config* fcgi_config = provider->extra;
    int fcgi_fd = fcgi_request_connection(rs, fcgi_config);
    if (fcgi_fd < 0) {
        errlog(rs->conn->server->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
        return NULL;
    }
    struct mempool* provision_pool = mempool_new();
    struct mempool* sub_pool = mempool_new();
    phook(rs->pool, (void (*)(void*)) safe_close_fcgi, sub_pool);
    pchild(rs->src_conn->conn->pool, sub_pool);
    struct sub_conn* sub_conn = pcalloc(sub_pool, sizeof(struct sub_conn));
    sub_conn->conn = rs->conn;
    sub_conn->pool = sub_pool;
    phook(sub_conn->pool, close_hook, (void*) fcgi_fd);
    buffer_init(&sub_conn->read_buffer, sub_conn->pool);
    buffer_init(&sub_conn->write_buffer, sub_conn->pool);
    sub_conn->fd = fcgi_fd;
    struct fcgi_stream_data* stream_data = pcalloc(sub_conn->pool, sizeof(struct fcgi_stream_data));
    buffer_init(&stream_data->headers, sub_conn->pool);
    stream_data->output = pcalloc(sub_conn->pool, sizeof(struct buffer));
    buffer_init(stream_data->output, sub_conn->pool);
    stream_data->rs = rs;
    sub_conn->extra = stream_data;
    sub_conn->read = fcgi_read;
    sub_conn->on_closed = fcgi_on_closed;
    llist_append(rs->conn->manager->pending_sub_conns, sub_conn);

    struct fcgi_frame frame;
    frame.type = FCGI_BEGIN_REQUEST;
    stream_data->request_id = frame.request_id = (uint16_t) (fcgi_config->req_id_counter++ & 0xFFFF);
    if (fcgi_config->req_id_counter > 65535) fcgi_config->req_id_counter = 0;
    frame.len = 8;
    uint8_t* begin_packet = pcalloc(sub_conn->pool, 8);
    // 0 -> 7 are 0 intentionally
    begin_packet[1] = 1;
    begin_packet[2] = 1;
    frame.data = begin_packet;
    fcgi_writeFrame(&sub_conn->write_buffer, &frame);

    //TODO: SERVER_ADDR?

    struct hashmap* fcgi_params = hashmap_new(16, rs->pool);
    hashmap_put(fcgi_params, "REQUEST_URI", rs->request->path);
    hashmap_put(fcgi_params, "CONTENT_LENGTH", "0");
    if (rs->request->body != NULL && rs->request->body->content_type != NULL) {
        hashmap_put(fcgi_params, "CONTENT_TYPE", rs->request->body->content_type);
    }
    hashmap_put(fcgi_params, "GATEWAY_INTERFACE", "CGI/1.1");
    hashmap_put(fcgi_params, "PATH", getenv("PATH"));
    hashmap_put(fcgi_params, "QUERY_STRING", get_parameters);
    hashmap_put(fcgi_params, "REQUEST_URI", rs->request->path);
    {
        char tip[48];
        char* mip = tip;
        if (rs->conn->addr.tcp6.sin6_family == AF_INET) {
            inet_ntop(AF_INET, &rs->conn->addr.tcp4.sin_addr, tip, 48);
        } else if (rs->conn->addr.tcp6.sin6_family == AF_INET6) {
            if (memseq((unsigned char*) &rs->conn->addr.tcp6.sin6_addr, 10, 0) &&
                memseq((unsigned char*) &rs->conn->addr.tcp6.sin6_addr + 10, 2, 0xff)) {
                inet_ntop(AF_INET, ((unsigned char*) &rs->conn->addr.tcp6.sin6_addr) + 12, tip, 48);
            } else inet_ntop(AF_INET6, &rs->conn->addr.tcp6.sin6_addr, tip, 48);
        } else if (rs->conn->addr.tcp6.sin6_family == AF_LOCAL) {
            mip = "UNIX";
        } else {
            mip = "UNKNOWN";
        }
        if (mip == NULL) mip = "INVALID";
        hashmap_put(fcgi_params, "REMOTE_ADDR", mip);
        hashmap_put(fcgi_params, "REMOTE_HOST", mip);
    }
    hashmap_put(fcgi_params, "REMOTE_PORT", port_str);
    struct vhost_htdocs* htdocs = rs->vhost->sub->extra;
    size_t htdocs_length = strlen(htdocs->htdocs);

    if (rs->request_extra_path != NULL) {
        hashmap_put(fcgi_params, "PATH_INFO", rs->request_extra_path);
        size_t epl = strlen(rs->request_extra_path);
        char* path_translated = pmalloc(rs->pool, htdocs_length + epl);
        memcpy(path_translated, htdocs->htdocs, htdocs_length);
        memcpy(path_translated + htdocs_length, rs->request_extra_path + 1, epl);
        path_translated[htdocs_length + epl - 1] = 0;
        hashmap_put(fcgi_params, "PATH_TRANSLATED", path_translated);
    } else {
        hashmap_put(fcgi_params, "PATH_INFO", "");
        hashmap_put(fcgi_params, "PATH_TRANSLATED", "");
    }
    hashmap_put(fcgi_params, "REQUEST_METHOD", rs->request->method);
    char rss[4];
    rss[3] = 0;
    memcpy(rss, rs->response->code, 3);
    hashmap_put(fcgi_params, "REDIRECT_STATUS", rss);
    int htdocs_ends_slash = htdocs->htdocs[htdocs_length - 1] == '/';
    size_t rtpl = strlen(rs->request_htpath);
    if (rtpl < htdocs_length)
        errlog(rs->conn->server->logsess,
               "Setting FCGI SCRIPT_NAME requires the file to be in htdocs! @ %s", rs->request_htpath);
    else {
        hashmap_put(fcgi_params, "SCRIPT_NAME", rs->request_htpath + htdocs_length + (htdocs_ends_slash ? -1 : 0));
    }
    const char* host = header_get(rs->request->headers, "Host");
    if (host != NULL) {
        hashmap_put(fcgi_params, "SERVER_NAME", (void*) host);
    }
    hashmap_put(fcgi_params, "SERVER_PORT", sport_str);
    hashmap_put(fcgi_params, "SERVER_PROTOCOL", rs->request->http_version);
    hashmap_put(fcgi_params, "SERVER_SOFTWARE", "Avuna/" VERSION);
    hashmap_put(fcgi_params, "DOCUMENT_ROOT", htdocs->htdocs);
    hashmap_put(fcgi_params, "SCRIPT_FILENAME", rs->request_htpath);

    ITER_LLIST(rs->request->headers->header_list, pre_entry) {
        struct header_entry* entry = pre_entry;
        if (str_eq(entry->name, "Accept-Encoding")) continue;
        size_t name_length = strlen(entry->name);
        char* nname = pmalloc(rs->pool, name_length + 6);
        memcpy(nname, "HTTP_", 5);
        memcpy(nname + 5, entry->name, name_length + 1);
        name_length += 5;
        for (int x = 5; x < name_length; x++) {
            if (nname[x] >= 'a' && nname[x] <= 'z') nname[x] -= ' ';
            else if (nname[x] == '-') nname[x] = '_';
        }
        hashmap_put(fcgi_params, nname, (void*) entry->value);
        ITER_LLIST_END();
    }
    ITER_MAP(fcgi_params) {
        fcgi_writeParam(&sub_conn->write_buffer, frame.request_id, str_key, (char*) value);
        ITER_MAP_END();
    }

    frame.type = FCGI_PARAMS;
    frame.len = 0;
    frame.data = NULL;
    fcgi_writeFrame(&sub_conn->write_buffer, &frame);
    frame.type = FCGI_STDIN;

    if (rs->request->body != NULL) {
        if (rs->request->body->type == PROVISION_DATA) {
            size_t cr = 0;
            size_t left = rs->request->body->data.data.size;
            while (left > 0) {
                frame.len = (uint16_t) (left > 0xFFFF ? 0xFFFF : (uint16_t) left);
                frame.data = rs->request->body->data.data.data + cr;
                cr += frame.len;
                left -= frame.len;
                // pxfer should handle the invalid pointers correctly in writeFrame
                fcgi_writeFrame(&sub_conn->read_buffer, &frame);
            }
        } else {
            // TODO: implement once we have streaming post bodies implemented
        }
    }

    frame.len = 0;
    fcgi_writeFrame(&sub_conn->write_buffer, &frame);
    trigger_write(sub_conn);
    if (rs->response->body != NULL) {
        rs->response->body = NULL;
    }

    pchild(rs->pool, provision_pool);
    struct provision* provision = pcalloc(provision_pool, sizeof(struct provision));
    stream_data->provision = provision;
    provision->pool = provision_pool;
    provision->type = PROVISION_STREAM;
    provision->content_type = "application/octet-stream_id";
    provision->extra = stream_data;
    provision->data.stream.read = fcgi_provision_read;
    provision->data.stream.notify = rs->src_conn->notifier;
    provision->data.stream.stream_fd = -1;
    provision->requested_vhost_action = VHOST_ACTION_NO_CONTENT_UPDATE;
    provision->data.stream.delay_header_output = 1;
    provision->data.stream.known_length = -1;
    return provision;

}

void initialize(struct module* module) {
    struct provider* provider = pcalloc(module->pool, sizeof(struct provider));
    provider->load_config = fcgi_load_config;
    provider->provide_data = fcgi_provide_data;
    hashmap_put(available_provider_types, "fcgi", provider);
}