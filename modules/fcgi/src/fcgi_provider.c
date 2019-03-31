//
// Created by p on 3/30/19.
//

#include "fcgi.h"
#include <avuna/provider.h>
#include <avuna/config.h>
#include <avuna/http.h>
#include <avuna/module.h>
#include <avuna/pmem.h>
#include <avuna/string.h>
#include <avuna/globals.h>
#include <avuna/util.h>
#include <avuna/version.h>
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

void fcgi_load_config(struct provider* provider, struct config_node* node) {
    struct fcgi_config* fcgi = provider->extra = pcalloc(provider->pool, sizeof(struct fcgi_config));
    const char* mode = getConfigValue(node, "mode");
    if (str_eq(mode, "tcp")) {
        fcgi->addrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in* ina = pmalloc(provider->pool, sizeof(struct sockaddr_in));
        fcgi->addr = (struct sockaddr*) ina;
        ina->sin_family = AF_INET;
        const char* ip = getConfigValue(node, "ip");
        const char* port = getConfigValue(node, "port");
        if (ip == NULL || !inet_aton(ip, &ina->sin_addr)) {
            errlog(delog, "Invalid IP for FCGI node %s", node->name);
            return;
        }
        if (port == NULL || !str_isunum(port)) {
            errlog(delog, "Invalid Port for FCGI node %s", node->name);
            return;
        }
        ina->sin_port = htons((uint16_t) strtoul(port, NULL, 10));
    } else if (str_eq(mode, "unix")) {
        fcgi->addrlen = sizeof(struct sockaddr_un);
        struct sockaddr_un* ina = pmalloc(provider->pool, sizeof(struct sockaddr_un));
        fcgi->addr = (struct sockaddr*) ina;
        ina->sun_family = AF_LOCAL;
        const char* file = getConfigValue(node, "file");
        if (file == NULL || strlen(file) >= 107) {
            errlog(delog, "Invalid Unix Socket for FCGI node %s", node->name);
            return;
        }
        memcpy(ina->sun_path, file, strlen(file) + 1);
    } else {
        errlog(delog, "Invalid mode for FCGI node %s", node->name);
        return;
    }
    /*
     * TODO: no longer this function's duty, move to caller
    const char* mimes = getConfigValue(node, "mime-types");
    if (mimes != NULL) {
        char* mimes_split = pclaim(provider->pool, str_dup(mimes, 0, provider->pool));
        mimes_split = str_trim(mimes_split);
        struct list* mime_list = list_new(8, provider->pool);
        str_split(mimes_split, ",", mime_list);
        for (size_t i = 0; i < mime_list->count; ++i) {
            mime_list->data[i] = str_trim(mime_list->data[i]);
            hashmap_put(available_provider_types, mime_list->data[i], provider);
        }
    }*/
}


int fcgi_request_connection(struct fcgi_config* fcgi) {
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

struct provision* fcgi_provide_data(struct provider* provider, struct request_session* rs) {
    int attempt_count = 0;
    int fcgi_fd;
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

    goto start_fcgi;
    restart_fcgi:;
    if (fcgi_fd >= 0) {
        close(fcgi_fd);
    }
    attempt_count++;
    errlog(rs->conn->server->logsess,
           "Failed to read/write to FCGI Server! File: %s Error: %s, restarting connection!", rs->request_htpath,
           strerror(errno));
    start_fcgi:;
    if (attempt_count >= 2) {
        errlog(rs->conn->server->logsess, "Too many FCGI connection attempts, aborting.");
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
        return NULL;
    }
    struct fcgi_config* fcgi_config = provider->extra;
    fcgi_fd = fcgi_request_connection(fcgi_config);
    if (fcgi_fd < 0) {
        errlog(rs->conn->server->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
        return NULL;
    }

    struct fcgiframe ff;
    ff.type = FCGI_BEGIN_REQUEST;
    ff.reqID = fcgi_config->req_id_counter++ % 65535;
    if (fcgi_config->req_id_counter > 65535) fcgi_config->req_id_counter = 0;
    ff.len = 8;
    unsigned char pkt[8];
    pkt[0] = 0;
    pkt[1] = 1;
    pkt[2] = 1;
    memset(pkt + 3, 0, 5);
    ff.data = pkt;
    if (writeFCGIFrame(fcgi_fd, &ff)) goto restart_fcgi;
    //TODO: SERVER_ADDR
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

    for (int i = 0; i < rs->request->headers->count; i++) {
        const char* name = rs->request->headers->names[i];
        if (str_eq(name, "Accept-Encoding")) continue;
        const char* value = rs->request->headers->values[i];
        size_t name_length = strlen(name);
        char* nname = pmalloc(rs->pool, name_length + 6);
        memcpy(nname, "HTTP_", 5);
        memcpy(nname + 5, name, name_length + 1);
        name_length += 5;
        for (int x = 5; x < name_length; x++) {
            if (nname[x] >= 'a' && nname[x] <= 'z') nname[x] -= ' ';
            else if (nname[x] == '-') nname[x] = '_';
        }
        hashmap_put(fcgi_params, nname, value);
    }
    ITER_MAP(fcgi_params) {
        writeFCGIParam(fcgi_fd, ff.reqID, str_key, (char*) value);
        ITER_MAP_END();
    }

    ff.type = FCGI_PARAMS;
    ff.len = 0;
    ff.data = NULL;
    writeFCGIFrame(fcgi_fd, &ff);
    ff.type = FCGI_STDIN;
    // ended here: we need to asynchronize networking!
    if (rs->request->body != NULL && rs->request->body->len > 0) {
        size_t cr = 0;
        size_t left = rs->request->body->len;
        while (left > 0) {
            ff.len = left > 0xFFFF ? 0xFFFF : (uint16_t) left;
            ff.data = rs->request->body->data + cr;
            cr += ff.len;
            left -= ff.len;
            writeFCGIFrame(fcgi_fd, &ff);
        }
    }
    ff.len = 0;
    writeFCGIFrame(fcgi_fd, &ff);
    if (rs->response->body != NULL) {
        rs->response->body = NULL;
    }

    char* ct = NULL;
    int hd = 0;
    char* hdd = NULL;
    size_t hddl = 0;
    int eid = ff.reqID;

    while (ff.type != FCGI_END_REQUEST) {
        if (readFCGIFrame(fcgi_fd, &ff, rs->pool)) {
            errlog(rs->worker->server->logsess, "Error reading from FCGI server: %s", strerror(errno));
            goto restart_fcgi;
        }
        if (ff.reqID != eid) {
            //printf("unx name %i wanted: %i\n", ff.reqID, eid);
            if (ff.type == FCGI_END_REQUEST) {
                ff.type = FCGI_STDERR;
                //printf("rewr\n");
            }
            continue;
        }
        //printf("recv %i\n", ff.type);
        if (ff.type == FCGI_END_REQUEST) {
            //printf("er!\n");
            continue;
        }
        if (ff.type == FCGI_STDERR) {
            errlog(rs->worker->server->logsess, "FCGI STDERR <%s>: %s", htpath, ff.data);
        }
        if (ff.type == FCGI_STDOUT || ff.type == FCGI_STDERR) {
            int hr = 0;
            if (!hd && ff.type == FCGI_STDOUT) {
                int ml = 0;
                char* tm = "\r\n\r\n";
                for (int i = 0; i < ff.len; i++) {
                    if (((char*) ff.data)[i] == tm[ml]) {
                        ml++;
                        if (ml == 4) {
                            hd = 1;
                            hr = i + 1;
                            if (hdd == NULL) {
                                hdd = pmalloc(rs->pool, i + 1);
                                hdd[i] = 0;
                                memcpy(hdd, ff.data, i);
                                hddl = i;
                            } else {
                                hdd = prealloc(rs->pool, hdd, hddl + i + 1);
                                hdd[hddl + i] = 0;
                                memcpy(hdd + hddl, ff.data, i);
                                hddl += i;
                            }
                            break;
                        }
                    } else ml = 0;
                }
                if (!hd) {
                    hr = ff.len;
                    if (hdd == NULL) {
                        hdd = pmalloc(rs->pool, ff.len);
                        hdd[ff.len] = 0;
                        memcpy(hdd, ff.data, ff.len);
                        hddl = ff.len;
                    } else {
                        hdd = prealloc(rs->pool, hdd, hddl + ff.len);
                        hdd[hddl + ff.len] = 0;
                        memcpy(hdd + hddl, ff.data, ff.len);
                        hddl += ff.len;
                    }
                }
            }

            if (hd == 1 && ff.type == FCGI_STDOUT) {
                hd = 2;
                struct headers* hdrs = pcalloc(rs->pool, sizeof(struct headers));
                hdrs->pool = rs->pool;
                header_parse(hdrs, hdd, 0, rs->pool);
                for (int i = 0; i < hdrs->count; i++) {
                    const char* name = hdrs->names[i];
                    const char* value = hdrs->values[i];
                    if (str_eq(name, "Content-Type")) {
                        ct = value;
                    } else if (str_eq(name, "Status")) {
                        if (!rs->response->parsed) {
                            rs->response->parsed = 2;
                        }
                        rs->response->code = value;
                    } else if (str_eq(name, "ETag")) {
                        // we handle ETags, ignore FCGI-given ones
                    } else header_add(rs->response->headers, name, value);
                }
            }

            if (hr <= ff.len) {
                unsigned char* ffd = ff.data + hr;
                ff.len -= hr;
                if (rs->response->body == NULL) {
                    rs->response->body = pmalloc(rs->pool, sizeof(struct body));
                    rs->response->body->data = pmalloc(rs->pool, ff.len);
                    memcpy(rs->response->body->data, ffd, ff.len);
                    rs->response->body->len = ff.len;
                    rs->response->body->mime_type = ct == NULL ? "text/html" : ct;
                    rs->response->body->stream_fd = -1;
                    rs->response->body->stream_type = STREAM_TYPE_INVALID;
                } else {
                    rs->response->body->len += ff.len;
                    rs->response->body->data = prealloc(rs->pool, rs->response->body->data,
                                                        rs->response->body->len);
                    memcpy(rs->response->body->data + rs->response->body->len - ff.len, ffd, ff.len);
                }
            }
        }
    }

    close(fcgi_fd);
}

void initialize(struct module* module) {
    struct provider* provider = pcalloc(module->pool, sizeof(struct provider));
    provider->load_config = fcgi_load_config;
    provider->provide_data = fcgi_provide_data;
    hashmap_put(available_provider_types, "fcgi", provider);
}