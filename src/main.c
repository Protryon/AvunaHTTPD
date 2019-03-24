/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include <unistd.h>
#include <stdio.h>
#include "config.h"
#include <errno.h>
#include "xstring.h"
#include "version.h"
#include "util.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "streams.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "accept.h"
#include "globals.h"
#include "list.h"
#include "work.h"
#include <sys/types.h>
#include "mime.h"
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include "tls.h"
#include "http.h"
#include "vhost.h"
#include "smem.h"
#include <sys/resource.h>
#include "server.h"
#include "pmem_hooks.h"
#include "wake_thread.h"

int load_vhost_htdocs(struct config_node* config_node, struct vhost* vhost) {
    struct vhost_htdocs* htdocs = &vhost->sub.htdocs;
    htdocs->index = list_new(8, vhost->pool);
    htdocs->error_pages = hashmap_new(8, vhost->pool);
    htdocs->enableGzip = 1;
    htdocs->cache_types = list_new(8, vhost->pool);
    htdocs->fcgis = hashmap_new(8, vhost->pool);
    htdocs->maxAge = 604800;
    htdocs->htdocs = getConfigValue(config_node, "htdocs");
    if (htdocs->htdocs == NULL) {
        errlog(delog, "No htdocs at vhost: %s, assuming '/var/www/html'.", config_node->name);
        htdocs->htdocs = "/var/www/html/";
    }
    recur_mkdir(htdocs->htdocs, 0750);
    htdocs->htdocs = realpath(htdocs->htdocs, NULL);
    if (htdocs->htdocs == NULL) {
        errlog(delog, "No htdocs at vhost %s, or does not exist and cannot be created.", config_node->name);
        return 1;
    }
    size_t htdocs_length = strlen(htdocs->htdocs);
    if (htdocs->htdocs[htdocs_length - 1] != '/') {
        htdocs->htdocs = str_dup(htdocs->htdocs, ++htdocs_length + 1, vhost->pool);
        htdocs->htdocs[htdocs_length - 1] = '/';
        htdocs->htdocs[htdocs_length] = 0;
    }
    const char* temp = getConfigValue(config_node, "nohardlinks");
    htdocs->nohardlinks = temp == NULL ? 1 : str_eq(temp, "true");
    if (temp == NULL) {
        errlog(delog, "No nohardlinks at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "symlock");
    htdocs->symlock = temp == NULL ? 1 : str_eq(temp, "true");
    if (temp == NULL) {
        errlog(delog, "No symlock at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "scache");
    htdocs->scacheEnabled = temp == NULL ? 1 : str_eq(temp, "true");
    if (temp == NULL) {
        errlog(delog, "No scache at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "cache-maxage");
    if (temp == NULL || !str_isunum(temp)) {
        errlog(delog, "No cache-maxage at vhost: %s, assuming '604800'", config_node->name);
        temp = "604800";
    }
    htdocs->maxAge = strtoul(temp, NULL, 10);
    temp = getConfigValue(config_node, "maxSCache");
    if (temp == NULL || !str_isunum(temp)) {
        errlog(delog, "No maxSCache at vhost: %s, assuming '0'", config_node->name);
        temp = "0";
    }
    htdocs->cache = cache_new(strtoul(temp, NULL, 10));
    pchild(vhost->pool, htdocs->cache->pool);
    temp = getConfigValue(config_node, "enable-gzip");
    htdocs->enableGzip = temp == NULL ? 1 : str_eq(temp, "true");
    if (temp == NULL) {
        errlog(delog, "No enable-gzip at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "index");
    if (temp == NULL) {
        errlog(delog, "No index at vhost: %s, assuming 'index.php, index.html, index.htm'", config_node->name);
        temp = "index.php, index.html, index.htm";
    }
    char* temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", htdocs->index);
    for (size_t i = 0; i < htdocs->index->count; ++i) {
        htdocs->index->data[i] = str_trim(htdocs->index->data[i]);
    }

    temp = getConfigValue(config_node, "cache-types");
    if (temp == NULL) {
        errlog(delog, "No cache-types at vhost: %s, assuming 'text/css,application/javascript,image/*'", config_node->name);
        temp = "text/css,application/javascript,image/*";
    }
    temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", htdocs->cache_types);
    for (size_t i = 0; i < htdocs->cache_types->count; ++i) {
        htdocs->cache_types->data[i] = str_trim(htdocs->cache_types->data[i]);
    }

    ITER_MAP(config_node->map) {
        if (str_prefixes(str_key, "error-")) {
            const char* en = str_key + 6;
            if (!str_isunum(en)) {
                errlog(delog, "Invalid error page specifier at vhost: %s", config_node->name);
                continue;
            }
            hashmap_putptr(htdocs->error_pages, (void*) strtoul(en, NULL, 10), value);
        }
    } ITER_MAP_END();

    temp = getConfigValue(config_node, "fcgis");
    if (temp != NULL) {
        temp2 = str_dup(temp, 0, vhost->pool);
        struct list* fcgi_names = list_new(8, vhost->pool);
        str_split(temp2, ",", fcgi_names);
        for (size_t i = 0; i < fcgi_names->count; ++i) {
            fcgi_names->data[i] = str_trim(fcgi_names->data[i]);
            struct config_node* fcgi_node = hashmap_get(cfg->nodesByName, fcgi_names->data[i]);
            if (fcgi_node == NULL || !str_eq_case(fcgi_node->category, "fcgi")) {
                errlog(delog, "Could not find FCGI entry %s at vhost: %s", temp2, config_node->name);
                continue;
            }
            const char* mode = getConfigValue(fcgi_node, "mode");
            struct fcgi* fcgi = pmalloc(vhost->pool, sizeof(struct fcgi));
            fcgi->mimes = NULL;
            fcgi->req_id_counter = 0;
            if (str_eq(mode, "tcp")) {
                fcgi->addrlen = sizeof(struct sockaddr_in);
                struct sockaddr_in* ina = pmalloc(vhost->pool, sizeof(struct sockaddr_in));
                fcgi->addr = (struct sockaddr *) ina;
                ina->sin_family = AF_INET;
                const char* ip = getConfigValue(fcgi_node, "ip");
                const char* port = getConfigValue(fcgi_node, "port");
                if (ip == NULL || !inet_aton(ip, &ina->sin_addr)) {
                    errlog(delog, "Invalid IP for FCGI node %s at vhost: %s", temp2, config_node->name);
                    continue;
                }
                if (port == NULL || !str_isunum(port)) {
                    errlog(delog, "Invalid Port for FCGI node %s at vhost: %s", temp2, config_node->name);
                    continue;
                }
                ina->sin_port = htons((uint16_t) strtoul(port, NULL, 10));
            } else if (str_eq(mode, "unix")) {
                fcgi->addrlen = sizeof(struct sockaddr_un);
                struct sockaddr_un* ina =pmalloc(vhost->pool, sizeof(struct sockaddr_un));
                fcgi->addr = ina;
                ina->sun_family = AF_LOCAL;
                const char* file = getConfigValue(fcgi_node, "file");
                if (file == NULL || strlen(file) >= 107) {
                    errlog(delog, "Invalid Unix Socket for FCGI node %s at vhost: %s", temp2, config_node->name);
                    continue;
                }
                memcpy(ina->sun_path, file, strlen(file) + 1);
            } else {
                errlog(delog, "Invalid mode for FCGI node %s at vhost: %s", temp2, config_node->name);
                continue;
            }
            const char* mimes = getConfigValue(fcgi_node, "mime-types");
            if (mimes != NULL) {
                char* mimes_split = pclaim(vhost->pool, str_dup(mimes, 0, vhost->pool));
                mimes_split = str_trim(mimes_split);
                fcgi->mimes = list_new(8, vhost->pool);
                str_split(mimes_split, ",", fcgi->mimes);
                for (size_t j = 0; j < fcgi->mimes->count; ++j) {
                    fcgi->mimes->data[i] = str_trim(fcgi->mimes->data[i]);
                    hashmap_put(htdocs->fcgis, fcgi->mimes->data[i], fcgi);
                }
            }
        }
    }
    return 0;
}

int load_vhost_rproxy(struct config_node* config_node, struct vhost* vhost) {
    struct vhost_rproxy* rproxy = &vhost->sub.rproxy;
    rproxy->enableGzip = 1;
    rproxy->cache_types = list_new(8, vhost->pool);
    rproxy->dynamic_types = hashset_new(8, vhost->pool);
    rproxy->maxAge = 604800;
    const char* forward_mode = getConfigValue(config_node, "forward-mode");
    if (str_eq(forward_mode, "tcp")) {
        rproxy->fwaddrlen = sizeof(struct sockaddr_in);
        struct sockaddr_in* ina = pmalloc(vhost->pool, sizeof(struct sockaddr_in));
        rproxy->fwaddr = ina;
        ina->sin_family = AF_INET;
        const char* forward_ip = getConfigValue(config_node, "forward-ip");
        const char* forward_port = getConfigValue(config_node, "forward-port");
        if (forward_ip == NULL || !inet_aton(forward_ip, &ina->sin_addr)) {
            errlog(delog, "Invalid IP for Reverse Proxy vhost: %s", config_node->name);
            return 1;
        }
        if (forward_port == NULL || !str_isunum(forward_port)) {
            errlog(delog, "Invalid Port for Reverse Proxy vhost: %s", config_node->name);
            return 1;
        }
        ina->sin_port = (uint16_t) strtoul(forward_port, NULL, 10);
    } else if (str_eq(forward_mode, "unix")) {
        rproxy->fwaddrlen = sizeof(struct sockaddr_un);
        struct sockaddr_un* ina = pmalloc(vhost->pool, sizeof(struct sockaddr_un));
        rproxy->fwaddr = ina;
        ina->sun_family = AF_LOCAL;
        const char* ffile = getConfigValue(config_node, "file");
        if (ffile == NULL || strlen(ffile) >= 107) {
            errlog(delog, "Invalid Unix Socket for Reverse Proxy vhost: %s", config_node->name);
            return 1;
        }
        memcpy(ina->sun_path, ffile, strlen(ffile) + 1);
    } else {
        errlog(delog, "Invalid mode for Reverse Proxy vhost: %s", config_node->name);
        return 1;
    }
    rproxy->headers = NULL;
    ITER_MAP(config_node->map) {
        if (str_prefixes(str_key, "header-")) {
            const char* en = str_key + 7;
            if (rproxy->headers == NULL) {
                rproxy->headers = pcalloc(vhost->pool, sizeof(struct headers));
                rproxy->headers->pool = vhost->pool;
            }
            header_add(rproxy->headers, en, value);
        }
    } ITER_MAP_END();

    const char* temp = getConfigValue(config_node, "cache-types");
    if (temp == NULL) {
        errlog(delog, "No cache-types at vhost: %s, assuming 'text/css,application/`javascript,image/*'", config_node->name);
        temp = "text/css,application/javascript,image/*";
    }
    char* temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", rproxy->cache_types);
    for (size_t i = 0; i < rproxy->cache_types->count; ++i) {
        rproxy->cache_types->data[i] = str_trim(rproxy->cache_types->data[i]);
    }

    temp = getConfigValue(config_node, "scache");
    rproxy->scacheEnabled = (uint8_t) (temp == NULL ? 1 : str_eq(temp, "true"));
    if (temp == NULL) {
        errlog(delog, "No scache at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "cache-maxage");
    if (temp == NULL || !str_isunum(temp)) {
        errlog(delog, "No cache-maxage at vhost: %s, assuming '604800'", config_node->name);
        temp = "604800";
    }
    rproxy->maxAge = strtoul(temp, NULL, 10);
    temp = getConfigValue(config_node, "maxSCache");
    if (temp == NULL || !str_isunum(temp)) {
        errlog(delog, "No maxSCache at vhost: %s, assuming '0'", config_node->name);
        temp = "0";
    }
    rproxy->cache = cache_new(strtoul(temp, NULL, 10));
    pchild(vhost->pool, rproxy->cache->pool);
    temp = getConfigValue(config_node, "enable-gzip");
    rproxy->enableGzip = (uint8_t) (temp == NULL ? 1 : str_eq(temp, "true"));
    if (temp == NULL) {
        errlog(delog, "No enable-gzip at vhost: %s, assuming 'true'", config_node->name);
    }
    temp = getConfigValue(config_node, "dynamic-types");
    if (temp == NULL) {
        errlog(delog, "No dynamic-types at vhost: %s, assuming 'application/x-php'", config_node->name);
        temp = "application/x-php";
    }
    temp2 = str_dup(temp, 0, vhost->pool);
    str_split_set(temp2, ",", rproxy->dynamic_types);
    return 0;
}

int load_vhost(struct config_node* config_node, struct vhost* vhost) {
    vhost->id = config_node->name;
    vhost->hosts = list_new(8, vhost->pool);
    const char* vht = getConfigValue(config_node, "type");
    if (str_eq_case(vht, "htdocs")) {
        vhost->type = VHOST_HTDOCS;
    } else if (str_eq_case(vht, "reverse-proxy")) {
        vhost->type = VHOST_RPROXY;
    } else if (str_eq_case(vht, "redirect")) {
        vhost->type = VHOST_REDIRECT;
    } else if (str_eq_case(vht, "mount")) {
        vhost->type = VHOST_MOUNT;
    } else {
        errlog(delog, "Invalid VHost Type: %s", vht);
        return 1;
    }
    char* host_value = str_dup(getConfigValue(config_node, "host"), 0, vhost->pool);
    str_split(host_value, ",", vhost->hosts);
    for (size_t i = 0; i < vhost->hosts->count; ++i) {
        vhost->hosts->data[i] = str_trim(vhost->hosts->data[i]);
    }
    const char* ssl_name = getConfigValue(config_node, "ssl");
    if (ssl_name != NULL) {
        struct config_node* ssl_node = hashmap_get(cfg->nodesByName, ssl_name);
        if (ssl_node == NULL || !str_eq_case(ssl_node->category, "ssl")) {
            errlog(delog, "Invalid SSL node! Node not found! '%s'", ssl_name);
            goto post_ssl;
        }
        const char* cert = getConfigValue(ssl_node, "publicKey");
        const char* key = getConfigValue(ssl_node, "privateKey");
        if (cert == NULL || key == NULL || access(cert, R_OK) || access(key, R_OK)) {
            errlog(delog, "Invalid SSL node! No publicKey/privateKey value or cannot be read!");
            goto post_ssl;
        }
        vhost->ssl_cert = loadCert(cert, key, vhost->pool);
        phook(vhost->pool, SSL_CTX_free, vhost->ssl_cert->ctx);
    } else {
        vhost->ssl_cert = NULL;
    }
    post_ssl:;

    if (vhost->type == VHOST_HTDOCS && load_vhost_htdocs(config_node, vhost)) {
        return 1;
    } else if (vhost->type == VHOST_RPROXY && load_vhost_rproxy(config_node, vhost)) {
        return 1;
    } else if (vhost->type == VHOST_REDIRECT) {
        struct vhost_redirect* redirect = &vhost->sub.redirect;
        redirect->redir = getConfigValue(config_node, "redirect");
        if (redirect->redir == NULL) {
            errlog(delog, "No redirect at vhost: %s", config_node->name);
            return 1;
        }
    } else if (vhost->type == VHOST_MOUNT) {
        struct vhost_mount* mount = &vhost->sub.mount;
        mount->mounts = list_new(8, vhost->pool);
        ITER_MAP(config_node->map) {
            if (str_prefixes_case(str_key, "/")) {
                struct mountpoint* point = pmalloc(vhost->pool, sizeof(struct mountpoint));
                point->path = str_key;
                point->vhost = value;
                list_add(mount->mounts, point);
            }
        } ITER_MAP_END();
        const char* keep_prefix = getConfigValue(config_node, "keep-prefix");
        if (keep_prefix == NULL) {
            errlog(delog, "No keep-prefix at vhost: %s, assuming 'false'", config_node->name);
            keep_prefix = "false";
        }
        mount->keep_prefix = str_eq(keep_prefix, "true");
    }
    return 0;
}

int load_binding(struct config_node* bind_node, struct server_binding* binding) {
    const char* bind_mode = getConfigValue(bind_node, "bind-mode");
    const char* bind_ip = NULL;
    uint16_t port = 0;
    const char* bind_file = NULL;
    int namespace;
    int bind_all = 0;
    int use_ipv6 = 0;
    if (str_eq_case(bind_mode, "tcp")) {
        binding->binding_type = BINDING_TCP4;
        bind_ip = getConfigValue(bind_node, "bind-ip");
        if (bind_ip == NULL || str_eq_case(bind_ip, "0.0.0.0")) {
            bind_all = 1;
        }
        use_ipv6 = bind_all || str_contains_case(bind_ip, ":");
        if (use_ipv6) {
            binding->binding_type = BINDING_TCP6;
        }
        const char* bind_port = getConfigValue(bind_node, "bind-port");
        if (bind_port != NULL && !str_isunum(bind_port)) {
            errlog(delog, "Invalid bind-port for binding: %s", bind_node->name);
            return 1;
        }
        port = (uint16_t) (bind_port == NULL ? 80 : strtoul(bind_port, NULL, 10));
        namespace = use_ipv6 ? PF_INET6 : PF_INET;
    } else if (str_eq_case(bind_mode, "unix")) {
        binding->binding_type = BINDING_UNIX;
        bind_file = getConfigValue(bind_node, "bind-file");
        namespace = PF_LOCAL;
    } else {
        errlog(delog, "Invalid bind-mode for binding: %s", bind_node->name);
        return 1;
    }

    const char* mcc = getConfigValue(bind_node, "max-conn");
    if (mcc != NULL && !str_isunum(mcc)) {
        errlog(delog, "Invalid max-conn for binding: %s", bind_node->name);
        return 1;
    }
    binding->conn_limit = (size_t) strtol(mcc, NULL, 10);

    int server_fd = socket(namespace, SOCK_STREAM, 0);
    if (server_fd < 0) {
        errlog(delog, "Error creating socket for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }
    phook(binding->pool, close_hook, (void*) server_fd);
    int one = 1;
    int zero = 0;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
        errlog(delog, "Error setting SO_REUSEADDR for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }
    sock: ;

    if (binding->binding_type == BINDING_TCP6) {
        if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void *) &zero, sizeof(zero)) == -1) {
            errlog(delog, "Error unsetting IPV6_V6ONLY for binding: %s, %s", bind_node->name, strerror(errno));
            return 1;
        }
        binding->binding.tcp6.sin6_flowinfo = 0;
        binding->binding.tcp6.sin6_scope_id = 0;
        binding->binding.tcp6.sin6_family = AF_INET6;
        if (bind_all) binding->binding.tcp6.sin6_addr = in6addr_any;
        else if (!inet_pton(AF_INET6, bind_ip, &(binding->binding.tcp6.sin6_addr))) {
            errlog(delog, "Error binding socket for binding: %s, invalid bind-ip", bind_node->name);
            return 1;
        }
        binding->binding.tcp6.sin6_port = htons(port);
        if (bind(server_fd, (struct sockaddr *) &binding->binding.tcp6, sizeof(binding->binding.tcp6))) {
            if (bind_all) {
                binding->binding_type = BINDING_TCP4;
                goto sock;
            }
            errlog(delog, "Error binding socket for binding: %s, %s", bind_node->name, strerror(errno));
            return 1;
        }
    } else if (binding->binding_type == BINDING_TCP4) {
        binding->binding.tcp4.sin_family = AF_INET;
        if (bind_all) binding->binding.tcp4.sin_addr.s_addr = INADDR_ANY;
        else if (!inet_aton(bind_ip, &(binding->binding.tcp4.sin_addr))) {
            errlog(delog, "Error binding socket for binding: %s, invalid bind-ip", bind_node->name);
            return 1;
        }
        binding->binding.tcp4.sin_port = htons(port);
        if (bind(server_fd, (struct sockaddr*) &binding->binding.tcp4, sizeof(binding->binding.tcp4))) {
            errlog(delog, "Error binding socket for binding: %s, %s", bind_node->name, strerror(errno));
            return 1;
        }
    } else if (namespace == PF_LOCAL) {
        strncpy(binding->binding.un.sun_path, bind_file, 108);
        if (bind(server_fd, (struct sockaddr*) &binding->binding.un, sizeof(binding->binding.un))) {
            errlog(delog, "Error binding socket for binding: %s, %s", bind_node->name, strerror(errno));
            return 1;
        }
    } else {
        errlog(delog, "Invalid family for binding: %s", bind_node->name);
        return 1;
    }
    if (listen(server_fd, 50)) {
        errlog(delog, "Error listening on socket for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }
    if (fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL) | O_NONBLOCK) < 0) {
        errlog(delog, "Error setting non-blocking for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }
    binding->fd = server_fd;

    binding->mode = 0;

    const char* protocol = getConfigValue(bind_node, "protocol");
    if (protocol == NULL || str_eq_case(protocol, "http/1.1")) {
        binding->mode |= BINDING_MODE_HTTP2_UPGRADABLE;
    } else if (str_eq_case(protocol, "http/2.0")) {
        binding->mode |= BINDING_MODE_HTTP2_ONLY;
    } else {
        errlog(delog, "Invalid protocol for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }

    const char* ssl_name = getConfigValue(bind_node, "ssl");
    if (ssl_name != NULL) {
        struct config_node* ssl_node = hashmap_get(cfg->nodesByName, ssl_name);
        if (ssl_node == NULL || !str_eq_case(ssl_node->category, "ssl")) {
            errlog(delog, "Invalid SSL node! Node not found! '%s'", ssl_name);
            goto post_ssl;
        }
        const char* cert = getConfigValue(ssl_node, "publicKey");
        const char* key = getConfigValue(ssl_node, "privateKey");
        if (cert == NULL || key == NULL || access(cert, R_OK) || access(key, R_OK)) {
            errlog(delog, "Invalid SSL node! No publicKey/privateKey value or cannot be read!");
            goto post_ssl;
        }
        binding->ssl_cert = loadCert(cert, key, binding->pool);
        phook(binding->pool, SSL_CTX_free, binding->ssl_cert->ctx);
        binding->mode |= BINDING_MODE_HTTPS;
    } else {
        binding->ssl_cert = NULL;
        binding->mode |= BINDING_MODE_PLAINTEXT;
    }
    post_ssl:;
    return 0;
}

int main(int argc, char* argv[]) {
	signal(SIGPIPE, SIG_IGN);
#ifndef DEBUG
    if (getuid() != 0 || getgid() != 0) {
		printf("Must run as root!\n");
		return 1;
	}
#endif
    global_pool = mempool_new();
    printf("Loading Avuna %s %s\n", DAEMON_NAME, VERSION);
#ifdef DEBUG
	printf("Running in Debug mode!\n");
#endif
	char cwd[256];
	if (argc == 1) {
		memcpy(cwd, "/etc/avuna/", 11);
		cwd[11] = 0;
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME) + 1, 0, global_pool);
		strcat(cwd, str_tolower(dn));
	} else {
		size_t l = strlen(argv[1]);
		if (argv[1][l - 1] == '/') argv[1][--l] = 0;
		memcpy(cwd, argv[1], l + 1);
	}
	recur_mkdir(cwd, 0750);
	chdir(cwd);
	if (strlen(cwd) > 240) {
		printf("Load Directory is more than 240 characters path length!\n");
		return 1;
	}
	strncat(cwd, "/main.cfg", 9);
	cfg = loadConfig(cwd);
	if (cfg == NULL) {
		printf("Error loading Config<%s>: %s\n", cwd, errno == EINVAL ? "File doesn't exist!" : strerror(errno));
		return 1;
	}
	struct config_node* dm = getUniqueByCat(cfg, "daemon");
	if (dm == NULL) {
		printf("[daemon] block does not exist in %s!\n", cwd);
		return 1;
	}
#ifndef DEBUG
    pid_t pid = 0;
	const char* pid_file = getConfigValue(dm, "pid-file");
	if (!access(pid_file, F_OK)) {
		int pidfd = open(pid_file, O_RDONLY);
		if (pidfd < 0) {
			printf("Failed to open PID file! %s\n", strerror(errno));
			return 1;
		}
		char pidr[16];
		if (readLine(pidfd, pidr, 16) >= 1) {
			pid = strtol(pidr, NULL, 10);
			int k = kill(pid, 0);
			if (k == 0) {
            }
		} else {
			printf("Failed to read PID file! %s\n", strerror(errno));
			return 1;
		}
		close(pidfd);
	}
	if (runn) {
		printf("Already running! PID = %i\n", pid);
		exit(0);
	} else {
		pid_t f = fork();
		if (f > 0) {
			printf("Daemonized! PID = %i\n", f);
			exit(0);
		} else {
			printf("Now running as daemon!\n");
			if (setsid() < 0) {
				printf("Failed to exit process tree: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "r", stdin) < 0) {
				printf("reopening of STDIN to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stderr) < 0) {
				printf("reopening of STDERR to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stdout) < 0) {
				printf("reopening of STDOUT to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
		}
	}
#else
	printf("Daemonized! PID = %i\n", getpid());
#endif
	delog = pmalloc(global_pool, sizeof(struct logsess));
	delog->pi = 0;
	delog->access_fd = NULL;
	const char* el = getConfigValue(dm, "error-log");
	delog->error_fd = el == NULL ? NULL : fopen(el, "a"); // fopen will return NULL on error, which works.
#ifndef DEBUG
	size_t pfpl = strlen(pid_file);
	char* pfp = xcopy(pid_file, pfpl + 1, 0, global_pool);
	for (ssize_t i = pfpl - 1; i--; i >= 0) {
		if (pfp[i] == '/') {
			pfp[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pfp, 0750) == -1) {
		errlog(delog, "Error making directories for PID file: %s.", strerror(errno));
		return 1;
	}
	FILE *pfd = fopen(pid_file, "w");
	if (pfd == NULL) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
#endif
	const char* rlt = getConfigValue(dm, "fd-limit");
	if(rlt == NULL) {
		errlog(delog, "No fd-limit in daemon config! Assuming 1024.");	
	}
	size_t fd_lim = rlt == NULL ? 1024 : strtoul(rlt, NULL, 10);
	struct rlimit rlx;
	rlx.rlim_cur = fd_lim;
	rlx.rlim_max = fd_lim;
	if(setrlimit(RLIMIT_NOFILE, &rlx) == -1) printf("Error setting resource limit: %s\n", strerror(errno));
	const char* mtf = getConfigValue(dm, "mime-types");
	if (mtf == NULL) {
		errlog(delog, "No mime-types in daemon config!");
		return 1;
	}
	if (access(mtf, R_OK) || loadMimes(mtf)) {
		errlog(delog, "Cannot read or mime-types file does not exist: %s", mtf);
		return 1;
	}
	(void) SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	OPENSSL_config (NULL);

	struct hashmap* binding_map = hashmap_new(16, global_pool);

    struct list* binding_list = hashmap_get(cfg->nodeListsByCat, "binding");
    for (int i = 0; i < binding_list->count; i++) {
        struct config_node* bind_node = binding_list->data[i];
        if (bind_node->name == NULL) {
            errlog(delog, "All bind nodes must have names, skipping node.");
            continue;
        }
        struct mempool* pool = mempool_new();
        struct server_binding* binding = pmalloc(pool, sizeof(struct server_binding));
        binding->pool = pool;

        if (load_binding(bind_node, binding)) {
            pfree(binding->pool);
        } else {
            hashmap_put(binding_map, bind_node->name, binding);
        }
    }

    struct hashmap* vhost_map = hashmap_new(16, global_pool);

    struct list* vhost_list = hashmap_get(cfg->nodeListsByCat, "vhost");
    for (int i = 0; i < vhost_list->count; i++) {
        struct config_node *vhost_node = vhost_list->data[i];
        if (vhost_node->name == NULL) {
            errlog(delog, "All vhost nodes must have names, skipping node.");
            continue;
        }

        struct mempool* pool = mempool_new();
        struct vhost* vhost = pmalloc(pool, sizeof(struct vhost));
        vhost->pool = pool;
        if(load_vhost(vhost_node, vhost)) {
            pfree(pool);
        } else {
            hashmap_put(vhost_map, vhost_node->name, vhost);
        }
    }

    struct list* server_list = hashmap_get(cfg->nodeListsByCat, "server");

	struct list* server_infos = list_new(8, global_pool);

	for (size_t i = 0; i < server_list->count; i++) {
		struct config_node* serv = server_list->data[i];
        if (serv->name == NULL) {
            errlog(delog, "All server nodes must have names, skipping node.");
            continue;
        }
        struct mempool* pool = mempool_new();
        struct server_info* info = pmalloc(pool, sizeof(struct server_info));
        info->id = serv->name;
        info->pool = pool;
        info->bindings = list_new(8, info->pool);
        info->vhosts = list_new(16, info->pool);
        info->prepared_connections = queue_new(0, 1, info->pool);
        list_add(server_infos, info);
        const char* bindings = getConfigValue(serv, "bindings");
        struct list* binding_names = list_new(8, info->pool);
        char bindings_dup[strlen(bindings) + 1];
        strcpy(bindings_dup, bindings);
        str_split(bindings_dup, ",", binding_names);

        for (size_t j = 0; j < binding_names->count; ++j) {
            char* name_trimmed = str_trim(binding_names->data[j]);
            struct server_binding* data = hashmap_get(binding_map, name_trimmed);
            if (data == NULL) {
                errlog(delog, "Invalid binding name for server: %s, %s", serv->name, name_trimmed);
                continue;
            }
            list_add(info->bindings, data);
        }

        const char* vhosts = getConfigValue(serv, "vhosts");
        struct list* vhost_names = list_new(8, info->pool);
        char vhosts_dup[strlen(vhosts) + 1];
        strcpy(vhosts_dup, vhosts);
        str_split(vhosts_dup, ",", vhost_names);

        for (size_t j = 0; j < vhost_names->count; ++j) {
            char* name_trimmed = str_trim(vhost_names->data[j]);
            struct vhost* data = hashmap_get(vhost_map, name_trimmed);
            if (data == NULL) {
                errlog(delog, "Invalid vhost name for server: %s, %s", serv->name, name_trimmed);
                continue;
            }
            list_add(info->vhosts, data);
        }

        const char* tcc = getConfigValue(serv, "threads");
		if (!str_isunum(tcc)) {
			errlog(delog, "Invalid threads for server: %s", serv->name);
			continue;
		}
		ssize_t tc = strtoul(tcc, NULL, 10);
		if (tc < 1 || tc > 128) {
			errlog(delog, "Invalid threads for server: %s, must be greater than 1 and less than 128.\n", serv->name);
			continue;
		}
		info->max_worker_count = (uint16_t) tc;
        char* maxPostStr = getConfigValue(serv, "max-post");
        if (maxPostStr == NULL || !str_isunum(maxPostStr)) {
            errlog(delog, "No max-post at server: %s, assuming '0'", serv->name);
            maxPostStr = "0";
        }
        info->max_post = strtoul(maxPostStr, NULL, 10);

		struct logsess* slog = pmalloc(info->pool, sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = getConfigValue(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
		const char* lel = getConfigValue(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
		acclog(slog, "Server %s listening for connections!", serv->name);
		info->logsess = slog;
	}

	const char* uids = getConfigValue(dm, "uid");
	const char* gids = getConfigValue(dm, "gid");
	uid_t uid = uids == NULL ? 0 : strtoul(uids, NULL, 10);
	uid_t gid = gids == NULL ? 0 : strtoul(gids, NULL, 10);
	if (gid > 0 && setgid(gid) != 0) {
	    errlog(delog, "Failed to setgid! %s", strerror(errno));
	}
	if (uid > 0 && setuid(uid) != 0) {
	    errlog(delog, "Failed to setuid! %s", strerror(errno));
	}
	acclog(delog, "Running as UID = %u, GID = %u, starting workers.", getuid(), getgid());
	for (size_t i = 0; i < server_infos->count; ++i) {
	    struct server_info* server = server_infos->data[i];
        for (size_t j = 0; j < server->bindings->count; ++j) {
            struct accept_param *param = pmalloc(server->pool, sizeof(struct accept_param));
            param->server = server;
            param->binding = server->bindings->data[j];
            pthread_t pt;
            int pthread_err = pthread_create(&pt, NULL, (void *) run_accept, param);
            if (pthread_err != 0) {
                errlog(delog, "Error creating accept thread: pthread errno = %i.", pthread_err);
                continue;
            }
        }

        struct list* works = list_new(server->max_worker_count, server->pool);

        for (size_t j = 0; j< server->max_worker_count; ++j) {
            struct work_param* param = pmalloc(server->pool, sizeof(struct work_param));
            param->i = j;
            param->server = server;
            param->pipes[0] = -1;
            param->pipes[1] = -1;
            pthread_t pt;
            int pthread_err = pthread_create(&pt, NULL, (void *) run_work, param);
            if (pthread_err != 0) {
                errlog(delog, "Error creating work thread: pthread errno = %i.", pthread_err);
                continue;
            }
            list_add(works, param);
        }

        struct wake_thread_arg* wt_arg = pmalloc(server->pool, sizeof(struct wake_thread_arg));
        wt_arg->work_params = works;
        wt_arg->server = server;

        pthread_t pt;
        int pthread_err = pthread_create(&pt, NULL, (void *) wake_thread, wt_arg);
        if (pthread_err != 0) {
            errlog(delog, "Error creating work thread: pthread errno = %i.", pthread_err);
            continue;
        }

    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
	while (1)
		sleep(1);
#pragma clang diagnostic pop
	return 0;
}
