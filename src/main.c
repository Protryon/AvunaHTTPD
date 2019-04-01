/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include "accept.h"
#include "network.h"
#include "wake_thread.h"
#include <avuna/config.h>
#include <avuna/string.h>
#include <avuna/version.h>
#include <avuna/util.h>
#include <avuna/globals.h>
#include <avuna/mime.h>
#include <avuna/tls.h>
#include <avuna/vhost.h>
#include <avuna/pmem_hooks.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <sys/resource.h>
#include <dlfcn.h>
#include <dirent.h>
#include <avuna/module.h>

int load_vhost(struct config_node* config_node, struct vhost* vhost) {
    vhost->id = config_node->name;
    vhost->hosts = list_new(8, vhost->pool);
    const char* type = config_get(config_node, "type");
    if (type == NULL) {
        errlog(delog, "No vhost type found for vhost: %s", vhost->id);
    }
    vhost->sub = hashmap_get(registered_vhost_types, (char*) type);
    if (vhost->sub == NULL) {
        errlog(delog, "Invalid vhost type '%s' for vhost: %s", type, vhost->id);
        return 1;
    }
    // prevent sharing of extra field across instances
    vhost->sub = xcopy(vhost->sub, sizeof(struct vhost_type), 0, vhost->pool);

    char* raw_host = (char*) config_get(config_node, "host");
    if (raw_host == NULL) {
        errlog(delog, "No vhost host found for vhost: %s", vhost->id);
        return 1;
    }
    char* host_value = str_dup(raw_host, 0, vhost->pool);
    str_split(host_value, ",", vhost->hosts);
    for (size_t i = 0; i < vhost->hosts->count; ++i) {
        vhost->hosts->data[i] = str_trim(vhost->hosts->data[i]);
    }

    const char* ssl_name = config_get(config_node, "ssl");
    if (ssl_name != NULL) {
        struct config_node* ssl_node = hashmap_get(cfg->nodesByName, (char*) ssl_name);
        if (ssl_node == NULL || !str_eq_case(ssl_node->category, "ssl")) {
            errlog(delog, "Invalid SSL node! Node not found! '%s'", ssl_name);
            goto post_ssl;
        }
        const char* cert = config_get(ssl_node, "publicKey");
        const char* key = config_get(ssl_node, "privateKey");
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

    if (vhost->sub->load_config != NULL) {
        vhost->sub->load_config(vhost, config_node);
    }

    return 0;
}

int load_binding(struct config_node* bind_node, struct server_binding* binding) {
    const char* bind_mode = config_get(bind_node, "bind-mode");
    const char* bind_ip = NULL;
    uint16_t port = 0;
    const char* bind_file = NULL;
    int namespace;
    int bind_all = 0;
    int use_ipv6 = 0;
    if (str_eq_case(bind_mode, "tcp")) {
        binding->binding_type = BINDING_TCP4;
        bind_ip = config_get(bind_node, "bind-ip");
        if (bind_ip == NULL || str_eq_case(bind_ip, "0.0.0.0")) {
            bind_all = 1;
        }
        use_ipv6 = bind_all || str_contains_case(bind_ip, ":");
        if (use_ipv6) {
            binding->binding_type = BINDING_TCP6;
        }
        const char* bind_port = config_get(bind_node, "bind-port");
        if (bind_port != NULL && !str_isunum(bind_port)) {
            errlog(delog, "Invalid bind-port for binding: %s", bind_node->name);
            return 1;
        }
        port = (uint16_t) (bind_port == NULL ? 80 : strtoul(bind_port, NULL, 10));
        namespace = use_ipv6 ? PF_INET6 : PF_INET;
    } else if (str_eq_case(bind_mode, "unix")) {
        binding->binding_type = BINDING_UNIX;
        bind_file = config_get(bind_node, "bind-file");
        namespace = PF_LOCAL;
    } else {
        errlog(delog, "Invalid bind-mode for binding: %s", bind_node->name);
        return 1;
    }

    const char* mcc = config_get(bind_node, "max-conn");
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
    sock:;

    if (binding->binding_type == BINDING_TCP6) {
        if (setsockopt(server_fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &zero, sizeof(zero)) == -1) {
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
        if (bind(server_fd, (struct sockaddr*) &binding->binding.tcp6, sizeof(binding->binding.tcp6))) {
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

    const char* protocol = config_get(bind_node, "protocol");
    if (protocol == NULL || str_eq_case(protocol, "http/1.1")) {
        binding->mode |= BINDING_MODE_HTTP2_UPGRADABLE;
    } else if (str_eq_case(protocol, "http/2.0")) {
        binding->mode |= BINDING_MODE_HTTP2_ONLY;
    } else {
        errlog(delog, "Invalid protocol for binding: %s, %s", bind_node->name, strerror(errno));
        return 1;
    }

    const char* ssl_name = config_get(bind_node, "ssl");
    if (ssl_name != NULL) {
        struct config_node* ssl_node = hashmap_get(cfg->nodesByName, ssl_name);
        if (ssl_node == NULL || !str_eq_case(ssl_node->category, "ssl")) {
            errlog(delog, "Invalid SSL node! Node not found! '%s'", ssl_name);
            goto post_ssl;
        }
        const char* cert = config_get(ssl_node, "publicKey");
        const char* key = config_get(ssl_node, "privateKey");
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
    cfg = config_load(cwd);
    if (cfg == NULL) {
        printf("Error loading Config<%s>: %s\n", cwd, errno == EINVAL ? "File doesn't exist!" : strerror(errno));
        return 1;
    }
    struct config_node* daemon_node = config_get_unique_cat(cfg, "daemon");
    if (daemon_node == NULL) {
        printf("[daemon] block does not exist in %s!\n", cwd);
        return 1;
    }
#ifndef DEBUG
    int runn = 0;
    pid_t pid = 0;
    const char* pid_file = getConfigValue(daemon_node, "pid-file");
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
                runn = 1;
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
    const char* el = config_get(daemon_node, "error-log");
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
    const char* fd_limit_str = config_get(daemon_node, "fd-limit");
    if (fd_limit_str == NULL) {
        errlog(delog, "No fd-limit in daemon config! Assuming 1024.");
    }
    size_t fd_lim = fd_limit_str == NULL ? 1024 : strtoul(fd_limit_str, NULL, 10);
    struct rlimit rlx;
    rlx.rlim_cur = fd_lim;
    rlx.rlim_max = fd_lim;
    if (setrlimit(RLIMIT_NOFILE, &rlx) == -1) printf("Error setting resource limit: %s\n", strerror(errno));
    const char* mime_types_file = config_get(daemon_node, "mime-types");
    if (mime_types_file == NULL) {
        errlog(delog, "No mime-types in daemon config!");
        return 1;
    }
    if (access(mime_types_file, R_OK) || loadMimes(mime_types_file)) {
        errlog(delog, "Cannot read or mime-types file does not exist: %s", mime_types_file);
        return 1;
    }
    const char* modules_dir = config_get(daemon_node, "modules");
    if (modules_dir == NULL) {
        errlog(delog, "'modules' directory not defined in daemon block.");
        return 1;
    }
    size_t modules_dir_length = strlen(modules_dir);

    DIR* modules = opendir(modules_dir);
    if (modules == NULL) {
        errlog(delog, "Failed to open modules dir: '%s': %s", modules_dir, strerror(errno));
        return 1;
    }
    registered_vhost_types = hashmap_new(8, global_pool);
    loaded_modules = hashmap_new(8, global_pool);
    available_providers = hashmap_new(8, global_pool);
    available_provider_types = hashmap_new(8, global_pool);
    struct dirent* module_entry = NULL;
    while ((module_entry = readdir(modules)) != NULL) {
        char* name = module_entry->d_name;
        if (!str_suffixes(name, ".so") || !str_prefixes(name, "lib")) {
            continue;
        }
        size_t name_len = strlen(name);
        char* path = str_dup((char*) modules_dir, name_len + 2, global_pool);
        size_t path_index = modules_dir_length;
        if (!str_suffixes(modules_dir, "/")) {
            path[path_index++] = '/';
        }
        memcpy(path + path_index, name, name_len);
        path_index += name_len;
        path[path_index] = 0;
        void* handler = dlopen(path, RTLD_LAZY | RTLD_GLOBAL);
        if (handler == NULL) {
            errlog(delog, "Failed to open module: '%s': %s", path, dlerror());
            continue;
        }
        char* module_name = str_dup(name + 3, 0, global_pool);
        module_name[name_len - 3 - 3] = 0;
        void (*initialize)(struct module* module) = dlsym(handler, "initialize");
        if (initialize == NULL) {
            errlog(delog, "Failed to open module: '%s': %s", path, dlerror());
            continue;
        }
        void (*uninitialize)(struct module* module) = dlsym(handler, "uninitialize");
        // uninitialize can be NULL
        struct mempool* pool = mempool_new();
        struct module* module_data = pcalloc(pool, sizeof(struct module));
        module_data->pool = pool;
        module_data->name = module_name;
        module_data->handle = handler;
        module_data->initialize = initialize;
        module_data->uninitialize = uninitialize;
        hashmap_put(loaded_modules, module_name, module_data);
    }
    (void) SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    OPENSSL_config(NULL);

    ITER_MAP(loaded_modules) {
        struct module* module = value;
        module->initialize(module);
        ITER_MAP_END();
    }

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
        struct config_node* vhost_node = vhost_list->data[i];
        if (vhost_node->name == NULL) {
            errlog(delog, "All vhost nodes must have names, skipping node.");
            continue;
        }

        struct mempool* pool = mempool_new();
        struct vhost* vhost = pcalloc(pool, sizeof(struct vhost));
        vhost->pool = pool;
        if (load_vhost(vhost_node, vhost)) {
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
        const char* bindings = config_get(serv, "bindings");
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

        const char* vhosts = config_get(serv, "vhosts");
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

        const char* tcc = config_get(serv, "threads");
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
        char* maxPostStr = config_get(serv, "max-post");
        if (maxPostStr == NULL || !str_isunum(maxPostStr)) {
            errlog(delog, "No max-post at server: %s, assuming '0'", serv->name);
            maxPostStr = "0";
        }
        info->max_post = strtoul(maxPostStr, NULL, 10);

        struct logsess* slog = pmalloc(info->pool, sizeof(struct logsess));
        slog->pi = 0;
        const char* lal = config_get(serv, "access-log");
        slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
        const char* lel = config_get(serv, "error-log");
        slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
        acclog(slog, "Server %s listening for connections!", serv->name);
        info->logsess = slog;
    }

    const char* uids = config_get(daemon_node, "uid");
    const char* gids = config_get(daemon_node, "gid");
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
            struct accept_param* param = pmalloc(server->pool, sizeof(struct accept_param));
            param->server = server;
            param->binding = server->bindings->data[j];
            pthread_t pt;
            int pthread_err = pthread_create(&pt, NULL, (void*) run_accept, param);
            if (pthread_err != 0) {
                errlog(delog, "Error creating accept thread: pthread errno = %i.", pthread_err);
                continue;
            }
        }

        struct list* works = list_new(server->max_worker_count, server->pool);

        for (size_t j = 0; j < server->max_worker_count; ++j) {
            struct work_param* param = pmalloc(server->pool, sizeof(struct work_param));
            param->i = j;
            param->server = server;
            param->pipes[0] = -1;
            param->pipes[1] = -1;
            pthread_t pt;
            int pthread_err = pthread_create(&pt, NULL, (void*) run_work, param);
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
        int pthread_err = pthread_create(&pt, NULL, (void*) wake_thread, wt_arg);
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
