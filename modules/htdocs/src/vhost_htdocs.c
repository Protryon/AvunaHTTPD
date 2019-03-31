//
// Created by p on 3/30/19.
//

#include <mod_htdocs/util.h>
#include <mod_htdocs/vhost_htdocs.h>
#include <mod_htdocs/gzip.h>
#include <avuna/string.h>
#include <avuna/mime.h>
#include <avuna/provider.h>
#include <avuna/pmem_hooks.h>
#include <avuna/util.h>
#include <avuna/module.h>
#include <avuna/globals.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../../../src/vhost.h"


void handle_vhost_htdocs(struct request_session* rs) {
    struct vhost* vhost = rs->vhost;
    struct vhost_htdocs* htdocs = ((struct vhost_htdocs*) rs->vhost->sub->extra);
    if (htdocs->base.scacheEnabled && check_cache(rs)) {
        return;
    }
    int isStatic = 1;
    // make path relative to htdocs
    char* htpath;
    {
        size_t path_length = strlen(rs->request->path);
        if (path_length < 1 || rs->request->path[0] != '/') {
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "Malformed Request! If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
        size_t htdocs_length = strlen(htdocs->htdocs);
        htpath = pmalloc(rs->pool, htdocs_length + path_length);
        memcpy(htpath, htdocs->htdocs, htdocs_length);
        memcpy(htpath + htdocs_length, rs->request->path + 1, path_length);
        htpath[htdocs_length + path_length - 1] = 0;
    }
    // remove query parameters, if any
    {
        char* htpath_part = strchr(htpath, '#');
        if (htpath_part != NULL) htpath_part[0] = 0;
        htpath_part = strchr(htpath, '?');
        if (htpath_part != NULL) htpath_part[0] = 0;
    }


    // split path by '/' removing empty entries and initial entry (always empty)
    char* htpath_split = str_dup(htpath + 1, 1, rs->pool);
    {
        size_t htpath_split_length = strlen(htpath_split);
        htpath_split[htpath_split_length + 1] = 0;
        size_t last_x = 0;
        for (size_t x = 0; x < htpath_split_length; x++) {
            if (htpath_split[x] == '/') {
                htpath_split[x] = 0;
                if (last_x == x - 1) {
                    memmove(htpath_split + x, htpath_split + x + 1, htpath_split_length - x);
                }
                last_x = x;
            }
        }
    }

    int file_as_directory = 0; // set to true for files in directory path elements
    char* extra_path = NULL;
    // extra path resolution
    {
        char* htpath_preextra = pmalloc(rs->pool, 1);
        htpath_preextra[0] = 0;
        size_t htpath_preextra_length = 0;
        size_t extra_path_length = 0;
        size_t segment_length = 0;
        while ((segment_length = strlen(htpath_split)) > 0) {
            if (file_as_directory) {
                if (extra_path == NULL) extra_path = pmalloc(rs->pool, extra_path_length + segment_length + 2);
                else extra_path = prealloc(rs->pool, extra_path, extra_path_length + segment_length + 2);
                extra_path[extra_path_length++] = '/';
                memcpy(extra_path + extra_path_length, htpath_split, segment_length + 1);
                extra_path_length += segment_length;
                htpath_split += segment_length + 1;
            } else {
                htpath_preextra = prealloc(rs->pool, htpath_preextra, htpath_preextra_length + segment_length + 2);
                htpath_preextra[htpath_preextra_length++] = '/';
                memcpy(htpath_preextra + htpath_preextra_length, htpath_split, segment_length + 1);
                htpath_preextra_length += segment_length;
                htpath_split += segment_length + 1;
                struct stat cs;
                if (stat(htpath_preextra, &cs) < 0) {
                    if (errno == ENOENT || errno == ENOTDIR) {
                        rs->response->code = "404 Not Found";
                        generateDefaultErrorPage(rs,
                                                 "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
                    } else if (errno == EACCES) {
                        rs->response->code = "403 Forbidden";
                        generateDefaultErrorPage(rs,
                                                 "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
                    } else {
                        errlog(rs->conn->server->logsess, "Error while stating file: %s", strerror(errno));
                        rs->response->code = "500 Internal Server Error";
                        generateDefaultErrorPage(rs,
                                                 "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                    }
                    goto return_error;
                }
                if ((cs.st_mode & S_IFDIR) != S_IFDIR) {
                    file_as_directory = 1;
                }
            }
        }
        if (!file_as_directory) {
            htpath_preextra = prealloc(rs->pool, htpath_preextra, htpath_preextra_length + 2);
            htpath_preextra[htpath_preextra_length] = '/';
            htpath_preextra[htpath_preextra_length + 1] = 0;
        }
        htpath = htpath_preextra;
    }

    // resolve index if applicable
    int index_found = 0;
    if (!file_as_directory && !access(htpath, R_OK)) { // TODO: extra paths?
        for (size_t i = 0; i < htdocs->index->count; i++) {
            size_t index_length = strlen(htdocs->index->data[i]);
            char* index_path = str_dup(htpath, index_length, rs->pool);
            size_t htpath_length = strlen(htpath);
            memcpy(index_path + htpath_length, htdocs->index->data[i], index_length + 1);
            if (!access(index_path, R_OK)) {
                htpath = index_path;
                index_found = 1;
                break;
            }
        }
    }

    // resolve directory edge case:
    // if a url (http://example.com/test) is requested suc that test is a directory, cookies and other expected features of the index can break if we don't add a trailing slash.
    if (!file_as_directory) {
        char* expanded_path = str_dup(rs->request->path, 2, rs->pool);
        char* last_slash = strrchr(expanded_path, '/'); // no extra path because extra paths dont work on directories
        size_t after_last_slash = strlen(last_slash);

        if (last_slash != NULL && (after_last_slash > 1 && last_slash[1] != '?' && last_slash[1] != '#')) {
            rs->response->code = "302 Found";
            char* parameters = strpbrk(last_slash, "?#");
            if (parameters != NULL) {
                memmove(parameters, parameters + 1, strlen(parameters) + 1);
                parameters[0] = '/';
            } else {
                size_t expanded_path_length = strlen(expanded_path);
                expanded_path[expanded_path_length] = '/';
                expanded_path[expanded_path_length + 1] = 0;
            }
            header_add(rs->response->headers, "Location", expanded_path);
            return;
        }

        if (!index_found) {
            rs->response->code = "404 Not Found";
            generateDefaultErrorPage(rs,
                                     "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
    }

    struct stat st;
    htpath = pclaim(rs->pool, realpath(htpath, NULL));

    if (htpath == NULL) {
        // double checking permissions and presence
        if (errno == ENOENT || errno == ENOTDIR) {
            rs->response->code = "404 Not Found";
            generateDefaultErrorPage(rs,
                                     "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
        } else if (errno == EACCES) {
            rs->response->code = "403 Forbidden";
            generateDefaultErrorPage(rs,
                                     "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
        } else {
            errlog(rs->conn->server->logsess, "Error while getting the realpath of a file: %s",
                   strerror(errno));
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
        }
        goto return_error;
    }

    if (stat(htpath, &st) != 0) {
        errlog(rs->conn->server->logsess, "Failed stat on <%s>: %s", htpath, strerror(errno));
        rs->response->code = "500 Internal Server Error";
        generateDefaultErrorPage(rs,
                                 "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
        goto return_error;
    }

    {
        // ensure realpath didn't remove a trailing slash from a directory.
        size_t htpath_length = strlen(htpath);
        if ((st.st_mode & S_IFDIR) && htpath[htpath_length - 1] != '/') {
            htpath = prealloc(rs->pool, htpath, ++htpath_length + 1);
            htpath[htpath_length - 1] = '/';
            htpath[htpath_length] = 0;
        }
    }

    rs->request_htpath = htpath;
    rs->request_extra_path = extra_path;

    if (htdocs->symlock && !str_prefixes_case(htpath, htdocs->htdocs)) {
        rs->response->code = "404 Not Found";
        generateDefaultErrorPage(rs,
                                 "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
        goto return_error;
    }
    if (htdocs->nohardlinks && st.st_nlink != 1 && !(st.st_mode & S_IFDIR)) {
        rs->response->code = "403 Forbidden";
        generateDefaultErrorPage(rs,
                                 "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
        goto return_error;
    }

    // empty initialized body
    struct mempool* body_pool = mempool_new();
    rs->response->body = pcalloc(body_pool, sizeof(struct provision));
    rs->response->body->pool = body_pool;
    pchild(rs->pool, rs->response->body->pool);
    rs->response->body->type = PROVISION_DATA;
    char* ext = strrchr(htpath, '.');
    char* content_type = NULL;
    if (ext == NULL) {
        content_type = rs->response->body->content_type = "application/octet-stream";
    } else {
        char* mime = getMimeForExt(ext + 1);
        if (mime == NULL) {
            content_type = rs->response->body->content_type = "application/octet-stream";
        } else {
            content_type = rs->response->body->content_type = mime;
        }
    }

    struct provider* provider = hashmap_get(htdocs->providers, rs->response->body->content_type);

    if (provider != NULL) {
        isStatic = 0;
        rs->response->body = provider->provide_data(provider, rs);
        if (rs->response->body == NULL) {
            goto return_error;
        }
    } else {
        if (rs->response->body->pool == NULL) {
            body_pool = mempool_new();
            rs->response->body = pcalloc(body_pool, sizeof(struct provision));
            rs->response->body->pool = body_pool;
            pchild(rs->pool, rs->response->body->pool);
        }
        rs->response->body->content_type = content_type;
        check_client_cache(rs);

        int ffd = open(htpath, O_RDONLY);
        if (ffd < 0) {
            errlog(rs->conn->server->logsess, "Failed to open file %s! %s", htpath, strerror(errno));
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
        ssize_t len = lseek(ffd, 0, SEEK_END);
        if (len < 0 || lseek(ffd, 0, SEEK_SET) != 0) {
            close(ffd);
            errlog(rs->conn->server->logsess, "Failed to seek file %s! %s", htpath, strerror(errno));
            rs->response->code = "500 Internal Server Error";
            generateDefaultErrorPage(rs,
                                     "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
            goto return_error;
        }
        if (len < 1024 * 1024) { // perhaps make this configurable?
            rs->response->body->type = PROVISION_DATA;
            rs->response->body->data.data.size = 0;
            rs->response->body->data.data.data = pmalloc(rs->pool, (size_t) len);
            ssize_t r = 0;
            while ((r = read(ffd, rs->response->body->data.data.data + rs->response->body->data.data.size,
                             len - rs->response->body->data.data.size)) > 0) {
                rs->response->body->data.data.size += r;
            }
            if (r < 0) {
                errlog(rs->conn->server->logsess, "Failed to read file %s! %s", htpath, strerror(errno));
                close(ffd);
                rs->response->code = "500 Internal Server Error";
                generateDefaultErrorPage(rs,
                                         "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
                goto return_error;
            }
            close(ffd);
        } else {
            phook(rs->pool, close_hook, (void*) ffd);
            rs->response->body->type = PROVISION_STREAM;
            rs->response->body->data.stream.stream_fd = ffd;
            rs->response->body->data.stream.read = raw_stream_read;
        }
    }

    return_error:;
    char etag[35];
    int has_etag = 0;
    int cache_activated = 0;
    if (rs->response->body != NULL && rs->response->body->type == PROVISION_DATA && rs->response->body->data.data.size > 0 && rs->response->code != NULL &&
        rs->response->code[0] == '2') {
        MD5_CTX md5ctx;
        MD5_Init(&md5ctx);
        MD5_Update(&md5ctx, rs->response->body->data.data.data, rs->response->body->data.data.size);
        unsigned char rawmd5[16];
        MD5_Final(rawmd5, &md5ctx);
        has_etag = 1;
        etag[34] = 0;
        etag[0] = '\"';
        for (int i = 0; i < 16; i++) {
            snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
        }
        etag[33] = '\"';
        header_add(rs->response->headers, "ETag", etag);
        if (str_eq_case(etag, header_get(rs->request->headers, "If-None-Match"))) {
            cache_activated = 1;
            if (!isStatic) {
                rs->response->code = "304 Not Modified";
                rs->response->body = NULL;
            }
        }
    }

    int do_gzip = should_gzip(rs);

    if (do_gzip == 1) {
        if (rs->response->body->type == PROVISION_DATA) {
            if (gzip_total(rs)) {
                // gzip failed, continue without it
                do_gzip = 0;
            }
        } else { // PROVISION_STREAM
            struct provision* gzip_overlay = xcopy(rs->response->body, sizeof(struct provision), 0, rs->response->body->pool);
            init_gzip_stream(rs->response->body, gzip_overlay);
            rs->response->body = gzip_overlay;
        }
    }


    if (isStatic && htdocs->base.scacheEnabled && rs->response->body->type == PROVISION_DATA &&
        (htdocs->base.maxCache <= 0 || htdocs->base.maxCache < htdocs->base.cache->max_size)) {
        struct mempool* scpool = mempool_new();
        struct scache* sc = pmalloc(scpool, sizeof(struct scache));
        sc->pool = scpool;
        pchild(htdocs->base.cache->pool, sc->pool);
        pxfer_parent(rs->pool, sc->pool, rs->response->body->pool);
        sc->content_encoding = do_gzip == 1 || do_gzip == -1; // done or already done
        sc->code = pxfer(rs->pool, sc->pool, rs->response->code);
        if (rs->response->body != NULL)
            header_setoradd(rs->response->headers, "Content-Type", rs->response->body->content_type);
        char l[16];
        if (rs->response->body != NULL) sprintf(l, "%u", (unsigned int) rs->response->body->data.data.size);
        header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
        sc->headers = pxfer(rs->pool, sc->pool, rs->response->headers);
        sc->headers->pool = sc->pool;
        pxfer(rs->pool, sc->pool, sc->headers->names);
        pxfer(rs->pool, sc->pool, sc->headers->values);
        for (size_t i = 0; i < sc->headers->count; ++i) {
            pxfer(rs->pool, sc->pool, sc->headers->names[i]);
            pxfer(rs->pool, sc->pool, sc->headers->values[i]);
        }
        sc->request_path = pxfer(rs->pool, sc->pool, rs->request->path);
        if (!has_etag) {
            if (rs->response->body == NULL) {
                etag[0] = '\"';
                memset(etag + 1, '0', 32);
                etag[33] = '\"';
                etag[34] = 0;
            } else {
                MD5_CTX md5ctx;
                MD5_Init(&md5ctx);
                MD5_Update(&md5ctx, rs->response->body->data, rs->response->body->len);
                unsigned char rawmd5[16];
                MD5_Final(rawmd5, &md5ctx);
                etag[34] = 0;
                etag[0] = '\"';
                for (int i = 0; i < 16; i++) {
                    snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
                }
                etag[33] = '\"';
            }
        }
        memcpy(sc->etag, etag, 35);
        cache_add(htdocs->base.cache, sc);
        rs->response->fromCache = sc;
        rs->request->add_to_cache = 1;
        if (cache_activated) {
            rs->response->body = NULL;
            rs->response->code = "304 Not Modified";
        }
    }
    //TODO: Chunked
}

char* load_default(struct config_node* node, char* key, char* def) {
    char* result = getConfigValue(node, key);
    if (result == NULL) {
        if (def == NULL) {
            errlog(delog, "No %s at vhost %s, no default is available.", key, node->name);
        } else {
            result = def;
            errlog(delog, "No %s at vhost %s, assuming default \"%s\".", key, node->name, def);
        }
    }
    return result;
}

int vhost_parse_config(struct vhost* vhost, struct config_node* node) {
    struct vhost_htdocs* htdocs = vhost->sub->extra = pcalloc(sizeof(struct vhost_htdocs));
    htdocs->index = list_new(8, vhost->pool);
    htdocs->base.error_pages = hashmap_new(8, vhost->pool);
    htdocs->base.enableGzip = 1;
    htdocs->base.cache_types = list_new(8, vhost->pool);
    htdocs->base.maxAge = 604800;
    htdocs->providers = hashmap_new(8, vhost->pool);
    htdocs->htdocs = load_default(node, "htdocs", "/var/www/html/");
    recur_mkdir(htdocs->htdocs, 0750);
    char* original_htdocs = htdocs->htdocs;
    htdocs->htdocs = pclaim(vhost->pool, realpath(htdocs->htdocs, NULL));
    if (htdocs->htdocs == NULL) {
        errlog(delog, "Cannot find create htdocs for vhost %s: %s.", node->name, original_htdocs);
        return 1;
    }
    size_t htdocs_length = strlen(htdocs->htdocs);
    if (htdocs->htdocs[htdocs_length - 1] != '/') {
        htdocs->htdocs = prealloc(vhost->pool, htdocs->htdocs, ++htdocs_length + 1);
        htdocs->htdocs[htdocs_length - 1] = '/';
        htdocs->htdocs[htdocs_length] = 0;
    }
    htdocs->nohardlinks = (uint8_t) str_eq(load_default(node, "nohardlinks", "true"), "true");
    htdocs->symlock = (uint8_t) str_eq(load_default(node, "symlock", "true"), "true");
    htdocs->base.scacheEnabled = (uint8_t) str_eq(load_default(node, "scache", "true"), "true");
    char* temp = load_default(node, "cache-maxage", "604800");
    if (!str_isunum(temp)) {
        errlog(delog, "Invalid cache-maxage at vhost: %s, assuming '604800'", node->name);
        temp = "604800";
    }
    htdocs->base.maxAge = strtoul(temp, NULL, 10);
    temp = load_default(node, "maxSCache", "0");
    if (!str_isunum(temp)) {
        errlog(delog, "Invalid maxSCache at vhost: %s, assuming '0'", node->name);
        temp = "0";
    }
    htdocs->base.cache = cache_new(strtoul(temp, NULL, 10));
    pchild(vhost->pool, htdocs->base.cache->pool);
    htdocs->base.enableGzip = (uint8_t) str_eq(load_default(node, "enable-gzip", "true"), "true");
    temp = load_default(node, "index", "index.php, index.html, index.htm");
    char* temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", htdocs->index);
    for (size_t i = 0; i < htdocs->index->count; ++i) {
        htdocs->index->data[i] = str_trim(htdocs->index->data[i]);
    }

    temp = load_default(node, "cache-types", "text/css,application/javascript,image/*");
    temp2 = str_dup(temp, 0, vhost->pool);
    str_split(temp2, ",", htdocs->base.cache_types);
    for (size_t i = 0; i < htdocs->base.cache_types->count; ++i) {
        htdocs->base.cache_types->data[i] = str_trim(htdocs->base.cache_types->data[i]);
    }

    ITER_MAP(node->map) {
        if (str_prefixes(str_key, "error-")) {
            const char* en = str_key + 6;
            if (!str_isunum(en)) {
                errlog(delog, "Invalid error page specifier at vhost: %s", node->name);
                continue;
            }
            hashmap_putptr(htdocs->base.error_pages, (void*) strtoul(en, NULL, 10), value);
        }
        ITER_MAP_END();
    }

    temp = getConfigValue(node, "providers");
    if (temp != NULL) {
        temp2 = str_dup(temp, 0, vhost->pool);
        struct list* provider_names = list_new(8, vhost->pool);
        str_split(temp2, ",", provider_names);
        for (size_t i = 0; i < provider_names->count; ++i) {
            provider_names->data[i] = str_trim(provider_names->data[i]);
            struct provider* provider = hashmap_get(available_providers, provider_names->data[i]);
            if (provider == NULL) {
                errlog(delog, "Could not find provider entry %s at vhost: %s", temp2, node->name);
                continue;
            }
        }
    }
    return 0;
}

void initialize(struct module* module) {
    struct vhost_type* vhost_type = pcalloc(module->pool, sizeof(struct vhost_type));
    vhost_type->handle_request = handle_vhost_htdocs;
    vhost_type->load_config = vhost_parse_config;
    vhost_type->name = "htdocs";
    hashmap_put(registered_vhost_types, "htdocs", vhost_type);
}