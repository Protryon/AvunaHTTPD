/*
 * config.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include <avuna/config.h>
#include <avuna/string.h>
#include <avuna/streams.h>
#include <avuna/util.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

struct config* loadConfig(const char* file) {
    if (file == NULL) {
        errno = EBADF;
        return NULL;
    }
    if (access(file, F_OK)) {
        errno = EINVAL;
        return NULL;
    }
    if (access(file, R_OK)) {
        errno = EPERM;
        return NULL;
    }
    int fd = open(file, O_RDONLY);
    if (fd < 0) return NULL;
    struct mempool* pool = mempool_new();
    struct config* cfg = pmalloc(pool, sizeof(struct config));
    cfg->pool = pool;
    cfg->allNodes = list_new(16, cfg->pool);
    cfg->nodeListsByCat = hashmap_new(16, cfg->pool);
    cfg->nodesByName = hashmap_new(16, cfg->pool);
    char line[1024];
    ssize_t l = 0;
    struct config_node* cur_node = NULL;
    while (1) {
        l = readLine(fd, line, 1024);
        if (l < 0) break;
        char* wl = str_trim(line);
        if (wl[0] == 0) continue;
        char* comment = strchr(line, '#');
        if (comment != NULL) {
            comment[0] = 0;
            wl = str_trim(line);
            if (wl[0] == 0) continue;
        }
        l = strlen(wl);
        if (l > 5 && wl[0] == '[' && wl[l - 1] == ']') {
            wl[--l] = 0;
            wl++;
            char* id = strchr(wl, ' ');
            if (id != NULL) {
                id[0] = 0;
                id++;
                id = str_trim(id);
            }
            wl = str_trim(wl);
            char* category = str_dup(wl, 0, cfg->pool);
            cur_node = pmalloc(cfg->pool, sizeof(struct config_node));
            list_add(cfg->allNodes, cur_node);
            cur_node->map = hashmap_new(16, cfg->pool);
            struct list* current_cat_list = hashmap_get(cfg->nodeListsByCat, category);
            if (current_cat_list == NULL) {
                current_cat_list = list_new(8, cfg->pool);
                hashmap_put(cfg->nodeListsByCat, category, current_cat_list);
            }
            list_add(current_cat_list, cur_node);
            cur_node->category = category;

            if (id == NULL) {
                cur_node->name = NULL;
            } else {
                cur_node->name = str_dup(id, 0, cfg->pool);
                hashmap_put(cfg->nodesByName, cur_node->name, cur_node);
            }
        } else {
            char* value = strchr(wl, '=');
            if (value == NULL) continue;
            value[0] = 0;
            value++;
            value = str_trim(value);
            wl = str_trim(wl);
            hashmap_put(cur_node->map, str_dup(wl, 0, cfg->pool), str_dup(value, 0, cfg->pool));
        }
    }
    close(fd);
    return cfg;
}

const char* getConfigValue(const struct config_node* cat, const char* name) {
    if (cat == NULL || name == NULL) return NULL;
    return (char*) hashmap_get(cat->map, name);
}

struct config_node* getUniqueByCat(const struct config* cfg, const char* cat) {
    if (cfg == NULL || cat == NULL) return NULL;
    struct list* cat_list = hashmap_get(cfg->nodeListsByCat, cat);
    if (cat_list == NULL || cat_list->count == 0) {
        return NULL;
    }
    return cat_list->data[0];
}
