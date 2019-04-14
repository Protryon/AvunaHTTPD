//
// Created by p on 2/10/19.
//

#include <avuna/headers.h>
#include <avuna/string.h>
#include <avuna/hash.h>
#include <avuna/llist.h>
#include <stdio.h>


char* header_get(struct headers* headers, char* name) {
    char lower[strlen(name) + 1];
    memcpy(lower, name, strlen(name) + 1);
    str_tolower(lower);
    struct llist* list = hashmap_get(headers->header_map, lower);
    if (list == NULL) return NULL;
    struct header_entry* entry = list->head->data;
    return entry->value;
}

int header_set(struct headers* headers, char* name, char* value) {
    char lower[strlen(name) + 1];
    memcpy(lower, name, strlen(name) + 1);
    str_tolower(lower);
    struct llist* list = hashmap_get(headers->header_map, name);
    if (list == NULL) return 0;
    struct header_entry* entry = list->head->data;
    entry->value = str_dup(value, 0, headers->pool);
    return 1;
}

int header_add(struct headers* headers, char* name, char* value) {
    struct llist* list = hashmap_get(headers->header_map, name);
    char* new_name = str_tolower(str_dup(name, 0, headers->pool));
    if (list == NULL) {
        list = llist_new(headers->pool);
        hashmap_put(headers->header_map, new_name, list);
    }
    struct header_entry* entry = pcalloc(headers->pool, sizeof(struct header_entry));
    entry->name = new_name;
    entry->value = str_dup(value, 0, headers->pool);
    entry->map_node = llist_append(list, entry);
    entry->node = llist_append(headers->header_list, entry);
    return 1;
}

int header_prepend(struct headers* headers, char* name, char* value) {
    struct llist* list = hashmap_get(headers->header_map, name);
    char* new_name = str_tolower(str_dup(name, 0, headers->pool));
    if (list == NULL) {
        list = llist_new(headers->pool);
        hashmap_put(headers->header_map, new_name, list);
    }
    struct header_entry* entry = pcalloc(headers->pool, sizeof(struct header_entry));
    entry->name = new_name;
    entry->value = str_dup(value, 0, headers->pool);
    entry->map_node = llist_prepend(list, entry);
    entry->node = llist_prepend(headers->header_list, entry);
    return 1;
}


void header_del(struct headers* headers, char* name) {
    char lower[strlen(name) + 1];
    memcpy(lower, name, strlen(name) + 1);
    str_tolower(lower);
    struct llist* list = hashmap_get(headers->header_map, lower);
    if (list == NULL) {
        return;
    }
    ITER_LLIST(list, value) {
        struct header_entry* entry = value;
        llist_del(headers->header_list, entry->node);
        ITER_LLIST_END();
    }
    hashmap_put(headers->header_map, lower, NULL);
}


int header_tryadd(struct headers* headers, char* name, char* value) {
    if (header_get(headers, name) != NULL) return 1;
    return header_add(headers, name, value);
}

int header_setoradd(struct headers* headers, char* name, char* value) {
    int r = 0;
    if (!(r = header_set(headers, name, value)))
        r = header_add(headers, name, value);
    return r;
}

struct headers* header_new(struct mempool* parent) {
    struct mempool* pool = mempool_new();
    pchild(parent, pool);
    struct headers* headers = pcalloc(pool, sizeof(struct headers));
    headers->header_list = llist_new(pool);
    headers->header_map = hashmap_new(16, pool);
    headers->pool = pool;
    return headers;
}

struct headers* header_parse(char* data, struct mempool* parent) {
    struct headers* headers = header_new(parent);
    char* cd = data;
    while (cd != NULL) {
        char* eol = strchr(cd, '\n');
        if (eol == NULL) break;
        eol[0] = 0;
        char* value = strchr(cd, ':');
        if (value == NULL) {
            cd = eol + 1;
            continue;
        }
        value[0] = 0;
        value++;
        cd = str_trim(cd);
        value = str_trim(value);
        header_add(headers, cd, value);
        cd = eol + 1;
    }
    return headers;
}

char* header_serialize(struct headers* headers, size_t* len) {
    *len = 0;
    ITER_LLIST(headers->header_list, value) {
        struct header_entry* entry = value;
        *len += strlen(entry->name) + strlen(entry->value) + 4;
        ITER_LLIST_END();
    }
    (*len) += 2;
    char* ret = pmalloc(headers->pool, *len);
    int ri = 0;
    ITER_LLIST(headers->header_list, value) {
        struct header_entry* entry = value;
        ri += snprintf(ret + ri, *len - ri, "%s: %s\r\n", entry->name, entry->value);
        ITER_LLIST_END();
    }
    ret[ri++] = '\r';
    ret[ri++] = '\n';
    return ret;
}