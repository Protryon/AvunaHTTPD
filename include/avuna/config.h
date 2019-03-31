/*
 * config.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include <avuna/pmem.h>
#include <avuna/hash.h>
#include <avuna/list.h>

struct config_node {
    char* category;
    char* name;
    struct hashmap* map;
};

struct config {
    struct mempool* pool;
    struct list* allNodes;
    struct hashmap* nodesByName;
    struct hashmap* nodeListsByCat;
};

struct config* config_load(const char* file);

const char* config_get(const struct config_node* cat, const char* name);

char* config_get_default(struct config_node* node, char* key, char* def);

struct config_node* config_get_unique_cat(const struct config* cfg, const char* cat);

#endif /* CONFIG_H_ */
