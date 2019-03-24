/*
 * config.h
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#ifndef CONFIG_H_
#define CONFIG_H_

#include "hash.h"
#include "list.h"
#include "pmem.h"

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

struct config* loadConfig(const char* file);

const char* getConfigValue(const struct config_node* cat, const char* name);

struct config_node* getUniqueByCat(const struct config* cfg, const char* cat);

#endif /* CONFIG_H_ */
