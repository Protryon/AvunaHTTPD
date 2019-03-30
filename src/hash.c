
#include <avuna/hash.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

uint64_t hashmap_hash(char* key) {
    if (key == NULL) return 0;
    size_t kl = strlen(key);
    size_t i = 0;
    uint64_t hash = 0x8888888888888888;
    for (; i + 8 < kl; i += 8) {
        uint64_t v = *(uint64_t*) &key[i];
        hash = hash ^ v;
    }
    if (kl >= 8) {
        uint64_t v = *(uint64_t*) &key[kl - 8];
        hash = hash ^ v;
    } else {
        for (; i < kl; i++) {
            uint8_t v = (uint8_t) key[i];
            hash = hash ^ (v << (8 * i));
        }
    }
    hash = hash ^ kl;

    return hash;
}

uint64_t hashmap_hash_mod(uint64_t hash, size_t size) {
    // a loop would get marginally better hashes, but be a bit slower
    if (size <= 0xFFFFFFFF) {
        hash = (hash >> 32) ^ (hash & 0xFFFFFFFF);
    }
    if (size <= 0xFFFF) {
        hash = (hash >> 16) ^ (hash & 0xFFFF);
    }
    if (size <= 0xFF) {
        hash = (hash >> 8) ^ (hash & 0xFF);
    }
    return hash % size;
}

void hashset_fixcap(struct hashset* set);

void hashmap_fixcap(struct hashmap* hashmap);

struct hashmap* hashmap_new(size_t init_cap, struct mempool* pool) {
    struct hashmap* map = pcalloc(pool, sizeof(struct hashmap));
    map->bucket_count = init_cap;
    map->buckets = pcalloc(pool, sizeof(struct hashmap_bucket_entry*) * map->bucket_count);
    map->entry_count = 0;
    map->pool = pool;
    return map;
}

struct hashset* hashset_new(size_t init_cap, struct mempool* pool) {
    struct hashset* set = pcalloc(pool, sizeof(struct hashset));
    set->bucket_count = init_cap;
    set->buckets = pcalloc(pool, sizeof(struct hashset_bucket_entry*) * set->bucket_count);
    set->entry_count = 0;
    set->pool = pool;
    return set;
}

void hashmap_free(struct hashmap* hashmap) {
    if (hashmap->pool != NULL) {
        return;
    }
    for (size_t i = 0; i < hashmap->bucket_count; i++) {
        for (struct hashmap_bucket_entry* bucket = hashmap->buckets[i]; bucket != NULL;) {
            struct hashmap_bucket_entry* next = bucket->next;
            free(bucket);
            bucket = next;
        }
    }
    free(hashmap->buckets);
    free(hashmap);
}

void hashset_free(struct hashset* set) {
    if (set->pool != NULL) {
        return;
    }
    for (size_t i = 0; i < set->bucket_count; i++) {
        for (struct hashset_bucket_entry* bucket = set->buckets[i]; bucket != NULL;) {
            struct hashset_bucket_entry* next = bucket->next;
            free(bucket);
            bucket = next;
        }
    }
    free(set->buckets);
    free(set);
}

void* hashmap_get(struct hashmap* hashmap, char* key) {
    uint64_t hashum = hashmap_hash(key);
    uint64_t hash = hashmap_hash_mod(hashum, hashmap->bucket_count);
    for (struct hashmap_bucket_entry* bucket = hashmap->buckets[hash]; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == hashum && (key == bucket->key || (key != NULL && strcmp(bucket->key, key) == 0))) {
            return bucket->data;
        }
    }
    return NULL;
}

void* hashmap_getptr(struct hashmap* hashmap, void* key) {
    uint64_t hash = hashmap_hash_mod((uint64_t) key >> 2, hashmap->bucket_count);
    for (struct hashmap_bucket_entry* bucket = hashmap->buckets[hash]; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == (uint64_t) key && bucket->key == NULL) {
            return bucket->data;
        }
    }
    return NULL;
}

int hashset_has(struct hashset* set, char* key) {
    uint64_t hashum = hashmap_hash(key);
    uint64_t hash = hashmap_hash_mod(hashum, set->bucket_count);
    for (struct hashset_bucket_entry* bucket = set->buckets[hash]; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == hashum && strcmp(bucket->key, key) == 0) {
            return 1;
        }
    }
    return 0;
}

int hashset_hasptr(struct hashset* set, void* key) {
    uint64_t hash = hashmap_hash_mod((uint64_t) key >> 2, set->bucket_count);
    for (struct hashset_bucket_entry* bucket = set->buckets[hash]; bucket != NULL; bucket = bucket->next) {
        if (bucket->key == key) {
            return 1;
        }
    }
    return 0;
}

void hashmap_put(struct hashmap* hashmap, char* key, void* data) {
    uint64_t hashum = hashmap_hash(key);
    uint64_t hash = hashmap_hash_mod(hashum, hashmap->bucket_count);
    struct hashmap_bucket_entry* bucket = hashmap->buckets[hash];
    if (bucket == NULL) {
        bucket = pmalloc(hashmap->pool, sizeof(struct hashmap_bucket_entry));
        bucket->umod_hash = hashum;
        bucket->next = NULL;
        bucket->key = key;
        bucket->data = data;
        hashmap->buckets[hash] = bucket;
        hashmap->entry_count++;
        goto putret;
    }
    for (; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == hashum && (key == bucket->key || (key != NULL && strcmp(bucket->key, key) == 0))) {
            bucket->data = data;
            break;
        } else if (bucket->next == NULL) {
            struct hashmap_bucket_entry* bucketc = pmalloc(hashmap->pool, sizeof(struct hashmap_bucket_entry));
            bucketc->umod_hash = hashum;
            bucketc->next = NULL;
            bucketc->key = key;
            bucketc->data = data;
            bucket->next = bucketc;
            hashmap->entry_count++;
            break;
        }
    }
    putret:;
    hashmap_fixcap(hashmap);
}

void hashmap_putptr(struct hashmap* hashmap, void* key, void* data) {
    uint64_t hash = hashmap_hash_mod((uint64_t) key >> 2, hashmap->bucket_count);
    struct hashmap_bucket_entry* bucket = hashmap->buckets[hash];
    if (bucket == NULL) {
        bucket = pmalloc(hashmap->pool, sizeof(struct hashmap_bucket_entry));
        bucket->umod_hash = ((uint64_t) key) >> 2;
        bucket->next = NULL;
        bucket->key = NULL;
        bucket->data = data;
        hashmap->buckets[hash] = bucket;
        hashmap->entry_count++;
        goto putret;
    }
    for (; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == (uint64_t) key && bucket->key == NULL) {
            bucket->data = data;
            break;
        } else if (bucket->next == NULL) {
            struct hashmap_bucket_entry* bucketc = pmalloc(hashmap->pool, sizeof(struct hashmap_bucket_entry));
            bucketc->umod_hash = ((uint64_t) key) >> 2;
            bucketc->next = NULL;
            bucketc->key = NULL;
            bucketc->data = data;
            bucket->next = bucketc;
            hashmap->entry_count++;
            break;
        }
    }
    putret:;
    hashmap_fixcap(hashmap);
}

void hashmap_fixcap(struct hashmap* hashmap) {
    if ((hashmap->entry_count / hashmap->bucket_count) > 4) {
        size_t nbuck_count = hashmap->bucket_count * 2;
        hashmap->buckets = prealloc(hashmap->pool, hashmap->buckets,
                                    nbuck_count * sizeof(struct hashmap_bucket_entry*));
        memset((void*) hashmap->buckets + (hashmap->bucket_count * sizeof(struct hashmap_bucket_entry*)), 0,
               hashmap->bucket_count * sizeof(struct hashmap_bucket_entry*));
        for (size_t i = 0; i < hashmap->bucket_count; i++) {
            struct hashmap_bucket_entry* lbucket = NULL;
            for (struct hashmap_bucket_entry* bucket = hashmap->buckets[i]; bucket != NULL;) {
                size_t ni = hashmap_hash_mod(bucket->umod_hash, nbuck_count);
                if (ni == i) {
                    lbucket = bucket;
                    bucket = bucket->next;
                    continue;
                } else {
                    struct hashmap_bucket_entry* nbucket = bucket->next;
                    if (lbucket == NULL) {
                        hashmap->buckets[i] = nbucket;
                    } else {
                        lbucket->next = nbucket;
                    }
                    if (hashmap->buckets[ni] == NULL) {
                        hashmap->buckets[ni] = bucket;
                        bucket->next = NULL;
                    } else {
                        bucket->next = hashmap->buckets[ni];
                        hashmap->buckets[ni] = bucket;
                    }
                    bucket = nbucket;
                    // no lbucket change
                }
            }
        }
        hashmap->bucket_count = nbuck_count;
    }
}

void hashset_add(struct hashset* set, char* key) {
    uint64_t hashum = hashmap_hash(key);
    uint64_t hash = hashmap_hash_mod(hashum, set->bucket_count);
    struct hashset_bucket_entry* bucket = set->buckets[hash];
    if (bucket == NULL) {
        bucket = pmalloc(set->pool, sizeof(struct hashset_bucket_entry));
        bucket->umod_hash = hashum;
        bucket->next = NULL;
        bucket->key = key;
        set->buckets[hash] = bucket;
        set->entry_count++;
        goto putret;
    }
    for (; bucket != NULL; bucket = bucket->next) {
        if (bucket->umod_hash == hashum && strcmp(bucket->key, key) == 0) {
            break;
        } else if (bucket->next == NULL) {
            struct hashset_bucket_entry* bucketc = pmalloc(set->pool, sizeof(struct hashset_bucket_entry));
            bucketc->umod_hash = hashum;
            bucketc->next = NULL;
            bucketc->key = key;
            bucket->next = bucketc;
            set->entry_count++;
            break;
        }
    }
    putret:;
    hashset_fixcap(set);
}

void hashset_addptr(struct hashset* set, void* key) {
    uint64_t hash = hashmap_hash_mod((uint64_t) key >> 2, set->bucket_count);
    struct hashset_bucket_entry* bucket = set->buckets[hash];
    if (bucket == NULL) {
        bucket = pmalloc(set->pool, sizeof(struct hashset_bucket_entry));
        bucket->umod_hash = ((uint64_t) key) >> 2;
        bucket->next = NULL;
        bucket->key = key;
        set->buckets[hash] = bucket;
        set->entry_count++;
        goto putret;
    }
    for (; bucket != NULL; bucket = bucket->next) {
        if (bucket->key == key) {
            break;
        } else if (bucket->next == NULL) {
            struct hashset_bucket_entry* bucketc = pmalloc(set->pool, sizeof(struct hashset_bucket_entry));
            bucketc->umod_hash = ((uint64_t) key) >> 2;
            bucketc->next = NULL;
            bucketc->key = key;
            bucket->next = bucketc;
            set->entry_count++;
            break;
        }
    }
    putret:;
    hashset_fixcap(set);
}


void hashset_rem(struct hashset* set, char* key) {
    uint64_t hashum = hashmap_hash(key);
    uint64_t hash = hashmap_hash_mod(hashum, set->bucket_count);
    struct hashset_bucket_entry* bucket = set->buckets[hash];
    if (bucket == NULL) {
        return;
    }
    struct hashset_bucket_entry* last_bucket = NULL;
    for (; bucket != NULL; last_bucket = bucket, bucket = bucket->next) {
        if (bucket->umod_hash == hashum && strcmp(bucket->key, key) == 0) {
            if (last_bucket != NULL) {
                last_bucket->next = bucket->next;
                pprefree(set->pool, bucket);
                break;
            } else {
                set->buckets[hash] = bucket->next;
                pprefree(set->pool, bucket);
                break;
            }
        }
    }
    --set->entry_count;
}

void hashset_remptr(struct hashset* set, void* key) {
    uint64_t hash = hashmap_hash_mod((uint64_t) key >> 2, set->bucket_count);
    struct hashset_bucket_entry* bucket = set->buckets[hash];
    if (bucket == NULL) {
        return;
    }
    struct hashset_bucket_entry* last_bucket = NULL;
    for (; bucket != NULL; last_bucket = bucket, bucket = bucket->next) {
        if (bucket->key == key) {
            if (last_bucket != NULL) {
                last_bucket->next = bucket->next;
                pprefree(set->pool, bucket);
                break;
            } else {
                set->buckets[hash] = bucket->next;
                pprefree(set->pool, bucket);
                break;
            }
        }
    }
}

void hashset_fixcap(struct hashset* set) {
    if ((set->entry_count / set->bucket_count) > 4) {
        size_t nbuck_count = set->bucket_count * 2;
        set->buckets = prealloc(set->pool, set->buckets, nbuck_count * sizeof(struct hashset_bucket_entry*));
        memset((void*) set->buckets + (set->bucket_count * sizeof(struct hashset_bucket_entry*)), 0,
               set->bucket_count * sizeof(struct hashset_bucket_entry*));
        for (size_t i = 0; i < set->bucket_count; i++) {
            struct hashset_bucket_entry* lbucket = NULL;
            for (struct hashset_bucket_entry* bucket = set->buckets[i]; bucket != NULL;) {
                size_t ni = hashmap_hash_mod(bucket->umod_hash, nbuck_count);
                if (ni == i) {
                    lbucket = bucket;
                    bucket = bucket->next;
                    continue;
                } else {
                    struct hashset_bucket_entry* nbucket = bucket->next;
                    if (lbucket == NULL) {
                        set->buckets[i] = nbucket;
                    } else {
                        lbucket->next = nbucket;
                    }
                    if (set->buckets[ni] == NULL) {
                        set->buckets[ni] = bucket;
                        bucket->next = NULL;
                    } else {
                        bucket->next = set->buckets[ni];
                        set->buckets[ni] = bucket;
                    }
                    bucket = nbucket;
                    // no lbucket change
                }
            }
        }
        set->bucket_count = nbuck_count;
    }
}

struct hashmap* hashmap_clone(struct hashmap* hashmap, struct mempool* pool) {
    struct hashmap* newmap = hashmap_new(hashmap->bucket_count, pool);
    for (size_t i = 0; i < hashmap->bucket_count; i++) {
        if (hashmap->buckets[i] == NULL) continue;
        struct hashmap_bucket_entry** newbucket = &newmap->buckets[i];
        for (struct hashmap_bucket_entry* bucket = hashmap->buckets[i]; bucket != NULL; bucket = bucket->next) {
            (*newbucket) = pcalloc(pool, sizeof(struct hashmap_bucket_entry));
            (*newbucket)->data = bucket->data;
            (*newbucket)->key = bucket->key;
            (*newbucket)->umod_hash = bucket->umod_hash;
            newbucket = &((*newbucket)->next);
        }
    }
    return newmap;
}