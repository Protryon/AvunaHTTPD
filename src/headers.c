//
// Created by p on 2/10/19.
//

#include "headers.h"
#include "xstring.h"


const char* header_get(const struct headers* headers, const char* name) {
    if (headers->count == 0) return NULL;
    for (size_t i = 0; i < headers->count; i++) {
        if (str_eq(headers->names[i], name)) {
            return headers->values[i];
        }
    }
    return NULL;
}

int header_set(struct headers* headers, const char* name, const char* value) {
    if (headers->count == 0) return -1;
    for (size_t i = 0; i < headers->count; i++) {
        if (str_eq(headers->names[i], name)) {
            size_t vl = strlen(value) + 1;
            headers->values[i] =
                headers->values[i] == NULL ? pmalloc(headers->pool, vl) : prealloc(headers->pool, headers->values[i],
                                                                                   vl);
            memcpy(headers->values[i], value, vl);
            return 1;
        }
    }
    return 0;
}

int header_add(struct headers* headers, const char* name, const char* value) {
    if (headers->names == NULL || headers->capacity < 8) {
        if (headers->capacity < 8) {
            headers->capacity = 8;
        }
        headers->names = pmalloc(headers->pool, sizeof(char*) * headers->capacity);
        headers->values = pmalloc(headers->pool, sizeof(char*) * headers->capacity);
    } else if (headers->count <= headers->capacity) {
        headers->capacity *= 2;
        headers->values = prealloc(headers->pool, headers->values, sizeof(char*) * headers->capacity);
        headers->names = prealloc(headers->pool, headers->names, sizeof(char*) * headers->capacity);
    }

    headers->count++;
    size_t cdl = strlen(name) + 1;
    size_t vl = strlen(value) + 1;
    headers->names[headers->count - 1] = pmalloc(headers->pool, cdl);
    headers->values[headers->count - 1] = pmalloc(headers->pool, vl);
    memcpy(headers->names[headers->count - 1], name, cdl);
    memcpy(headers->values[headers->count - 1], value, vl);
    return 0;
}

int header_tryadd(struct headers* headers, const char* name, const char* value) {
    if (header_get(headers, name) != NULL) return 1;
    return header_add(headers, name, value);
}

int header_setoradd(struct headers* headers, const char* name, const char* value) {
    int r = 0;
    if (!(r = header_set(headers, name, value))) r = header_add(headers, name, value);
    return r;
}

//modes are 0 for clear, 1 for append, 2 for weak, 3 for append/weak
int header_parse(struct headers* headers, char* data, int mode, struct mempool* pool) {
    if ((mode & 1) == 0) {
        headers->names = NULL;
        headers->values = NULL;
        headers->count = 0;
        headers->pool = pool;
    }
    char* cd = data;
    while (cd != NULL) {
        char* eol = strchr(cd, '\n');
        if (eol == NULL) break;
        eol[0] = 0;
        char* value = strchr(cd, ':');
        if (value == NULL) {
            cd = eol + 1;
            continue;
            // TODO multiline headers?
        }
        value[0] = 0;
        value++;
        cd = str_trim(cd);
        value = str_trim(value);
        if ((mode & 2) == 0) {
            header_add(headers, cd, value);
        } else {
            header_tryadd(headers, cd, value);
        }
        cd = eol + 1;
    }
    return 0;
}

char* header_serialize(struct headers* headers, size_t* len) {
    *len = 0;
    if (headers->count == 0) {
        return NULL;
    }
    for (int i = 0; i < headers->count; i++) {
        *len += strlen(headers->names[i]) + strlen(headers->values[i]) + 4;
    }
    (*len) += 2;
    char* ret = pmalloc(headers->pool, *len);
    int ri = 0;
    for (int i = 0; i < headers->count; i++) {
        size_t nl = strlen(headers->names[i]);
        size_t vl = strlen(headers->values[i]);
        memcpy(ret + ri, headers->names[i], nl);
        ri += nl;
        ret[ri++] = ':';
        ret[ri++] = ' ';
        memcpy(ret + ri, headers->values[i], vl);
        ri += vl;
        ret[ri++] = '\r';
        ret[ri++] = '\n';
    }
    ret[ri++] = '\r';
    ret[ri++] = '\n';
    return ret;
}