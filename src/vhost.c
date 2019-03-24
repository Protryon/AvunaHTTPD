/*
 * vhost.c
 *
 *  Created on: Jul 16, 2016
 *      Author: root
 */

#include <stdlib.h>
#include "xstring.h"
#include "vhost.h"

int domeq(const char* dom1, const char* dom2) {
    if (str_eq_case(dom1, "@") || str_eq_case(dom1, "*")) return 1;
    char* d1 = str_dup(dom1, 1, NULL);
    size_t d1l = strlen(dom1);
    for (size_t i = 0; i < d1l; i++) {
        if (d1[i] == '.') d1[i] = 0;
    }
    d1[d1l + 1] = 0;
    char* od1 = d1;
    char* d2 = str_dup(dom2, 0, NULL);
    char* sp2 = NULL;
    char* m2 = NULL;
    while (strlen(d1) > 0) {
        m2 = strtok_r(m2 == NULL ? d2 : NULL, ".", &sp2);
        if (str_eq_case(d1, "*")) goto cont;
        if (str_eq_case(d1, "**")) {
            char* nd = d1 + strlen(d1) + 1;
            if (m2 == NULL && strlen(nd) == 0) break;
            else if (m2 == NULL) {
                free(od1);
                free(d2);
                return 0;
            }
            if (strlen(nd) > 0 && (!str_eq_case(nd, "*") && !str_eq(nd, m2))) {
                continue;
            } else {
                d1 = nd;
                goto cont;
            }
        }
        if (m2 == NULL || !str_eq(d1, m2)) {
            free(od1);
            free(d2);
            return 0;
        }
        cont:;
        d1 = d1 + strlen(d1) + 1;
    }
    free(od1);
    free(d2);
    return 1;
}

