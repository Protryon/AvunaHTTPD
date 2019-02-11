/*
 * vhost.c
 *
 *  Created on: Jul 16, 2016
 *      Author: root
 */

#include <stdlib.h>
#include "xstring.h"
#include "vhost.h"
#include "util.h"

int domeq(const char* dom1, const char* dom2) {
	if (streq(dom1, "@") || streq(dom1, "*")) return 1;
	char* d1 = xstrdup(dom1, 1);
	size_t d1l = strlen(dom1);
	for (size_t i = 0; i < d1l; i++) {
		if (d1[i] == '.') d1[i] = 0;
	}
	d1[d1l + 1] = 0;
	char* od1 = d1;
	char* d2 = xstrdup(dom2, 0);
	char* sp2 = NULL;
	char* m2 = NULL;
	while (strlen(d1) > 0) {
		m2 = strtok_r(m2 == NULL ? d2 : NULL, ".", &sp2);
		if (streq(d1, "*")) goto cont;
		if (streq(d1, "**")) {
			char* nd = d1 + strlen(d1) + 1;
			if (m2 == NULL && strlen(nd) == 0) break;
			else if (m2 == NULL) {
				xfree(od1);
				xfree(d2);
				return 0;
			}
			if (strlen(nd) > 0 && (!streq(nd, "*") && !streq_nocase(nd, m2))) {
				continue;
			} else {
				d1 = nd;
				goto cont;
			}
		}
		if (m2 == NULL || !streq_nocase(d1, m2)) {
			xfree(od1);
			xfree(d2);
			return 0;
		}
		cont: ;
		d1 = d1 + strlen(d1) + 1;
	}
	xfree(od1);
	xfree(d2);
	return 1;
}

