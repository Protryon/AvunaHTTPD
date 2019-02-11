/*
 * mime.c
 *
 *  Created on: Nov 24, 2015
 *      Author: root
 */

#include "mime.h"
#include "xstring.h"
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include "streams.h"
#include "util.h"
#include "globals.h"

int loadMimes(const char* file) {
	int fd = open(file, O_RDONLY);
	if (fd < 0) return -1;
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
	mimes = NULL;
	mime_count = 0;
	char line[1024];
	int h = 0;
	while ((h = readLine(fd, line, 1024)) >= 0) {
		char* tl = trim(line);
		char* nl = NULL;
		int x = 0;
		struct mime* cm = xmalloc(sizeof(struct mime));
		cm->ext_count = 0;
		cm->exts = NULL;
		while ((nl = strchr(tl, ' ')) != NULL || strlen(tl) > 0) {
			if (nl != NULL) {
				nl[0] = 0;
				nl++;
			}
			if (x++ == 0) {
				cm->type = xstrdup(tl, 0);
			} else {
				if (cm->exts == NULL) {
					cm->exts = xmalloc(sizeof(char*));
					cm->ext_count = 1;
				} else {
					cm->exts = xrealloc(cm->exts, sizeof(char*) * ++cm->ext_count);
				}
				cm->exts[cm->ext_count - 1] = xstrdup(tl, 0);
			}
			tl = nl == NULL ? tl + strlen(tl) : nl;
		}
		if (mimes == NULL) {
			mimes = xmalloc(sizeof(struct mime*));
			mime_count = 1;
		} else {
			mimes = xrealloc(mimes, sizeof(struct mime*) * ++mime_count);
		}
		mimes[mime_count - 1] = cm;
	}
	close(fd);
	return 0;
}

char* getMimeForExt(char* ext) {
	if (ext == NULL || mimes == NULL) return NULL;
	for (int i = 0; i < mime_count; i++) {
		struct mime* mime = mimes[i];
		for (int x = 0; x < mime->ext_count; x++) {
			if (streq_nocase(mime->exts[x], ext)) {
				return mime->type;
			}
		}
	}
	return NULL;
}
