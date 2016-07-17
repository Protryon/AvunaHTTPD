/*
 * fcgi.c
 *
 *  Created on: Nov 26, 2015
 *      Author: root
 */

#include "fcgi.h"
#include <stdio.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include "xstring.h"
#include "util.h"

int writeFCGIFrame(int fd, struct fcgiframe* fcgif) {
	unsigned char header[8];
	header[0] = FCGI_VERSION_1;
	header[1] = fcgif->type;
	header[2] = (fcgif->reqID & 0xFF00) >> 8;
	header[3] = fcgif->reqID & 0x00FF;
	header[4] = (fcgif->len & 0xFF00) >> 8;
	header[5] = fcgif->len & 0x00FF;
	header[6] = 0;
	header[7] = 0;
	int w = 0;
	while (w < 8) {
		int x = write(fd, header + w, 8 - w);
		if (x < 0) return -1;
		else if (x == 0) {
			errno = ECONNRESET;
			return -1;
		}
		w += x;
	}
	w = 0;
	while (w < fcgif->len) {
		int x = write(fd, fcgif->data + w, fcgif->len - w);
		if (x < 0) return -1;
		else if (x == 0) {
			errno = ECONNRESET;
			return -1;
		}
		w += x;
	}
	//printf("write %i: %i <%i>\n", fd, fcgif->type, fcgif->len);
	return 0;
}

int writeFCGIParam(int fd, const char* name, const char* value) {
	//printf("fcgi param     %s=%s\n", name, value);
	struct fcgiframe fcgif;
	fcgif.type = FCGI_PARAMS;
	fcgif.reqID = 0;
	size_t ml = strlen(name);
	size_t vl = strlen(value);
	int enl = ml > 127;
	int evl = vl > 127;
	fcgif.len = (enl ? 4 : 1) + (evl ? 4 : 1) + ml + vl;
	unsigned char data[fcgif.len];
	int i = 0;
	if (enl) {
		data[i++] = (ml & 0xFF000000) >> 24 | 0x80;
		data[i++] = (ml & 0x00FF0000) >> 16;
		data[i++] = (ml & 0x0000FF00) >> 8;
		data[i++] = (ml & 0x000000FF);
	} else {
		data[i++] = ml;
	}
	if (evl) {
		data[i++] = ((vl & 0xFF000000) >> 24) | 0x80;
		data[i++] = (vl & 0x00FF0000) >> 16;
		data[i++] = (vl & 0x0000FF00) >> 8;
		data[i++] = (vl & 0x000000FF);
	} else {
		data[i++] = vl;
	}
	memcpy(data + i, name, ml);
	i += ml;
	memcpy(data + i, value, vl);
	fcgif.data = data;
	return writeFCGIFrame(fd, &fcgif);
}

int readFCGIFrame(int fd, struct fcgiframe* fcgif) {
	unsigned char header[8];
	int r = 0;
	while (r < 8) {
		int x = read(fd, header + r, 8 - r);
		if (x < 0) return -1;
		else if (x == 0) {
			errno = ECONNRESET;
			return -1;
		}
		r += x;
	}
	if (header[0] != FCGI_VERSION_1) {
		return -2;
	}
	fcgif->type = header[1];
	fcgif->reqID = (header[2] << 8) + header[3];
	fcgif->len = (header[4] << 8) + header[5];
	unsigned char padding = header[6];
	//7 = reserved
	fcgif->data = xmalloc(fcgif->len + 1);
	((char*) fcgif->data)[fcgif->len] = 0;
	r = 0;
	while (r < fcgif->len) {
		int x = read(fd, fcgif->data + r, fcgif->len - r);
		if (x < 0) return -1;
		else if (x == 0) {
			errno = ECONNRESET;
			return -1;
		}
		r += x;
	}
	r = 0;
	unsigned char pbuf[padding];
	while (r < padding) {
		int x = read(fd, pbuf + r, padding - r);
		if (x < 0) return -1;
		else if (x == 0) {
			errno = ECONNRESET;
			return -1;
		}
		r += x;
	}
	//printf("read %i: %i <%i>\n", fd, fcgif->type, fcgif->len);
	return 0;
}
