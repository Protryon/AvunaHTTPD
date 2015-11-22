/*
 * http.c
 *
 *  Created on: Nov 20, 2015
 *      Author: root
 */

#include "http.h"
#include "util.h"
#include "xstring.h"
#include "accept.h"
#include <errno.h>
#include "version.h"
#include <stdio.h>

const char* header_get(const struct headers* headers, const char* name) {
	if (headers->count == 0) return NULL;
	for (int i = 0; i < headers->count; i++) {
		if (streq_nocase(headers->names[i], name)) {
			return headers->values[i];
		}
	}
	return NULL;
}

int header_set(struct headers* headers, const char* name, const char* value) {
	if (headers->count == 0) return -1;
	for (int i = 0; i < headers->count; i++) {
		if (streq_nocase(headers->names[i], name)) {
			int vl = strlen(value) + 1;
			headers->values[i] = xrealloc(headers->values[i], vl);
			memcpy(headers->values[i], value, vl);
			return 0;
		}
	}
	return -1;
}

int header_add(struct headers* headers, const char* name, const char* value) {
	headers->count++;
	if (headers->names == NULL) {
		headers->names = xmalloc(sizeof(char*));
		headers->values = xmalloc(sizeof(char*));
	} else {
		headers->names = xrealloc(headers->names, sizeof(char*) * headers->count);
		headers->values = xrealloc(headers->values, sizeof(char*) * headers->count);
	}
	int cdl = strlen(name) + 1;
	int vl = strlen(value) + 1;
	headers->names[headers->count - 1] = xmalloc(cdl);
	headers->values[headers->count - 1] = xmalloc(vl);
	memcpy(headers->names[headers->count - 1], name, cdl);
	memcpy(headers->values[headers->count - 1], value, vl); // TODO: after a req or two, something here is causing corruption.
	return 0;
}

int parseHeaders(struct headers* headers, char* data) {
	headers->names = NULL;
	headers->values = NULL;
	headers->count = 0;
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
		cd = trim(cd);
		value = trim(value);
		header_add(headers, cd, value);
		cd = eol + 1;
	}
	return 0;
}

char* serializeHeaders(struct headers* headers, size_t* len) {
	*len = 0;
	if (headers->count == 0) {
		return "";
	}
	for (int i = 0; i < headers->count; i++) {
		*len += strlen(headers->names[i]) + strlen(headers->values[i]) + 4;
	}
	(*len) += 3;
	char* ret = xmalloc(*len);
	int ri = 0;
	for (int i = 0; i < headers->count; i++) {
		int nl = strlen(headers->names[i]);
		int vl = strlen(headers->values[i]);
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
	ret[ri++] = 0;
	return ret;
}

void freeHeaders(struct headers* headers) {
	if (headers->count > 0) for (int i = 0; i < headers->count; i++) {
		xfree(headers->names[i]);
		xfree(headers->values[i]);
	}
	if (headers->names != NULL) xfree(headers->names);
	if (headers->values != NULL) xfree(headers->values);
}

int parseRequest(struct request* request, char* data) {
	char* cd = data;
	char* eol1 = strchr(cd, '\n');
	if (eol1 == NULL) {
		errno = EINVAL;
		return -1;
	}
	eol1[0] = 0;
	eol1 = strchr(cd, ' ');
	if (eol1 == NULL) {
		errno = EINVAL;
		return -1;
	}
	eol1[0] = 0;
	if (streq(cd, "GET")) {
		request->method = METHOD_GET;
	} else if (streq(cd, "POST")) {
		request->method = METHOD_POST;
	} else if (streq(cd, "HEAD")) {
		request->method = METHOD_HEAD;
	} else {
		request->method = METHOD_UNK;
	}
	cd = eol1 + 1;
	eol1 = strchr(cd, ' ');
	if (eol1 == NULL) {
		errno = EINVAL;
		return -1;
	}
	eol1[0] = 0;
	size_t pl = strlen(cd) + 1;
	request->path = xmalloc(pl);
	memcpy(request->path, cd, pl);
	cd = eol1 + 1;
	cd = trim(cd);
	pl = strlen(cd) + 1;
	request->version = xmalloc(pl);
	memcpy(request->version, cd, pl);
	cd += pl + 1;
	request->headers.count = 0;
	request->headers.names = NULL;
	request->headers.values = NULL;
	parseHeaders(&request->headers, cd);
	request->body = NULL;
	xfree(data);
	return 0;
}

unsigned char* serializeRequest(struct request* request, size_t* len) {

}

int parseResponse(struct response* response, char* data) {

	xfree(data);
	return 0;
}

unsigned char* serializeResponse(struct response* response, size_t* len) {
	*len = 0;
	size_t vl = strlen(response->version);
	size_t cl = strlen(response->code);
	*len = vl + 1 + cl + 2;
	size_t hl = 0;
	char* headers = serializeHeaders(&response->headers, &hl);
	*len += hl;
	if (response->body != NULL) *len += response->body->len;
	unsigned char* ret = xmalloc(*len);
	size_t wr = 0;
	memcpy(ret, response->version, vl);
	wr += vl;
	ret[wr++] = ' ';
	memcpy(ret + wr, response->code, cl);
	wr += cl;
	ret[wr++] = '\r';
	ret[wr++] = '\n';
	memcpy(ret + wr, headers, hl);
	wr += hl;
	xfree(headers);
	if (response->body != NULL) {
		memcpy(ret + wr, response->body->data, response->body->len);
		wr += response->body->len;
	}
	return ret;
}

int generateResponse(struct conn* sender, struct response* response, struct request* request) {
	response->version = "HTTP/1.1";
	response->code = "200 OK";
	response->headers.count = 0;
	response->headers.names = NULL;
	response->headers.values = NULL;
	char svr[16];
	strcpy(svr, "Avuna/");
	strcat(svr, VERSION);
	header_add(&response->headers, "Server", svr);
	response->body = NULL;
	header_add(&response->headers, "Connection", "keep-alive");
	//body stuff
	header_add(&response->headers, "Content-Type", response->body == NULL ? "text/html" : response->body->mime_type);
	char l[16];
	if (response->body != NULL) sprintf(l, "%u", (unsigned int) response->body->len); //TODO: might be a size limit here
	header_add(&response->headers, "Content-Length", response->body == NULL ? "0" : l);
	return 0;
}
