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
#include "work.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "mime.h"
#include <fcntl.h>
#include <openssl/md5.h>
#include <zlib.h>
#include "cache.h"
#include "fcgi.h"
#include <netinet/in.h>
#include "vhost.h"
#include <stdint.h>
#include "oqueue.h"

const char* getMethod(int m) {
	if (m == METHOD_GET) {
		return "GET";
	} else if (m == METHOD_POST) {
		return "POST";
	} else if (m == METHOD_HEAD) {
		return "HEAD";
	} else {
		return "UNKNOWN";
	}
}

char* escapehtml(const char* orig) {
	size_t len = strlen(orig);
	size_t clen = len + 1;
	size_t ioff = 0;
	char* ns = xmalloc(clen);
	for (int i = 0; i < len; i++) {
		if (orig[i] == '&') {
			clen += 4;
			ns = xrealloc(ns, clen);
			ns[i + ioff] = '&';
			ns[i + ioff++] = 'a';
			ns[i + ioff++] = 'm';
			ns[i + ioff++] = 'p';
			ns[i + ioff++] = ';';
		} else if (orig[i] == '\"') {
			clen += 5;
			ns = xrealloc(ns, clen);
			ns[i + ioff] = '&';
			ns[i + ioff++] = 'q';
			ns[i + ioff++] = 'u';
			ns[i + ioff++] = 'o';
			ns[i + ioff++] = 't';
			ns[i + ioff++] = ';';
		} else if (orig[i] == '\'') {
			clen += 5;
			ns = xrealloc(ns, clen);
			ns[i + ioff] = '&';
			ns[i + ioff++] = '#';
			ns[i + ioff++] = '0';
			ns[i + ioff++] = '3';
			ns[i + ioff++] = '9';
			ns[i + ioff++] = ';';
		} else if (orig[i] == '<') {
			clen += 3;
			ns = xrealloc(ns, clen);
			ns[i + ioff] = '&';
			ns[i + ioff++] = 'l';
			ns[i + ioff++] = 't';
			ns[i + ioff++] = ';';
		} else if (orig[i] == '>') {
			clen += 3;
			ns = xrealloc(ns, clen);
			ns[i + ioff] = '&';
			ns[i + ioff++] = 'g';
			ns[i + ioff++] = 't';
			ns[i + ioff++] = ';';
		} else {
			ns[i + ioff] = orig[i];
		}
	}
	ns[clen - 1] = 0;
	return ns;
}

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
			size_t vl = strlen(value) + 1;
			headers->values[i] = headers->values[i] == NULL ? xmalloc(vl) : xrealloc(headers->values[i], vl);
			memcpy(headers->values[i], value, vl);
			return 1;
		}
	}
	return 0;
}

int header_add(struct headers* headers, const char* name, const char* value) {
	headers->count++;
	if (headers->names == NULL) {
		headers->names = xmalloc(sizeof(char*));
		headers->values = xmalloc(sizeof(char*));
	} else {
		headers->values = xrealloc(headers->values, sizeof(char*) * headers->count);
		headers->names = xrealloc(headers->names, sizeof(char*) * headers->count);
	}
	int cdl = strlen(name) + 1;
	int vl = strlen(value) + 1;
	headers->names[headers->count - 1] = xmalloc(cdl);
	headers->values[headers->count - 1] = xmalloc(vl);
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
int parseHeaders(struct headers* headers, char* data, int mode) {
	if ((mode & 1) == 0) {
		headers->names = NULL;
		headers->values = NULL;
		headers->count = 0;
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
		cd = trim(cd);
		value = trim(value);
		if ((mode & 2) == 0) {
			header_add(headers, cd, value);
		} else {
			header_tryadd(headers, cd, value);
		}
		cd = eol + 1;
	}
	return 0;
}

char* serializeHeaders(struct headers* headers, size_t* len) {
	*len = 0;
	if (headers->count == 0) {
		return NULL;
	}
	for (int i = 0; i < headers->count; i++) {
		*len += strlen(headers->names[i]) + strlen(headers->values[i]) + 4;
	}
	(*len) += 2;
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
	return ret;
}

void freeHeaders(struct headers* headers) {
	if (headers->count > 0) for (int i = 0; i < headers->count; i++) {
		xfree(headers->names[i]);
		xfree(headers->values[i]);
	}
	if (headers->names != NULL) xfree(headers->names);
	if (headers->values != NULL) xfree(headers->values);
	xfree(headers);
}

int parseRequest(struct request* request, char* data, size_t maxPost) {
	request->atc = 0;
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
	request->headers = xmalloc(sizeof(struct headers));
	request->headers->count = 0;
	request->headers->names = NULL;
	request->headers->values = NULL;
	parseHeaders(request->headers, cd, 0);
	request->body = NULL;
	xfree(data);
	const char* cl = header_get(request->headers, "Content-Length");
	if (request->method == METHOD_POST && cl != NULL && strisunum(cl)) {
		long int cli = atol(cl);
		if (cli > 0 && (maxPost == 0 || cli < maxPost)) {
			request->body = xmalloc(sizeof(struct body));
			request->body->len = cli;
			request->body->data = xmalloc(cli);
			const char* tmp = header_get(request->headers, "Content-Type");
			request->body->mime_type = xstrdup(tmp == NULL ? "application/x-www-form-urlencoded" : tmp, 0);
			request->body->freeMime = 1;
			request->body->stream_fd = -1;
			request->body->stream_type = -1;
		}
	}
	return 0;
}

unsigned char* serializeRequest(struct reqsess* rs, size_t* len) {
	*len = 0;
	const char* ms = getMethod(rs->request->method);
	size_t vl = strlen(ms);
	size_t cl = strlen(rs->request->path);
	size_t rvl = strlen(rs->request->version);
	*len = vl + 1 + cl + 1 + rvl + 2;
	size_t hl = 0;
	char* headers = serializeHeaders(rs->request->headers, &hl);
	*len += hl;
	if (rs->response->body != NULL) *len += rs->response->body->len;
	unsigned char* ret = xmalloc(*len);
	size_t wr = 0;
	memcpy(ret, ms, vl);
	wr += vl;
	ret[wr++] = ' ';
	memcpy(ret + wr, rs->request->path, cl);
	wr += cl;
	ret[wr++] = ' ';
	memcpy(ret + wr, rs->request->version, rvl);
	wr += rvl;
	ret[wr++] = '\r';
	ret[wr++] = '\n';
	memcpy(ret + wr, headers, hl);
	wr += hl;
	xfree(headers);
	if (rs->request->method == METHOD_POST && rs->request->body != NULL) {
		memcpy(ret + wr, rs->response->body->data, rs->response->body->len);
		wr += rs->response->body->len;
	}
	return ret;
}

int parseResponse(struct reqsess* rs, char* data) {
	rs->response->parsed = 1;
	char* cd = data;
	char* eol1 = strchr(cd, '\n');
	if (eol1 == NULL) {
		errno = EINVAL;
		return -1;
	}
	eol1[0] = 0;
	char* hdrs = eol1 + 1;
	eol1 = strchr(cd, ' ');
	if (eol1 == NULL) {
		errno = EINVAL;
		return -1;
	}
	eol1[0] = 0;
	eol1++;
	rs->response->version = xstrdup(cd, 0);
	size_t eols = strlen(eol1);
	if (eol1[eols - 1] == '\r') eol1[eols - 1] = 0;
	rs->response->code = xstrdup(eol1, 0);
	parseHeaders(rs->response->headers, hdrs, 3);
	xfree(data);
	const char* cl = header_get(rs->response->headers, "Content-Length");
	if (cl != NULL && strisunum(cl)) {
		size_t cli = atol(cl);
		rs->response->body = xmalloc(sizeof(struct body));
		rs->response->body->len = cli;
		rs->response->body->data = NULL;
		rs->response->body->mime_type = header_get(rs->response->headers, "Content-Type");
		if (rs->response->body->mime_type == NULL) {
			rs->response->body->mime_type = xstrdup("text/html", 0);
			rs->response->body->freeMime = 1;
		} else rs->response->body->freeMime = 0;
		rs->response->body->stream_fd = rs->sender->fw_fd;
		rs->response->body->stream_type = 0;
	}
	const char* te = header_get(rs->response->headers, "Transfer-Encoding");
	if (te != NULL) {
		if (rs->response->body != NULL) xfree(rs->response->body);
		rs->response->body = xmalloc(sizeof(struct body));
		rs->response->body->len = 0;
		rs->response->body->data = NULL;
		rs->response->body->mime_type = header_get(rs->response->headers, "Content-Type");
		if (rs->response->body->mime_type == NULL) {
			rs->response->body->mime_type = xstrdup("text/html", 0);
			rs->response->body->freeMime = 1;
		} else rs->response->body->freeMime = 0;
		rs->response->body->freeMime = 0;
		rs->response->body->stream_fd = rs->sender->fw_fd;
		rs->response->body->stream_type = 1;
	}
	return 0;
}

unsigned char* serializeResponse(struct reqsess* rs, size_t* len) {
	*len = 0;
	size_t vl = strlen(rs->response->version);
	size_t cl = strlen(rs->response->code);
	*len = vl + 1 + cl + 2;
	size_t hl = 0;
	char* headers = serializeHeaders(rs->response->headers, &hl);
	*len += hl;
	if (rs->response->body != NULL && rs->response->body->stream_type < 0) *len += rs->response->body->len;
	unsigned char* ret = xmalloc(*len);
	size_t wr = 0;
	memcpy(ret, rs->response->version, vl);
	wr += vl;
	ret[wr++] = ' ';
	memcpy(ret + wr, rs->response->code, cl);
	wr += cl;
	ret[wr++] = '\r';
	ret[wr++] = '\n';
	memcpy(ret + wr, headers, hl);
	wr += hl;
	xfree(headers);
	if (rs->request->method != METHOD_HEAD && rs->response->body != NULL && rs->response->body->stream_type < 0) {
		memcpy(ret + wr, rs->response->body->data, rs->response->body->len);
		wr += rs->response->body->len;
	}
	return ret;
}

int generateDefaultErrorPage(struct reqsess* rs, struct vhost* vh, const char* msg) {
	if (rs->response->body == NULL) {
		rs->response->body = xmalloc(sizeof(struct body));
	}
	char* rmsg = escapehtml(msg);
	size_t ml = strlen(rmsg);
	size_t cl = strlen(rs->response->code);
	size_t len = 120 + ml + (2 * cl);
	rs->response->body->len = len;
	rs->response->body->mime_type = xstrdup("text/html", 0);
	rs->response->body->freeMime = 1;
	rs->response->body->stream_fd = -1;
	rs->response->body->stream_type = -1;
	rs->response->body->data = xmalloc(len);
	static char* d1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>";
	size_t d1s = strlen(d1);
	size_t wr = 0;
	memcpy(rs->response->body->data + wr, d1, d1s);
	wr += d1s;
	size_t cs = strlen(rs->response->code);
	memcpy(rs->response->body->data + wr, rs->response->code, cs);
	wr += cs;
	static char* d2 = "</title></head><body><h1>";
	size_t d2s = strlen(d2);
	memcpy(rs->response->body->data + wr, d2, d2s);
	wr += d2s;
	memcpy(rs->response->body->data + wr, rs->response->code, cs);
	wr += cs;
	static char* d3 = "</h1><p>";
	size_t d3s = strlen(d3);
	memcpy(rs->response->body->data + wr, d3, d3s);
	wr += d3s;
	memcpy(rs->response->body->data + wr, rmsg, ml);
	wr += ml;
	static char* d4 = "</p></body></html>";
	size_t d4s = strlen(d4);
	memcpy(rs->response->body->data + wr, d4, d4s);
	wr += d4s;
	free(rmsg);
	if (vh != NULL && vh->sub.htdocs.errpage_count > 0) {
		for (int i = 0; i < vh->sub.htdocs.errpage_count; i++) {
			if (strtol(rs->response->code, NULL, 10) == vh->sub.htdocs.errpages[i]->code) {
				header_add(rs->response->headers, "Location", vh->sub.htdocs.errpages[i]->page);
			}
		}
	}
	return 0;
}

int generateResponse(struct reqsess* rs) {
	int eh = 1;
	rs->response->parsed = 0;
	rs->response->version = rs->request->version;
	rs->response->code = "200 OK";
	rs->response->headers->count = 0;
	rs->response->headers->names = NULL;
	rs->response->headers->values = NULL;
	const char* host = header_get(rs->request->headers, "Host");
	if (host == NULL) host = "";
	struct vhost* vh = NULL;
	for (int i = 0; i < rs->wp->vhosts_count; i++) {
		if (rs->wp->vhosts[i]->host_count == 0) {
			vh = rs->wp->vhosts[i];
			break;
		} else for (int x = 0; x < rs->wp->vhosts[i]->host_count; x++) {
			if (domeq(rs->wp->vhosts[i]->hosts[x], host)) {
				vh = rs->wp->vhosts[i];
				break;
			}
		}
		if (vh != NULL) break;
	}
	rs->request->vhost = vh;
	jpvh: ;
	const char* upg = header_get(rs->request->headers, "Upgrade");
	if (!streq(rs->response->version, "HTTP/2.0")) {
		if (upg != NULL && streq(upg, "h2")) {
			//header_set(rs->response->headers, "Upgrade", "h2");
			//printf("upgrade: %s\n", header_get(rs->response->headers, "HTTP2-Settings"));
		}
	}
	header_add(rs->response->headers, "Server", "Avuna/" VERSION);
	rs->response->body = NULL;
	header_add(rs->response->headers, "Connection", "keep-alive");
	int rp = 0;
	if (vh == NULL) {
		rs->response->code = "500 Internal Server Error";
		generateDefaultErrorPage(rs, NULL, "There was no website found at this domain! If you believe this to be an error, please contact your system administrator.");
	} else if (vh->type == VHOST_HTDOCS || vh->type == VHOST_RPROXY) {
		char* extraPath = NULL;
		rp = vh->type == VHOST_RPROXY;
		int isStatic = 1;
		size_t htdl = rp ? 0 : strlen(vh->sub.htdocs.htdocs);
		size_t pl = strlen(rs->request->path);
		char* tp = xmalloc(htdl + pl);
		if (!rp) memcpy(tp, vh->sub.htdocs.htdocs, htdl);
		memcpy(tp + htdl, rs->request->path + 1, pl);
		tp[htdl + pl - 1] = 0;
		char* ttp = strchr(tp, '#');
		if (ttp != NULL) ttp[0] = 0;
		ttp = strchr(tp, '?');
		if (ttp != NULL) ttp[0] = 0;
		char* rtp = NULL;
		if (vh->sub.htdocs.scacheEnabled) {
			struct scache* osc = getSCache(&vh->sub.htdocs.cache, rs->request->path, contains_nocase(header_get(rs->request->headers, "Accept-Encoding"), "gzip"));
			if (osc != NULL) {
				rs->response->body = osc->body;
				if (rs->response->headers->count > 0) for (int i = 0; i < rs->response->headers->count; i++) {
					xfree(rs->response->headers->names[i]);
					xfree(rs->response->headers->values[i]);
				}
				rs->request->atc = 1;
				if (rs->response->headers->names != NULL) xfree(rs->response->headers->names);
				if (rs->response->headers->values != NULL) xfree(rs->response->headers->values);
				rs->response->headers->count = osc->headers->count;
				rs->response->headers->names = xcopy(osc->headers->names, osc->headers->count * sizeof(char*), 0);
				rs->response->headers->values = xcopy(osc->headers->values, osc->headers->count * sizeof(char*), 0);
				for (int i = 0; i < rs->response->headers->count; i++) {
					rs->response->headers->names[i] = xstrdup(rs->response->headers->names[i], 0);
					rs->response->headers->values[i] = xstrdup(rs->response->headers->values[i], 0);
				}
				rs->response->code = osc->code;
				if (rs->response->body != NULL && rs->response->body->len > 0 && rs->response->code != NULL && rs->response->code[0] == '2') {
					if (streq(osc->etag, header_get(rs->request->headers, "If-None-Match"))) {
						rs->response->code = "304 Not Modified";
						rs->response->body = NULL;
					}
				}
				goto pcacheadd;
			}
		}
		if (pl < 1 || rs->request->path[0] != '/') {
			rs->response->code = "500 Internal Server Error";
			generateDefaultErrorPage(rs, vh, "Malformed Request! If you believe this to be an error, please contact your system administrator.");
			goto epage;
		}
		//printf("ps %s\n", tp);
		int ff = !rp ? 0 : (pl > 1 && tp[htdl + pl - 2] != '/');
		if (!rp) {
			char* nxtp = xstrdup(tp + 1, 1);
			char* onx = nxtp;
			nxtp[strlen(nxtp) + 1] = 0;
			size_t nxtpl = strlen(nxtp);
			size_t lx = 0;
			for (size_t x = 0; x < nxtpl; x++) {
				if (nxtp[x] == '/') {
					nxtp[x] = 0;
					if (lx == x - 1) {
						memmove(nxtp + x, nxtp + x + 1, nxtpl - x);
					}
					lx = x;
				}
			}
			char* rstp = xmalloc(1);
			rstp[0] = 0;
			size_t cstp = 0;
			size_t extp = 0;
			size_t clt = 0;
			while ((clt = strlen(nxtp)) > 0) {
				if (ff) {
					if (extraPath == NULL) extraPath = xmalloc(extp + clt + 2);
					else extraPath = xrealloc(extraPath, extp + clt + 2);
					extraPath[extp++] = '/';
					memcpy(extraPath + extp, nxtp, clt + 1);
					extp += clt;
					nxtp += clt + 1;
				} else {
					rstp = xrealloc(rstp, cstp + clt + 2);
					rstp[cstp++] = '/';
					memcpy(rstp + cstp, nxtp, clt + 1);
					cstp += clt;
					nxtp += clt + 1;
					struct stat cs;
					if (stat(rstp, &cs) < 0) {
						if (errno == ENOENT || errno == ENOTDIR) {
							rs->response->code = "404 Not Found";
							generateDefaultErrorPage(rs, vh, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
						} else if (errno == EACCES) {
							rs->response->code = "403 Forbidden";
							generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
						} else {
							errlog(rs->wp->logsess, "Error while stating file: %s", strerror(errno));
							rs->response->code = "500 Internal Server Error";
							generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
						}
						goto epage;
					}
					if ((cs.st_mode & S_IFDIR) != S_IFDIR) {
						ff = 1;
					}
				}
			}
			if (!ff) {
				rstp = xrealloc(rstp, cstp + 2);
				rstp[cstp] = '/';
				rstp[cstp + 1] = 0;
			}
			xfree(onx);
			xfree(tp);
			tp = rstp;
		}
		int indf = 0;
		if (!rp && !ff && !access(tp, R_OK)) { // TODO: extra paths!
			for (int ii = 0; ii < vh->sub.htdocs.index_count; ii++) {
				size_t cl = strlen(vh->sub.htdocs.index[ii]);
				char* tp2 = xmalloc(htdl + pl + cl);
				size_t l2 = strlen(tp);
				memcpy(tp2, tp, l2);
				memcpy(tp2 + l2, vh->sub.htdocs.index[ii], cl + 1);
				if (!access(tp2, R_OK)) {
					xfree(tp);
					tp = tp2;
					indf = 1;
					break;
				} else {
					xfree(tp2);
				}
			}
		}
		if (!ff) {
			char* tt = xstrdup(rs->request->path, 2);
			char* ppl = strrchr(tt, '/'); // no extra path because extra paths dont work on directories
			//printf("%s\n", ppl);
			size_t ppll = strlen(ppl);
			/*for (size_t j = ppl - tt - 1; j >= 0; j--) {
			 if (ppl[j] == '/') {
			 ppl--;
			 ppll++;
			 j = 1;
			 } else break;
			 }*/
			if (ppl != NULL && (ppll > 1 && ppl[1] != '?' && ppl[1] != '#')) {
				rs->response->code = "302 Found";
				char* el = strpbrk(ppl, "?#");
				if (el != NULL) {
					memmove(el, el + 1, strlen(el) + 1);
					el[0] = '/';
				} else {
					size_t ttl = strlen(tt);
					tt[ttl] = '/';
					tt[ttl + 1] = 0;
				}
				header_add(rs->response->headers, "Location", tt);
				xfree(tp);
				xfree(tt);
				xfree(extraPath);
				goto pvh;
			}
			xfree(tt);
			if (!indf) {
				rs->response->code = "404 Not Found";
				generateDefaultErrorPage(rs, vh, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
		}
		//TODO: overrides
		struct stat st;
		if (rp) {
			rtp = tp;
			tp = NULL;
		} else {
			rtp = realpath(tp, NULL);
			xfree(tp);
			tp = NULL;
			if (rtp == NULL) {
				if (errno == ENOENT || errno == ENOTDIR) {
					rs->response->code = "404 Not Found";
					generateDefaultErrorPage(rs, vh, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
				} else if (errno == EACCES) {
					rs->response->code = "403 Forbidden";
					generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
				} else {
					errlog(rs->wp->logsess, "Error while getting the realpath of a file: %s", strerror(errno));
					rs->response->code = "500 Internal Server Error";
					generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
				}
				goto epage;
			}
			if (stat(rtp, &st) != 0) {
				errlog(rs->wp->logsess, "Failed stat on <%s>: %s", rtp, strerror(errno));
				rs->response->code = "500 Internal Server Error";
				generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
			size_t rtpl = strlen(rtp);
			if ((st.st_mode & S_IFDIR) && rtp[rtpl - 1] != '/') {
				rtp = xrealloc(rtp, ++rtpl + 1);
				rtp[rtpl - 1] = '/';
				rtp[rtpl] = 0;
			}
			if (vh->sub.htdocs.symlock && !startsWith(rtp, vh->sub.htdocs.htdocs)) {
				rs->response->code = "404 Not Found";
				generateDefaultErrorPage(rs, vh, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
			if (vh->sub.htdocs.nohardlinks && st.st_nlink != 1 && !(st.st_mode & S_IFDIR)) {
				rs->response->code = "403 Forbidden";
				generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
		}
		if (rp) {
			//printf("-1 %16lX\n", rs->response);
			resrp: if (rs->sender->fw_fd < 0) {
				rs->sender->fw_fd = socket(vh->sub.rproxy.fwaddr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
				if (rs->sender->fw_fd < 0 || connect(rs->sender->fw_fd, vh->sub.rproxy.fwaddr, vh->sub.rproxy.fwaddrlen) < 0) {
					errlog(rs->wp->logsess, "Failed to create/connect to forwarding socket: %s", strerror(errno));
					rs->response->code = "500 Internal Server Error";
					generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
					goto epage;
				}
			}
			size_t sreql = 0;
			unsigned char* sreq = serializeRequest(rs, &sreql);
			size_t wr = 0;
			while (wr < sreql) {
				int x = write(rs->sender->fw_fd, sreq + wr, sreql - wr);
				if (x < 1) {
					close(rs->sender->fw_fd);
					rs->sender->fw_fd = -1;
					goto resrp;
				}
				wr += x;
			}
			xfree(sreq);
			if (rs->sender->fwqueue == NULL) {
				rs->sender->fwqueue = new_queue(0, 1);
			}
			rs->sender->fwed = 1;
			eh = 0;
			struct reqsess* rs2 = xmalloc(sizeof(struct reqsess));
			memcpy(rs2, rs, sizeof(struct reqsess));
			//printf("1 %16lX vs %16lX\n", rs2, rs);
			//printf("2 %16lX vs %16lX\n", rs2->response, rs->response);
			add_queue(rs->sender->fwqueue, rs2);
		} else {
			rs->response->body = xmalloc(sizeof(struct body));
			rs->response->body->len = 0;
			rs->response->body->data = NULL;
			const char* ext = strrchr(rtp, '.');
			if (ext == NULL) {
				rs->response->body->mime_type = xstrdup("application/octet-stream", 0);
				rs->response->body->freeMime = 1;
			} else {
				const char* mime = getMimeForExt(ext + 1);
				if (mime == NULL) {
					rs->response->body->mime_type = xstrdup("application/octet-stream", 0);
					rs->response->body->freeMime = 1;
				} else {
					rs->response->body->mime_type = xstrdup(mime, 0);
					rs->response->body->freeMime = 1;
				}
			}
			rs->response->body->stream_fd = -1;
			rs->response->body->stream_type = -1;
		}
		if (!rp && rs->response->body != NULL && rs->response->body->mime_type != NULL) for (int i = 0; i < vh->sub.htdocs.fcgi_count; i++) {
			struct fcgi* fcgi = vh->sub.htdocs.fcgis[i];
			int df = 0;
			for (int m = 0; m < fcgi->mime_count; m++) {
				char* mime = fcgi->mimes[m];
				if (streq_nocase(mime, rs->response->body->mime_type)) {
					df = 1;
					break;
				}
			}
			if (df) {
				isStatic = 0;
				int fc = 0;
				int* ffdl = &vh->sub.htdocs.fcgifds[rs->wp->i][i];
				if (*ffdl >= 0) goto pfcgix;
				sofcgi: ;
				//printf("%i, %i\n", rs->wp->i, i);
				//int ffd = vh->sub.htdocs.fcgifds[rs->wp->i][i];
				*ffdl = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
				if (*ffdl < 0) {
					errlog(rs->wp->logsess, "Error creating socket for FCGI Server! %s", strerror(errno));
					rs->response->code = "500 Internal Server Error";
					generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
					//if (ff.data != NULL) xfree(ff.data);
					*ffdl = -1;
					goto epage;
				}
				if (connect(*ffdl, fcgi->addr, fcgi->addrlen)) {
					errlog(rs->wp->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
					rs->response->code = "500 Internal Server Error";
					generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
					//if (ff.data != NULL) xfree(ff.data);
					close(*ffdl);
					*ffdl = -1;
					goto epage;
				}
				pfcgix: ;
				//printf("starting req on fd #%i\n", *ffdl);
				//printf("begin fcgi on %i\n", ffd);
				struct fcgiframe ff;
				ff.type = FCGI_BEGIN_REQUEST;
				ff.reqID = fcgi->gc++ % 65535;
				if (fcgi->gc > 65535) fcgi->gc = 0;
				//printf("nreqid %i\n", ff.reqID);
				ff.len = 8;
				unsigned char pkt[8];
				pkt[0] = 0;
				pkt[1] = 1;
				pkt[2] = 1;
				memset(pkt + 3, 0, 5);
				ff.data = pkt;
				if (writeFCGIFrame(*ffdl, &ff)) {
					errlog(rs->wp->logsess, "Failed to write to FCGI Server! File: %s Error: %s, restarting connection!", rtp, strerror(errno));
					close(*ffdl);
					*ffdl = -1;
					if (fc > 0) {
						errlog(rs->wp->logsess, "Connection failed restart, perhaps FCGI server is down?");
						rs->response->code = "500 Internal Server Error";
						generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
						goto epage;
					}
					*ffdl = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
					if (*ffdl < 0) {
						errlog(rs->wp->logsess, "Error creating socket for FCGI Server! %s", strerror(errno));
						rs->response->code = "500 Internal Server Error";
						generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
						*ffdl = -1;
						goto epage;
					}
					if (connect(*ffdl, fcgi->addr, fcgi->addrlen)) {
						errlog(rs->wp->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
						close(*ffdl);
						*ffdl = -1;
						rs->response->code = "500 Internal Server Error";
						generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
						goto epage;
					}
					fc++;
					goto sofcgi;
				}
				int ffd = *ffdl;
				//TODO: SERVER_ADDR
				char* rq = xstrdup(rs->request->path, 0);
				{
					char* ht = strchr(rq, '#');
					if (ht != NULL) ht[0] = 0;
				}
				char* get = strchr(rq, '?');
				if (get != NULL) {
					get[0] = 0;
					get++;
				} else {
					get = "";
				}
				writeFCGIParam(ffd, ff.reqID, "REQUEST_URI", rs->request->path);
				char cl[16];
				if (rs->request->body != NULL) {
					snprintf(cl, 16, "%i", rs->request->body->len);
				} else {
					cl[0] = '0';
					cl[1] = 0;
				}
				writeFCGIParam(ffd, ff.reqID, "CONTENT_LENGTH", cl);
				if (rs->request->body != NULL && rs->request->body->mime_type != NULL) writeFCGIParam(ffd, ff.reqID, "CONTENT_TYPE", rs->request->body->mime_type);
				writeFCGIParam(ffd, ff.reqID, "GATEWAY_INTERFACE", "CGI/1.1");
				writeFCGIParam(ffd, ff.reqID, "PATH", getenv("PATH"));
				writeFCGIParam(ffd, ff.reqID, "QUERY_STRING", get);
				{
					char tip[48];
					char* mip = tip;
					if (rs->sender->addr.sin6_family == AF_INET) {
						struct sockaddr_in *sip4 = (struct sockaddr_in*) &rs->sender->addr;
						inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
					} else if (rs->sender->addr.sin6_family == AF_INET6) {
						struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &rs->sender->addr;
						if (memseq((unsigned char*) &sip6->sin6_addr, 10, 0) && memseq((unsigned char*) &sip6->sin6_addr + 10, 2, 0xff)) {
							inet_ntop(AF_INET, ((unsigned char*) &sip6->sin6_addr) + 12, tip, 48);
						} else inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
					} else if (rs->sender->addr.sin6_family == AF_LOCAL) {
						mip = "UNIX";
					} else {
						mip = "UNKNOWN";
					}
					if (mip == NULL) mip = "INVALID";
					writeFCGIParam(ffd, ff.reqID, "REMOTE_ADDR", mip);
					writeFCGIParam(ffd, ff.reqID, "REMOTE_HOST", mip);
				}
				if (rs->sender->addr.sin6_family == AF_INET) {
					snprintf(cl, 16, "%i", ntohs(((struct sockaddr_in*) &rs->sender->addr)->sin_port));
				} else if (rs->sender->addr.sin6_family == AF_INET6) {
					snprintf(cl, 16, "%i", ntohs(((struct sockaddr_in6*) &rs->sender->addr)->sin6_port));
				} else {
					cl[0] = '0';
					cl[1] = 0;
				}
				writeFCGIParam(ffd, ff.reqID, "REMOTE_PORT", cl);
				if (extraPath != NULL) {
					writeFCGIParam(ffd, ff.reqID, "PATH_INFO", extraPath);
					size_t epl = strlen(extraPath);
					char* trns = xmalloc(htdl + epl);
					memcpy(trns, vh->sub.htdocs.htdocs, htdl);
					memcpy(trns + htdl, extraPath + 1, epl);
					trns[htdl + epl - 1] = 0;
					writeFCGIParam(ffd, ff.reqID, "PATH_TRANSLATED", trns);
					xfree(trns);
				} else {
					writeFCGIParam(ffd, ff.reqID, "PATH_INFO", "");
					writeFCGIParam(ffd, ff.reqID, "PATH_TRANSLATED", "");
				}
				writeFCGIParam(ffd, ff.reqID, "REQUEST_METHOD", getMethod(rs->request->method));
				char rss[4];
				rss[3] = 0;
				memcpy(rss, rs->response->code, 3);
				writeFCGIParam(ffd, ff.reqID, "REDIRECT_STATUS", rss);
				size_t htl = strlen(vh->sub.htdocs.htdocs);
				int htes = vh->sub.htdocs.htdocs[htl - 1] == '/';
				size_t rtpl = strlen(rtp);
				if (rtpl < htl) errlog(rs->wp->logsess, "Setting FCGI SCRIPT_NAME requires the file to be in htdocs! @ %s", rtp);
				else writeFCGIParam(ffd, ff.reqID, "SCRIPT_NAME", rtp + htl + (htes ? -1 : 0));
				if (host != NULL) writeFCGIParam(ffd, ff.reqID, "SERVER_NAME", host);
				snprintf(cl, 16, "%i", rs->wp->sport);
				writeFCGIParam(ffd, ff.reqID, "SERVER_PORT", cl);
				writeFCGIParam(ffd, ff.reqID, "SERVER_PROTOCOL", rs->request->version);
				writeFCGIParam(ffd, ff.reqID, "SERVER_SOFTWARE", "Avuna/" VERSION);
				writeFCGIParam(ffd, ff.reqID, "DOCUMENT_ROOT", vh->sub.htdocs.htdocs);
				writeFCGIParam(ffd, ff.reqID, "SCRIPT_FILENAME", rtp);
				for (int i = 0; i < rs->request->headers->count; i++) {
					const char* name = rs->request->headers->names[i];
					if (streq_nocase(name, "Accept-Encoding")) continue;
					const char* value = rs->request->headers->values[i];
					size_t nl = strlen(name);
					char nname[nl + 6];
					nname[0] = 'H';
					nname[1] = 'T';
					nname[2] = 'T';
					nname[3] = 'P';
					nname[4] = '_';
					memcpy(nname + 5, name, nl + 1);
					nl += 5;
					for (int x = 5; x < nl; x++) {
						if (nname[x] >= 'a' && nname[x] <= 'z') nname[x] -= ' ';
						else if (nname[x] == '-') nname[x] = '_';
					}
					writeFCGIParam(ffd, ff.reqID, nname, value);
				}
				ff.type = FCGI_PARAMS;
				ff.len = 0;
				ff.data = NULL;
				writeFCGIFrame(ffd, &ff);
				ff.type = FCGI_STDIN;
				if (rs->request->body != NULL && rs->request->body->len > 0) {
					size_t cr = 0;
					size_t left = rs->request->body->len;
					while (left > 0) {
						ff.len = left > 0xFFFF ? 0xFFFF : left;
						ff.data = rs->request->body->data + cr;
						cr += ff.len;
						left -= ff.len;
						writeFCGIFrame(ffd, &ff);
					}
				}
				ff.len = 0;
				writeFCGIFrame(ffd, &ff);
				if (rs->response->body != NULL) {
					xfree(rs->response->body->data);
					xfree(rs->response->body);
					rs->response->body = NULL;
				}
				xfree(rq);
				char* ct = NULL;
				int hd = 0;
				char* hdd = NULL;
				size_t hddl = 0;
				int eid = ff.reqID;
				//printf("read fcgi on %i\n", ffd);
				while (ff.type != FCGI_END_REQUEST) {
					if (readFCGIFrame(ffd, &ff)) {
						errlog(rs->wp->logsess, "Error reading from FCGI server: %s", strerror(errno));
						close(*ffdl);
						*ffdl = -1;
						if (fc > 0) {
							errlog(rs->wp->logsess, "Connection failed restart, perhaps FCGI server is down?");
							rs->response->code = "500 Internal Server Error";
							generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
							//if (ff.data != NULL) xfree(ff.data);
							goto epage;
						}
						*ffdl = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
						if (*ffdl < 0) {
							errlog(rs->wp->logsess, "Error creating socket for FCGI Server! %s", strerror(errno));
							rs->response->code = "500 Internal Server Error";
							generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
							//if (ff.data != NULL) xfree(ff.data);
							*ffdl = -1;
							goto epage;
						}
						if (connect(*ffdl, fcgi->addr, fcgi->addrlen)) {
							errlog(rs->wp->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
							rs->response->code = "500 Internal Server Error";
							generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
							//if (ff.data != NULL) xfree(ff.data);
							close(*ffdl);
							*ffdl = -1;
							goto epage;
						}
						fc++;
						goto sofcgi;
					}
					if (ff.reqID != eid) {
						//printf("unx id %i wanted: %i\n", ff.reqID, eid);
						if (ff.type == FCGI_END_REQUEST) {
							ff.type = FCGI_STDERR;
							//printf("rewr\n");
						}
						continue;
					}
					//printf("recv %i\n", ff.type);
					if (ff.type == FCGI_END_REQUEST) {
						//printf("er!\n");
						xfree(ff.data);
						continue;
					}
					if (ff.type == FCGI_STDERR) {
						errlog(rs->wp->logsess, "FCGI STDERR <%s>: %s", rtp, ff.data);
					}
					if (ff.type == FCGI_STDOUT || ff.type == FCGI_STDERR) {
						int hr = 0;
						if (!hd && ff.type == FCGI_STDOUT) {
							int ml = 0;
							char* tm = "\r\n\r\n";
							for (int i = 0; i < ff.len; i++) {
								if (((char*) ff.data)[i] == tm[ml]) {
									ml++;
									if (ml == 4) {
										hd = 1;
										hr = i + 1;
										if (hdd == NULL) {
											hdd = xmalloc(i + 1);
											hdd[i] = 0;
											memcpy(hdd, ff.data, i);
											hddl = i;
										} else {
											hdd = xrealloc(hdd, hddl + i + 1);
											hdd[hddl + i] = 0;
											memcpy(hdd + hddl, ff.data, i);
											hddl += i;
										}
										break;
									}
								} else ml = 0;
							}
							if (!hd) {
								hr = ff.len;
								if (hdd == NULL) {
									hdd = xmalloc(ff.len);
									hdd[ff.len] = 0;
									memcpy(hdd, ff.data, ff.len);
									hddl = ff.len;
								} else {
									hdd = xrealloc(hdd, hddl + ff.len);
									hdd[hddl + ff.len] = 0;
									memcpy(hdd + hddl, ff.data, ff.len);
									hddl += ff.len;
								}
							}
						}
						//printf("%lu\n", ff.len);
						if (hd == 1 && ff.type == FCGI_STDOUT) {
							hd = 2;
							struct headers hdrs;
							parseHeaders(&hdrs, hdd, 0);
							for (int i = 0; i < hdrs.count; i++) {
								const char* name = hdrs.names[i];
								const char* value = hdrs.values[i];
								if (streq_nocase(name, "Content-Type")) {
									if (ct != NULL) xfree(ct);
									ct = xstrdup(value, 0);
								} else if (streq_nocase(name, "Status")) {
									if (!rs->response->parsed) {
										rs->response->parsed = 2;
									} else {
										xfree(rs->response->code);
									}
									rs->response->code = xstrdup(value, 0);
								} else if (streq_nocase(name, "ETag")) {

								} else header_add(rs->response->headers, name, value);
							}
						}
						//printf("hr %i, fflem %i\n", hr, ff.len);
						if (hr <= ff.len) {
							unsigned char* ffd = ff.data + hr;
							ff.len -= hr;
							if (rs->response->body == NULL) {
								rs->response->body = xmalloc(sizeof(struct body));
								rs->response->body->data = xmalloc(ff.len);
								memcpy(rs->response->body->data, ffd, ff.len);
								rs->response->body->len = ff.len;
								rs->response->body->mime_type = ct == NULL ? xstrdup("text/html", 0) : ct;
								rs->response->body->freeMime = 1;
								rs->response->body->stream_fd = -1;
								rs->response->body->stream_type = -1;
							} else {
								rs->response->body->len += ff.len;
								rs->response->body->data = xrealloc(rs->response->body->data, rs->response->body->len);
								memcpy(rs->response->body->data + rs->response->body->len - ff.len, ffd, ff.len);
							}
						}
					}
					xfree(ff.data);
				}
				//printf("end fcgi on %i\n", ffd);
				//close(ffd);
				//printf("ending req on fd #%i appStatus: %i, protocolStatus: %i\n", *ffdl, *((int32_t*) (ff.data)), *((int8_t*) (ff.data) + 4));
				//*ffdl = -1;

			}
		}
		if (isStatic) {
			if (vh->sub.htdocs.maxAge > 0 && rs->response->body != NULL) {
				int dcc = 0;
				for (int i = 0; i < vh->sub.htdocs.cacheType_count; i++) {
					if (streq_nocase(vh->sub.htdocs.cacheTypes[i], rs->response->body->mime_type)) {
						dcc = 1;
						break;
					} else if (endsWith(vh->sub.htdocs.cacheTypes[i], "/*")) {
						char* nct = xstrdup(vh->sub.htdocs.cacheTypes[i], 0);
						nct[strlen(nct) - 1] = 0;
						if (startsWith(rs->response->body->mime_type, nct)) {
							dcc = 1;
							xfree(nct);
							break;
						}
						xfree(nct);
					}
				}

				char ccbuf[64];
				memcpy(ccbuf, "max-age=", 8);
				int snr = snprintf(ccbuf + 8, 18, "%lu", vh->sub.htdocs.maxAge);
				if (dcc) {
					memcpy(ccbuf + 8 + snr, ", no-cache", 11);
				} else {
					ccbuf[8 + snr] = 0;
				}
				header_add(rs->response->headers, "Cache-Control", ccbuf);
			}
		}
		if (!rp && isStatic) {
			int ffd = open(rtp, O_RDONLY);
			if (ffd < 0) {
				errlog(rs->wp->logsess, "Failed to open file %s! %s", rtp, strerror(errno));
				rs->response->code = "500 Internal Server Error";
				generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
			rs->response->body->data = xmalloc(st.st_size);
			int r = 0;
			while ((r = read(ffd, rs->response->body->data + rs->response->body->len, st.st_size - rs->response->body->len)) > 0) {
				rs->response->body->len += r;
			}
			if (r < 0) {
				errlog(rs->wp->logsess, "Failed to read file %s! %s", rtp, strerror(errno));
				rs->response->code = "500 Internal Server Error";
				generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
		}
		//TODO: CGI
		//TODO: SCGI
		//TODO: SO-CGI
		//TODO: SSI
		epage: ;
		char etag[35];
		int hetag = 0;
		int nm = 0;
		if (!rp && rs->response->body != NULL && rs->response->body->len > 0 && rs->response->code != NULL && rs->response->code[0] == '2') {
			MD5_CTX md5ctx;
			MD5_Init(&md5ctx);
			MD5_Update(&md5ctx, rs->response->body->data, rs->response->body->len);
			unsigned char rawmd5[16];
			MD5_Final(rawmd5, &md5ctx);
			hetag = 1;
			etag[34] = 0;
			etag[0] = '\"';
			for (int i = 0; i < 16; i++) {
				snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
			}
			etag[33] = '\"';
			header_add(rs->response->headers, "ETag", etag);
			if (streq(etag, header_get(rs->request->headers, "If-None-Match"))) {
				nm = 1;
				if (!isStatic) {
					rs->response->code = "304 Not Modified";
					xfree(rs->response->body->data);
					xfree(rs->response->body);
					rs->response->body = NULL;
				}
			}
		}
		const char* cce = header_get(rs->response->headers, "Content-Encoding");
		int wgz = streq(cce, "gzip");
		if (rs->response->body != NULL && rs->response->body->len > 1024 && cce == NULL) {
			const char* accenc = header_get(rs->request->headers, "Accept-Encoding");
			if (contains_nocase(accenc, "gzip")) {
				z_stream strm;
				strm.zalloc = Z_NULL;
				strm.zfree = Z_NULL;
				strm.opaque = Z_NULL;
				int dr = 0;
				if ((dr = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY)) != Z_OK) { // TODO: configurable level?
					errlog(rs->wp->logsess, "Error with zlib defaultInit: %i", dr);
					goto pgzip;
				}
				strm.avail_in = rs->response->body->len;
				strm.next_in = rs->response->body->data;
				void* cdata = xmalloc(16384);
				size_t ts = 0;
				size_t cc = 16384;
				strm.avail_out = cc - ts;
				strm.next_out = cdata + ts;
				do {
					strm.avail_out = cc - ts;
					strm.next_out = cdata + ts;
					dr = deflate(&strm, Z_FINISH);
					ts = strm.total_out;
					if (ts >= cc - 8192) {
						cc = ts + 16384;
						cdata = xrealloc(cdata, cc);
					}
					if (dr == Z_STREAM_ERROR) {
						xfree(cdata);
						errlog(rs->wp->logsess, "Stream error with zlib deflate");
						goto pgzip;
					}
				} while (strm.avail_out == 0);
				deflateEnd(&strm);
				xfree(rs->response->body->data);
				cdata = xrealloc(cdata, ts); // shrink
				rs->response->body->data = cdata;
				rs->response->body->len = ts;
				header_add(rs->response->headers, "Content-Encoding", "gzip");
				header_add(rs->response->headers, "Vary", "Accept-Encoding");
				wgz = 1;
			}
		}
		pgzip: if (isStatic && vh->sub.htdocs.scacheEnabled && (vh->sub.htdocs.maxCache <= 0 || vh->sub.htdocs.maxCache < getCacheSize(&vh->sub.htdocs.cache))) {
			if (rp) {
				rs->request->atc = 1;
			} else {
				struct scache* sc = xmalloc(sizeof(struct scache));
				sc->body = rs->response->body;
				sc->ce = wgz;
				sc->code = rs->response->code;
				if (eh) {
					if (rs->response->body != NULL) header_setoradd(rs->response->headers, "Content-Type", rs->response->body->mime_type);
					char l[16];
					if (rs->response->body != NULL) sprintf(l, "%u", (unsigned int) rs->response->body->len);
					header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
				}
				sc->headers = rs->response->headers;
				sc->rp = rs->request->path;
				if (!hetag) {
					if (rs->response->body == NULL) {
						hetag = 1;
						etag[0] = '\"';
						memset(etag + 1, '0', 32);
						etag[33] = '\"';
						etag[34] = 0;
					} else {
						MD5_CTX md5ctx;
						MD5_Init(&md5ctx);
						MD5_Update(&md5ctx, rs->response->body->data, rs->response->body->len);
						unsigned char rawmd5[16];
						MD5_Final(rawmd5, &md5ctx);
						hetag = 1;
						etag[34] = 0;
						etag[0] = '\"';
						for (int i = 0; i < 16; i++) {
							snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
						}
						etag[33] = '\"';
					}
				}
				memcpy(sc->etag, etag, 35);
				addSCache(&vh->sub.htdocs.cache, sc);
				rs->response->fromCache = sc;
				rs->request->atc = 1;
				if (nm) {
					rs->response->body = NULL;
					rs->response->code = "304 Not Modified";
				}
			}
		}
		pcacheadd:
		//TODO: Chunked
		if (extraPath != NULL) xfree(extraPath);
		if (rtp != NULL) xfree(rtp);
	} else if (vh->type == VHOST_REDIRECT) {
		rs->response->code = "302 Found";
		header_add(rs->response->headers, "Location", vh->sub.redirect.redir);
	} else if (vh->type == VHOST_MOUNT) {
		struct vhost_mount* vhm = &vh->sub.mount;
		char* oid = vh->id;
		char* orq = rs->request->path;
		vh = NULL;
		for (int i = 0; i < vhm->vhm_count; i++) {
			if (startsWith(rs->request->path, vhm->vhms[i].path)) {
				for (int x = 0; x < rs->wp->vhosts_count; x++) {
					if (streq_nocase(vhm->vhms[i].vh, rs->wp->vhosts[x]->id) && !streq_nocase(rs->wp->vhosts[x]->id, oid)) {
						if (!vhm->keep_prefix) {
							size_t vhpls = strlen(vhm->vhms[i].path);
							char* tmpp = xstrdup(orq, 0);
							char* tmpp2 = tmpp + vhpls;
							if (tmpp2[0] != '/') {
								tmpp2--;
								tmpp2[0] = '/';
							}
							rs->request->path = xstrdup(tmpp2, 0);
							xfree(tmpp);
						}
						vh = rs->wp->vhosts[x];
						rs->request->vhost = rs->wp->vhosts[x];
						break;
					}
				}
				if (vh != NULL) break;
			}
		}
		if (orq != rs->request->path) xfree(orq);
		goto jpvh;
	}
	pvh:
//body stuff
	if (eh && !rp && rs->response->body != NULL && rs->response->body->mime_type != NULL) {
		header_setoradd(rs->response->headers, "Content-Type", rs->response->body->mime_type);
	}
	if (eh && !rp) {
		char l[16];
		if (rs->response->body != NULL) sprintf(l, "%u", (unsigned int) rs->response->body->len);		//TODO: might be a size limit here
		header_setoradd(rs->response->headers, "Content-Length", rs->response->body == NULL ? "0" : l);
	}
	return 0;
}
