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
#include <nettle/md5.h>
#include <zlib.h>
#include "cache.h"
#include "fcgi.h"
#include <netinet/in.h>

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
			int vl = strlen(value) + 1;
			headers->values[i] = xrealloc(headers->values[i], vl);
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

int header_setoradd(struct headers* headers, const char* name, const char* value) {
	int r = 0;
	if (!(r = header_set(headers, name, value))) r = header_add(headers, name, value);
	return r;
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
	parseHeaders(request->headers, cd);
	request->body = NULL;
	xfree(data);
	char* cl = header_get(request->headers, "Content-Length");
	if (request->method == METHOD_POST && cl != NULL && strisunum(cl)) {
		long int cli = atol(cl);
		if (maxPost == 0 || cli < maxPost) {
			request->body = xmalloc(sizeof(struct body));
			request->body->len = cli;
			request->body->data = xmalloc(cli);
			request->body->mime_type = "application/x-www-form-urlencoded";
			request->body->freeMime = 0;
		}
	}
	return 0;
}

unsigned char* serializeRequest(struct request* request, size_t* len) {

}

int parseResponse(struct response* response, char* data) {

	xfree(data);
	return 0;
}

unsigned char* serializeResponse(struct reqsess rs, size_t* len) {
	*len = 0;
	size_t vl = strlen(rs.response->version);
	size_t cl = strlen(rs.response->code);
	*len = vl + 1 + cl + 2;
	size_t hl = 0;
	char* headers = serializeHeaders(rs.response->headers, &hl);
	*len += hl;
	if (rs.response->body != NULL) *len += rs.response->body->len;
	unsigned char* ret = xmalloc(*len);
	size_t wr = 0;
	memcpy(ret, rs.response->version, vl);
	wr += vl;
	ret[wr++] = ' ';
	memcpy(ret + wr, rs.response->code, cl);
	wr += cl;
	ret[wr++] = '\r';
	ret[wr++] = '\n';
	memcpy(ret + wr, headers, hl);
	wr += hl;
	xfree(headers);
	if (rs.request->method != METHOD_HEAD && rs.response->body != NULL) {
		memcpy(ret + wr, rs.response->body->data, rs.response->body->len);
		wr += rs.response->body->len;
	}
	return ret;
}

int generateDefaultErrorPage(struct reqsess rs, struct vhost* vh, const char* msg) {
	if (rs.response->body == NULL) {
		rs.response->body = xmalloc(sizeof(struct body));
	}
	rs.response->body->mime_type = "text/html";
	rs.response->body->freeMime = 0;
	char* rmsg = escapehtml(msg);
	size_t ml = strlen(rmsg);
	size_t cl = strlen(rs.response->code);
	size_t len = 120 + ml + (2 * cl);
	rs.response->body->len = len;
	rs.response->body->mime_type = "text/html";
	rs.response->body->data = xmalloc(len);
	static char* d1 = "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>";
	size_t d1s = strlen(d1);
	size_t wr = 0;
	memcpy(rs.response->body->data + wr, d1, d1s);
	wr += d1s;
	size_t cs = strlen(rs.response->code);
	memcpy(rs.response->body->data + wr, rs.response->code, cs);
	wr += cs;
	static char* d2 = "</title></head><body><h1>";
	size_t d2s = strlen(d2);
	memcpy(rs.response->body->data + wr, d2, d2s);
	wr += d2s;
	memcpy(rs.response->body->data + wr, rs.response->code, cs);
	wr += cs;
	static char* d3 = "</h1><p>";
	size_t d3s = strlen(d3);
	memcpy(rs.response->body->data + wr, d3, d3s);
	wr += d3s;
	memcpy(rs.response->body->data + wr, rmsg, ml);
	wr += ml;
	static char* d4 = "</p></body></html>";
	size_t d4s = strlen(d4);
	memcpy(rs.response->body->data + wr, d4, d4s);
	wr += d4s;
	free(rmsg);
	if (vh != NULL && vh->sub.htdocs.errpage_count > 0) {
		for (int i = 0; i < vh->sub.htdocs.errpage_count; i++) {
			if (startsWith_nocase(rs.response->code, vh->sub.htdocs.errpages[i]->code)) {
				header_add(rs.response->headers, "Location", vh->sub.htdocs.errpages[i]->page);
			}
		}
	}
	return 0;
}

int generateResponse(struct reqsess rs) {
	rs.response->version = "HTTP/1.1";
	rs.response->code = "200 OK";
	rs.response->headers->count = 0;
	rs.response->headers->names = NULL;
	rs.response->headers->values = NULL;
	const char* host = header_get(rs.request->headers, "Host");
	if (host == NULL) host = "";
	struct vhost* vh = NULL;
	int vhi = -1;
	for (int i = 0; i < rs.wp->vhosts_count; i++) {
		if (rs.wp->vhosts[i]->host_count == 0) {
			vh = rs.wp->vhosts[i];
			vhi = i;
			break;
		} else for (int x = 0; x < rs.wp->vhosts[i]->host_count; x++) {
			if (streq_nocase(rs.wp->vhosts[i]->hosts[x], host)) {
				vh = rs.wp->vhosts[i];
				vhi = i;
				break;
			}
		}
		if (vh != NULL) break;
	}
	char svr[16];
	strcpy(svr, "Avuna/");
	strcat(svr, VERSION);
	header_add(rs.response->headers, "Server", svr);
	rs.response->body = NULL;
	header_add(rs.response->headers, "Connection", "keep-alive");
	if (vh == NULL) {
		rs.response->code = "500 Internal Server Error";
		generateDefaultErrorPage(rs, NULL, "There was no website found at this domain! If you believe this to be an error, please contact your system administrator.");
	} else if (vh->type == VHOST_HTDOCS) {
		int isStatic = 1;
		size_t htdl = strlen(vh->sub.htdocs.htdocs);
		size_t pl = strlen(rs.request->path);
		char* tp = xmalloc(htdl + pl);
		memcpy(tp, vh->sub.htdocs.htdocs, htdl);
		memcpy(tp + htdl, rs.request->path + 1, pl);
		tp[htdl + pl - 1] = 0;
		char* ttp = strchr(tp, '#');
		if (ttp != NULL) ttp[0] = 0;
		ttp = strchr(tp, '?');
		if (ttp != NULL) ttp[0] = 0;
		char* rtp = NULL;
		struct scache* osc = getSCache(&vh->sub.htdocs.cache, rs.request->path, contains_nocase(header_get(rs.request->headers, "Accept-Encoding"), "gzip"));
		if (osc != NULL) {
			rs.response->atc = 1;
			rs.response->body = osc->body;
			if (rs.response->headers->count > 0) for (int i = 0; i < rs.response->headers->count; i++) {
				xfree(rs.response->headers->names[i]);
				xfree(rs.response->headers->values[i]);
			}
			if (rs.response->headers->names != NULL) xfree(rs.response->headers->names);
			if (rs.response->headers->values != NULL) xfree(rs.response->headers->values);
			rs.response->headers->count = osc->headers->count;
			rs.response->headers->names = xcopy(osc->headers->names, osc->headers->count * sizeof(char*), 0);
			rs.response->headers->values = xcopy(osc->headers->values, osc->headers->count * sizeof(char*), 0);
			rs.response->code = osc->code;
			if (rs.response->body != NULL && rs.response->body->len > 0 && rs.response->code != NULL && rs.response->code[0] == '2') {
				if (streq(osc->etag, header_get(rs.request->headers, "If-None-Match"))) {
					rs.response->code = "304 Not Modified";
					rs.response->body = NULL;
				}
			}
			goto pcacheadd;
		}
		if (pl < 1 || rs.request->path[0] != '/') {
			rs.response->code = "500 Internal Server Error";
			generateDefaultErrorPage(rs, vh, "Malformed Request! If you believe this to be an error, please contact your system administrator.");
			goto epage;
		}
		if (tp[htdl + pl - 2] == '/' && !access(tp, R_OK)) { // TODO: extra paths!
			for (int ii = 0; ii < vh->sub.htdocs.index_count; ii++) {
				size_t cl = strlen(vh->sub.htdocs.index[ii]);
				char* tp2 = xmalloc(htdl + pl + cl);
				memcpy(tp2, tp, htdl + pl - 1);
				memcpy(tp2 + htdl + pl - 1, vh->sub.htdocs.index[ii], cl + 1);
				if (!access(tp2, R_OK)) {
					xfree(tp);
					tp = tp2;
					break;
				} else {
					xfree(tp2);
				}
			}
		}
		rtp = realpath(tp, NULL);
		xfree(tp);
		if (rtp == NULL) {
			if (errno == ENOENT || errno == ENOTDIR) {
				rs.response->code = "404 Not Found";
				generateDefaultErrorPage(rs, vh, "The requested URL was not found on this server. If you believe this to be an error, please contact your system administrator.");
			} else if (errno == EACCES) {
				rs.response->code = "403 Forbidden";
				generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
			} else {
				rs.response->code = "500 Internal Server Error";
				generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
			}
			goto epage;
		}
		struct stat st;
		if (stat(rtp, &st) != 0) {
			errlog(rs.wp->logsess, "Failed stat on <%s>: %s", rtp, strerror(errno));
			rs.response->code = "500 Internal Server Error";
			generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
			goto epage;
		}
		if ((st.st_mode & S_IFDIR) && rs.request->path[pl - 1] != '/') {
			rs.response->code = "302 Found";
			size_t pl = strlen(rs.request->path);
			char np[pl + 2];
			memcpy(np, rs.request->path, pl);
			np[pl] = '/';
			np[pl + 1] = 0;
			header_add(rs.response->headers, "Location", np);
			xfree(rtp);
			goto pvh;
		}
		size_t rtpl = strlen(rtp);
		if ((st.st_mode & S_IFDIR) && rtp[rtpl - 1] != '/') {
			rtp = xrealloc(rtp, ++rtpl + 1);
			rtp[rtpl - 1] = '/';
			rtp[rtpl] = 0;
		}
		if (vh->sub.htdocs.symlock && !startsWith(rtp, vh->sub.htdocs.htdocs)) {
			rs.response->code = "403 Forbidden";
			generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
			goto epage;
		}
		if (vh->sub.htdocs.nohardlinks && st.st_nlink != 1 && !(st.st_mode & S_IFDIR)) {
			rs.response->code = "403 Forbidden";
			generateDefaultErrorPage(rs, vh, "The requested URL is not available. If you believe this to be an error, please contact your system administrator.");
			goto epage;
		}
		//TODO: overrides
		rs.response->body = xmalloc(sizeof(struct body));
		rs.response->body->len = 0;
		rs.response->body->data = NULL;
		const char* ext = strrchr(rtp, '.');
		rs.response->body->mime_type = ext == NULL ? "application/octet-stream" : getMimeForExt(ext + 1);
		rs.response->body->freeMime = 0;
		if (vh->sub.htdocs.maxAge > 0) {
			int dcc = 0;
			for (int i = 0; i < vh->sub.htdocs.cacheType_count; i++) {
				if (streq_nocase(vh->sub.htdocs.cacheTypes[i], rs.response->body->mime_type)) {
					dcc = 1;
					break;
				} else if (endsWith(vh->sub.htdocs.cacheTypes[i], "/*")) {
					char* nct = xstrdup(vh->sub.htdocs.cacheTypes[i], 0);
					nct[strlen(nct) - 1] = 0;
					if (startsWith(rs.response->body->mime_type, nct)) {
						dcc = 1;
						xfree(nct);
						break;
					}
					xfree(nct);
				}
			}

			char ccbuf[64];
			memcpy(ccbuf, "max-age=", 8);
			int snr = snprintf(ccbuf + 8, 18, "%u", vh->sub.htdocs.maxAge);
			if (dcc) {
				memcpy(ccbuf + 8 + snr, ", no-cache", 11);
			} else {
				ccbuf[8 + snr] = 0;
			}
			header_add(rs.response->headers, "Cache-Control", ccbuf);
		}
		if (rs.response->body != NULL && rs.response->body->mime_type != NULL) for (int i = 0; i < vh->sub.htdocs.fcgi_count; i++) {
			struct fcgi* fcgi = vh->sub.htdocs.fcgis[i];
			int df = 0;
			for (int m = 0; m < fcgi->mime_count; m++) {
				char* mime = fcgi->mimes[m];
				if (streq_nocase(mime, rs.response->body->mime_type)) {
					df = 1;
					break;
				}
			}
			if (df) {
				isStatic = 0;
				int fc = 0;
				sofcgi: ;
				int ffd = vh->sub.htdocs.fcgifds[rs.wp->i][i];
				struct fcgiframe ff;
				ff.type = FCGI_BEGIN_REQUEST;
				ff.reqID = 0;
				ff.len = 8;
				unsigned char pkt[8];
				pkt[0] = 0;
				pkt[1] = 1;
				pkt[2] = 1;
				memset(pkt + 3, 0, 5);
				ff.data = pkt;
				if (writeFCGIFrame(ffd, &ff)) {
					errlog(rs.wp->logsess, "Failed to write to FCGI Server! File: %s Error: %s, restarting connection!", rtp, strerror(errno));
					if (fc > 0) {
						errlog(rs.wp->logsess, "Connection failed restart, perhaps FCGI server is down?");
						rs.response->code = "500 Internal Server Error";
						generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
						goto epage;
					}
					int fd = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
					if (fd < 0) {
						errlog(rs.wp->logsess, "Error creating socket for FCGI Server! %s", strerror(errno));
						continue;
					}
					if (connect(fd, fcgi->addr, fcgi->addrlen)) {
						errlog(rs.wp->logsess, "Error connecting socket to FCGI Server! %s", strerror(errno));
						continue;
					}
					close(ffd);
					vh->sub.htdocs.fcgifds[rs.wp->i][i] = fd;
					fc++;
					goto sofcgi;
				}
				//TODO: SERVER_ADDR
				char* rq = xstrdup(rs.request->path, 0);
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
				writeFCGIParam(ffd, "REQUEST_URI", rs.request->path);
				char cl[16];
				if (rs.request->body != NULL) {
					snprintf(cl, 16, "%i", rs.request->body->len);
				} else {
					cl[0] = '0';
					cl[1] = 0;
				}
				writeFCGIParam(ffd, "CONTENT_LENGTH", cl);
				if (rs.request->body != NULL && rs.request->body->mime_type != NULL) writeFCGIParam(ffd, "CONTENT_TYPE", rs.request->body->mime_type);
				writeFCGIParam(ffd, "GATEWAY_INTERFACE", "CGI/1.1");
				writeFCGIParam(ffd, "QUERY_STRING", get);
				{
					char tip[48];
					char* mip = NULL;
					if (rs.sender->addr.sa_family == AF_INET) {
						struct sockaddr_in *sip4 = (struct sockaddr_in*) &rs.sender->addr;
						mip = tip;
						inet_ntop(AF_INET, &sip4->sin_addr, tip, 48);
					} else if (rs.sender->addr.sa_family == AF_INET6) {
						struct sockaddr_in6 *sip6 = (struct sockaddr_in6*) &rs.sender->addr;
						mip = tip;
						inet_ntop(AF_INET6, &sip6->sin6_addr, tip, 48);
					} else if (rs.sender->addr.sa_family == AF_LOCAL) {
						mip = "UNIX";
					} else {
						mip = "UNKNOWN";
					}
					if (mip == NULL) mip = "INVALID";
					writeFCGIParam(ffd, "REMOTE_ADDR", mip);
					writeFCGIParam(ffd, "REMOTE_HOST", mip);
				}
				if (rs.sender->addr.sa_family == AF_INET) {
					snprintf(cl, 16, "%i", ntohs(((struct sockaddr_in*) &rs.sender->addr)->sin_port));
				} else if (rs.sender->addr.sa_family == AF_INET6) {
					snprintf(cl, 16, "%i", ntohs(((struct sockaddr_in6*) &rs.sender->addr)->sin6_port));
				} else {
					cl[0] = '0';
					cl[1] = 0;
				}
				writeFCGIParam(ffd, "REMOTE_PORT", cl);
				writeFCGIParam(ffd, "REQUEST_METHOD", getMethod(rs.request->method));
				char rss[4];
				rss[3] = 0;
				memcpy(rss, rs.response->code, 3);
				writeFCGIParam(ffd, "REDIRECT_STATUS", rss);
				size_t htl = strlen(vh->sub.htdocs.htdocs);
				int htes = vh->sub.htdocs.htdocs[htl - 1] == '/';
				size_t rtpl = strlen(rtp);
				if (rtpl < htl) errlog(rs.wp->logsess, "Setting FCGI SCRIPT_NAME requires the file to be in htdocs! @ %s", rtp);
				else writeFCGIParam(ffd, "SCRIPT_NAME", rtp + htl + (htes ? -1 : 0));
				if (host != NULL) writeFCGIParam(ffd, "SERVER_NAME", host);
				snprintf(cl, 16, "%i", rs.wp->sport);
				writeFCGIParam(ffd, "SERVER_PORT", cl);
				writeFCGIParam(ffd, "SERVER_PROTOCOL", rs.request->version);
				writeFCGIParam(ffd, "SERVER_SOFTWARE", "Avuna/" VERSION);
				writeFCGIParam(ffd, "DOCUMENT_ROOT", vh->sub.htdocs.htdocs);
				writeFCGIParam(ffd, "SCRIPT_FILENAME", rtp);
				for (int i = 0; i < rs.request->headers->count; i++) {
					const char* name = rs.request->headers->names[i];
					if (streq_nocase(name, "Accept-Encoding")) continue;
					const char* value = rs.request->headers->values[i];
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
					writeFCGIParam(ffd, nname, value);
				}
				writeFCGIParam(ffd, "", "");
				ff.type = FCGI_STDIN;
				if (rs.request->body != NULL && rs.request->body->len > 0) {
					ff.len = rs.request->body->len;
					ff.data = rs.request->body->data;
					writeFCGIFrame(ffd, &ff);
				}
				ff.len = 0;
				writeFCGIFrame(ffd, &ff);
				if (rs.response->body != NULL) {
					xfree(rs.response->body->data);
					xfree(rs.response->body);
					rs.response->body = NULL;
				}
				xfree(rq);
				char* ct = NULL;
				int hd = 0;
				char* hdd = NULL;
				size_t hddl = 0;
				while (ff.type != FCGI_END_REQUEST) {
					if (readFCGIFrame(ffd, &ff)) {
						errlog(rs.wp->logsess, "Error reading from FCGI server: %s", strerror(errno));
					}
					if (ff.type == FCGI_END_REQUEST) {
						xfree(ff.data);
						continue;
					}
					if (ff.type == FCGI_STDERR) {
						errlog(rs.wp->logsess, "FCGI STDERR <%s>: %s", rtp, ff.data);
					} else if (ff.type == FCGI_STDOUT) {
						int hr = 0;
						if (!hd) {
							int ml = 0;
							char* tm = "\r\n\r\n";
							for (int i = 0; i < ff.len; i++) {
								if (((char*) ff.data)[i] == tm[ml]) {
									ml++;
									if (ml == 4) {
										hd = 1;
										hr = i + 1;
										if (hdd == NULL) {
											hdd = xmalloc(i);
											memcpy(hdd, ff.data, i);
											hddl = i;
										} else {
											hdd = xrealloc(hdd, hddl + i);
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
									memcpy(hdd, ff.data, ff.len);
									hddl = ff.len;
								} else {
									hdd = xrealloc(hdd, hddl + ff.len);
									memcpy(hdd + hddl, ff.data, ff.len);
									hddl += ff.len;
								}
							}
						} else if (hd == 1) {
							hd = 2;
							struct headers hdrs;
							parseHeaders(&hdrs, hdd);
							for (int i = 0; i < rs.request->headers->count; i++) {
								const char* name = rs.request->headers->names[i];
								const char* value = rs.request->headers->values[i];
								if (streq_nocase(name, "Content-Type")) {
									ct = xstrdup(value, 0);
								} else header_add(rs.response->headers, name, value);
							}
						}
						if (hr < ff.len) {
							unsigned char* ffd = ff.data + hr;
							ff.len -= hr;
							if (rs.response->body == NULL) {
								rs.response->body = xmalloc(sizeof(struct body));
								rs.response->body->data = xmalloc(ff.len);
								memcpy(rs.response->body->data, ffd, ff.len);
								rs.response->body->len = ff.len;
								rs.response->body->mime_type = ct == NULL ? "text/html" : ct;
								rs.response->body->freeMime = ct == NULL ? 0 : 1;
							} else {
								rs.response->body->len += ff.len;
								rs.response->body->data = xrealloc(rs.response->body->data, rs.response->body->len);
								memcpy(rs.response->body->data + rs.response->body->len - ff.len, ffd, ff.len);
							}
						}
					}
					xfree(ff.data);
				}
			}
		}
		if (isStatic) {
			int ffd = open(rtp, O_RDONLY);
			if (ffd < 0) {
				errlog(rs.wp->logsess, "Failed to open file %s! %s", rtp, strerror(errno));
				rs.response->code = "500 Internal Server Error";
				generateDefaultErrorPage(rs, vh, "An unknown error occurred trying to serve your request! If you believe this to be an error, please contact your system administrator.");
				goto epage;
			}
			rs.response->body->data = xmalloc(st.st_size);
			int r = 0;
			while ((r = read(ffd, rs.response->body->data + rs.response->body->len, st.st_size - rs.response->body->len)) > 0) {
				rs.response->body->len += r;
			}
			if (r < 0) {
				errlog(rs.wp->logsess, "Failed to read file %s! %s", rtp, strerror(errno));
				rs.response->code = "500 Internal Server Error";
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
		if (rs.response->body != NULL && rs.response->body->len > 0 && rs.response->code != NULL && rs.response->code[0] == '2') {
			struct md5_ctx md5ctx;
			md5_init(&md5ctx);
			md5_update(&md5ctx, rs.response->body->len, rs.response->body->data);
			unsigned char rawmd5[16];
			md5_digest(&md5ctx, 16, rawmd5);
			hetag = 1;
			etag[34] = 0;
			etag[0] = '\"';
			for (int i = 0; i < 16; i++) {
				snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
			}
			etag[33] = '\"';
			header_add(rs.response->headers, "ETag", etag);
			if (streq(etag, header_get(rs.request->headers, "If-None-Match"))) {
				nm = 1;
				if (!isStatic) {
					rs.response->code = "304 Not Modified";
					xfree(rs.response->body->data);
					xfree(rs.response->body);
					rs.response->body = NULL;
				}
			}
		}
		int wgz = 0;
		if (rs.response->body != NULL && rs.response->body->len > 1024 && header_get(rs.response->headers, "Content-Encoding") == NULL) {
			const char* accenc = header_get(rs.request->headers, "Accept-Encoding");
			if (contains_nocase(accenc, "gzip")) {
				z_stream strm;
				strm.zalloc = Z_NULL;
				strm.zfree = Z_NULL;
				strm.opaque = Z_NULL;
				int dr = 0;
				if ((dr = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY)) != Z_OK) { // TODO: configurable level?
					errlog(rs.wp->logsess, "Error with zlib defaultInit: %i", dr);
					goto pgzip;
				}
				strm.avail_in = rs.response->body->len;
				strm.next_in = rs.response->body->data;
				void* cdata = xmalloc(16384);
				size_t ts = 0;
				size_t cc = 16384;
				strm.avail_out = cc - ts;
				strm.next_out = cdata + ts;
				do {
					dr = deflate(&strm, Z_FINISH);
					ts = strm.total_out;
					if (ts >= cc) {
						cc = ts + 16384;
						cdata = xrealloc(cdata, cc);
					}
					if (dr == Z_STREAM_ERROR) {
						xfree(cdata);
						errlog(rs.wp->logsess, "Stream error with zlib deflate");
						goto pgzip;
					}
					strm.avail_out = cc - ts;
					strm.next_out = cdata + ts;
				} while (strm.avail_out == 0);
				deflateEnd(&strm);
				xfree(rs.response->body->data);
				cdata = xrealloc(cdata, ts); // shrink
				rs.response->body->data = cdata;
				rs.response->body->len = ts;
				header_add(rs.response->headers, "Content-Encoding", "gzip");
				header_add(rs.response->headers, "Vary", "Accept-Encoding");
				wgz = 1;
			}
		}
		pgzip: if (isStatic && vh->sub.htdocs.scacheEnabled) {
			struct scache* sc = xmalloc(sizeof(struct scache));
			sc->body = rs.response->body;
			sc->ce = wgz;
			sc->code = rs.response->code;
			if (rs.response->body != NULL) header_setoradd(rs.response->headers, "Content-Type", rs.response->body->mime_type);
			char l[16];
			if (rs.response->body != NULL) sprintf(l, "%u", (unsigned int) rs.response->body->len);		//TODO: might be a size limit here
			header_setoradd(rs.response->headers, "Content-Length", rs.response->body == NULL ? "0" : l);
			sc->headers = rs.response->headers;
			sc->rp = rs.request->path;
			if (!hetag) {
				struct md5_ctx md5ctx;
				md5_init(&md5ctx);
				md5_update(&md5ctx, rs.response->body->len, rs.response->body->data);
				unsigned char rawmd5[16];
				md5_digest(&md5ctx, 16, rawmd5);
				hetag = 1;
				etag[34] = 0;
				etag[0] = '\"';
				for (int i = 0; i < 16; i++) {
					snprintf(etag + (i * 2) + 1, 3, "%02X", rawmd5[i]);
				}
				etag[33] = '\"';
			}
			memcpy(sc->etag, etag, 35);
			addSCache(&vh->sub.htdocs.cache, sc);
			rs.response->atc = 1;
			rs.request->atc = 1;
			if (nm) {
				rs.response->body = NULL;
				rs.response->code = "304 Not Modified";
			}
		}
		pcacheadd:
		//TODO: Chunked
		if (rtp != NULL) xfree(rtp);
	} else if (vh->type == VHOST_RPROXY) {

	} else if (vh->type == VHOST_REDIRECT) {
		rs.response->code = "302 Found";
		header_add(rs.response->headers, "Location", vh->sub.redirect.redir);
	} else if (vh->type == VHOST_PROXY) {

	}
	pvh:
//body stuff
	if (rs.response->body != NULL) header_setoradd(rs.response->headers, "Content-Type", rs.response->body->mime_type);
	char l[16];
	if (rs.response->body != NULL) sprintf(l, "%u", (unsigned int) rs.response->body->len);		//TODO: might be a size limit here
	header_setoradd(rs.response->headers, "Content-Length", rs.response->body == NULL ? "0" : l);
	return 0;
}
