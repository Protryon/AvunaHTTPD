/*
 * main.c
 *
 *  Created on: Nov 17, 2015
 *      Author: root
 */

#include <unistd.h>
#include <stdio.h>
#include "config.h"
#include <errno.h>
#include "xstring.h"
#include "version.h"
#include "util.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "streams.h"
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "accept.h"
#include "globals.h"
#include "collection.h"
#include "work.h"
#include <sys/types.h>
#include "mime.h"
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include "tls.h"
#include "http.h"
#include "vhost.h"

int main(int argc, char* argv[]) {
	signal(SIGPIPE, SIG_IGN);
	if (getuid() != 0 || getgid() != 0) {
		printf("Must run as root!\n");
		return 1;
	}
	printf("Loading Avuna %s %s\n", DAEMON_NAME, VERSION);
#ifdef DEBUG
	printf("Running in Debug mode!\n");
#endif
	char cwd[256];
	if (argc == 1) {
		memcpy(cwd, "/etc/avuna/", 11);
		cwd[11] = 0;
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME) + 1, 0);
		strcat(cwd, toLowerCase(dn));
		xfree(dn);
	} else {
		size_t l = strlen(argv[1]);
		if (argv[1][l - 1] == '/') argv[1][--l] = 0;
		memcpy(cwd, argv[1], l + 1);
	}
	recur_mkdir(cwd, 0750);
	chdir(cwd);
	if (strlen(cwd) > 240) {
		printf("Load Directory is more than 240 characters path length!\n");
		return 1;
	}
	strncat(cwd, "/main.cfg", 9);
	cfg = loadConfig(cwd);
	if (cfg == NULL) {
		printf("Error loading Config<%s>: %s\n", cwd, errno == EINVAL ? "File doesn't exist!" : strerror(errno));
		return 1;
	}
	struct cnode* dm = getUniqueByCat(cfg, CAT_DAEMON);
	if (dm == NULL) {
		printf("[daemon] block does not exist in %s!\n", cwd);
		return 1;
	}
	int runn = 0;
	pid_t pid = 0;
	const char* pid_file = getConfigValue(dm, "pid-file");
	if (!access(pid_file, F_OK)) {
		int pidfd = open(pid_file, O_RDONLY);
		if (pidfd < 0) {
			printf("Failed to open PID file! %s\n", strerror(errno));
			return 1;
		}
		char pidr[16];
		if (readLine(pidfd, pidr, 16) >= 1) {
			pid = atol(pidr);
			int k = kill(pid, 0);
			if (k == 0) {
				runn = 1;
			}
		} else {
			printf("Failed to read PID file! %s\n", strerror(errno));
			return 1;
		}
		close(pidfd);
	}
#ifndef DEBUG
	if (runn) {
		printf("Already running! PID = %i\n", pid);
		exit(0);
	} else {

		pid_t f = fork();
		if (f == 0) {
			printf("Now running as daemon!\n");
			exit(0);
		} else {
			printf("Daemonized! PID = %i\n", f);
			if (setsid() < 0) {
				printf("Failed to exit process tree: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "r", stdin) < 0) {
				printf("reopening of STDIN to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stderr) < 0) {
				printf("reopening of STDERR to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
			if (freopen("/dev/null", "w", stdout) < 0) {
				printf("reopening of STDOUT to /dev/null failed: %s\n", strerror(errno));
				return 1;
			}
		}
	}
#else
	printf("Daemonized! PID = %i\n", getpid());
#endif
	delog = xmalloc(sizeof(struct logsess));
	delog->pi = 0;
	delog->access_fd = NULL;
	const char* el = getConfigValue(dm, "error-log");
	delog->error_fd = el == NULL ? NULL : fopen(el, "a"); // fopen will return NULL on error, which works.
	int pfpl = strlen(pid_file);
	char* pfp = xcopy(pid_file, pfpl + 1, 0);
	for (int i = pfpl - 1; i--; i >= 0) {
		if (pfp[i] == '/') {
			pfp[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pfp, 0750) == -1) {
		errlog(delog, "Error making directories for PID file: %s.", strerror(errno));
		return 1;
	}
	const char* mtf = getConfigValue(dm, "mime-types");
	if (mtf == NULL) {
		errlog(delog, "No mime-types in daemon config!");
		return 1;
	}
	if (access(mtf, R_OK) || loadMimes(mtf)) {
		errlog(delog, "Cannot read or mime-types file does not exist: %s", mtf);
		return 1;
	}
//TODO: chown group to de-escalated
	FILE *pfd = fopen(pid_file, "w");
	if (pfd == NULL) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		errlog(delog, "Error writing PID file: %s.", strerror(errno));
		return 1;
	}
	(void) SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	OPENSSL_config (NULL);
	int servsl;
	struct cnode** servs = getCatsByCat(cfg, CAT_SERVER, &servsl);
	int sr = 0;
	struct accept_param* aps[servsl];
	for (int i = 0; i < servsl; i++) {
		struct cnode* serv = servs[i];
		const char* bind_mode = getConfigValue(serv, "bind-mode");
		const char* bind_ip = NULL;
		int port = -1;
		const char* bind_file = NULL;
		int namespace = -1;
		int ba = 0;
		int ip6 = 0;
		if (streq(bind_mode, "tcp")) {
			bind_ip = getConfigValue(serv, "bind-ip");
			if (streq(bind_ip, "0.0.0.0")) {
				ba = 1;
			}
			ip6 = ba || contains(bind_ip, ":");
			const char* bind_port = getConfigValue(serv, "bind-port");
			if (!strisunum(bind_port)) {
				if (serv->id != NULL) errlog(delog, "Invalid bind-port for server: %s", serv->id);
				else errlog(delog, "Invalid bind-port for server.");
				continue;
			}
			port = atoi(bind_port);
			namespace = ip6 ? PF_INET6 : PF_INET;;
		} else if (streq(bind_mode, "unix")) {
			bind_file = getConfigValue(serv, "bind-file");
			namespace = PF_LOCAL;
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid bind-mode for server: %s", serv->id);
			else errlog(delog, "Invalid bind-mode for server.");
			continue;
		}
		const char* tcc = getConfigValue(serv, "threads");
		if (!strisunum(tcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s", serv->id);
			else errlog(delog, "Invalid threads for server.");
			continue;
		}
		int tc = atoi(tcc);
		if (tc < 1) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s, must be greater than 1.\n", serv->id);
			else errlog(delog, "Invalid threads for server, must be greater than 1.\n");
			continue;
		}
		const char* mcc = getConfigValue(serv, "max-conn");
		if (!strisunum(mcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-conn for server: %s", serv->id);
			else errlog(delog, "Invalid max-conn for server.");
			continue;
		}
		int mc = atoi(mcc);
		const char* mpc = getConfigValue(serv, "max-post");
		if (!strisunum(mpc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-post for server: %s", serv->id);
			else errlog(delog, "Invalid max-post for server.");
			continue;
		}
		long int mp = atol(mpc);
		sock: ;
		int sfd = socket(namespace, SOCK_STREAM, 0);
		if (sfd < 0) {
			if (serv->id != NULL) errlog(delog, "Error creating socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error creating socket for server, %s", strerror(errno));
			continue;
		}
		int one = 1;
		int zero = 0;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
			if (serv->id != NULL) errlog(delog, "Error setting SO_REUSEADDR for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting SO_REUSEADDR for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (namespace == PF_INET || namespace == PF_INET6) {
			if (ip6) {
				if (setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (void*) &zero, sizeof(zero)) == -1) {
					if (serv->id != NULL) errlog(delog, "Error unsetting IPV6_V6ONLY for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error unsetting IPV6_V6ONLY for server, %s", strerror(errno));
					close (sfd);
					continue;
				}
				struct sockaddr_in6 bip;
				bip.sin6_flowinfo = 0;
				bip.sin6_scope_id = 0;
				bip.sin6_family = AF_INET6;
				if (ba) bip.sin6_addr = in6addr_any;
				else if (!inet_pton(AF_INET6, bind_ip, &(bip.sin6_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin6_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					close (sfd);
					if (ba) {
						namespace = PF_INET;
						ip6 = 0;
						goto sock;
					}
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					continue;
				}
			} else {
				struct sockaddr_in bip;
				bip.sin_family = AF_INET;
				if (!inet_aton(bind_ip, &(bip.sin_addr))) {
					close (sfd);
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip", serv->id);
					else errlog(delog, "Error binding socket for server, invalid bind-ip");
					continue;
				}
				bip.sin_port = htons(port);
				if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
					if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
					else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
					close (sfd);
					continue;
				}
			}
		} else if (namespace == PF_LOCAL) {
			struct sockaddr_un uip;
			strncpy(uip.sun_path, bind_file, 108);
			if (bind(sfd, (struct sockaddr*) &uip, sizeof(uip))) {
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s", serv->id, strerror(errno));
				else errlog(delog, "Error binding socket for server, %s", strerror(errno));
				close (sfd);
				continue;
			}
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid family for server: %s", serv->id);
			else errlog(delog, "Invalid family for server");
			close (sfd);
			continue;
		}
		if (listen(sfd, 50)) {
			if (serv->id != NULL) errlog(delog, "Error listening on socket for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error listening on socket for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (serv->id != NULL) errlog(delog, "Error setting non-blocking for server: %s, %s", serv->id, strerror(errno));
			else errlog(delog, "Error setting non-blocking for server, %s", strerror(errno));
			close (sfd);
			continue;
		}
		struct logsess* slog = xmalloc(sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = getConfigValue(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
		const char* lel = getConfigValue(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
		const char* sssl = getConfigValue(serv, "ssl");
		if (serv->id != NULL) acclog(slog, "Server %s listening for connections!", serv->id);
		else acclog(slog, "Server listening for connections!");
		struct accept_param* ap = xmalloc(sizeof(struct accept_param));
		if (sssl != NULL) {
			struct cnode* ssln = getCatByID(cfg, sssl);
			if (ssln == NULL) {
				errlog(slog, "Invalid SSL node! Node not found!");
				goto pssl;
			}
			const char* cert = getConfigValue(ssln, "publicKey");
			const char* key = getConfigValue(ssln, "privateKey");
			if (cert == NULL || key == NULL || access(cert, R_OK) || access(key, R_OK)) {
				errlog(slog, "Invalid SSL node! No publicKey/privateKey value or cannot be read!");
				goto pssl;
			}
			ap->cert = loadCert(cert, key);
		} else {
			ap->cert = NULL;
		}
		pssl: ap->port = port;
		ap->server_fd = sfd;
		ap->config = serv;
		ap->works_count = tc;
		ap->logsess = slog;
		int vhc = 0;
		struct vhost** vohs = NULL;
		char* ovh = xstrdup(getConfigValue(serv, "vhosts"), 0);
		char* oovh = ovh;
		char* np = NULL;
		while ((np = strchr(ovh, ',')) != NULL || strlen(ovh) > 0) {
			if (np != NULL) {
				np[0] = 0;
				np++;
			}
			ovh = trim(ovh);
			struct cnode* vcn = getCatByID(cfg, ovh);
			if (vcn == NULL) {
				errlog(slog, "Could not find VHost: %s", ovh);
				goto cont_vh;
			}
			vhc++;
			if (vohs == NULL) {
				vohs = xmalloc(sizeof(struct vhost*));
			} else {
				vohs = xrealloc(vohs, sizeof(struct vhost*) * vhc);
			}
			vohs[vhc - 1] = xmalloc(sizeof(struct vhost));
			struct vhost* cv = vohs[vhc - 1];
			cv->id = vcn->id;
			cv->hosts = NULL;
			const char* vht = getConfigValue(vcn, "type");
			if (streq(vht, "htdocs")) {
				cv->type = VHOST_HTDOCS;
			} else if (streq(vht, "reverse-proxy")) {
				cv->type = VHOST_RPROXY;
			} else if (streq(vht, "redirect")) {
				cv->type = VHOST_REDIRECT;
			} else if (streq(vht, "mount")) {
				cv->type = VHOST_MOUNT;
			} else {
				errlog(slog, "Invalid VHost Type: %s", vht);
				xfree(cv);
				vohs[vhc - 1] = NULL;
				vhc--;
				goto cont_vh;
			}
			char* hnv = xstrdup(getConfigValue(vcn, "host"), 0);
			char* nph = NULL;
			while ((nph = strchr(hnv, ',')) != NULL || strlen(hnv) > 0) {
				if (nph != NULL) {
					nph[0] = 0;
					nph++;
				}
				hnv = trim(hnv);
				if (streq(hnv, "*")) {
					cv->host_count = 0;
					free(hnv);
					break;
				}
				if (cv->hosts == NULL) {
					cv->hosts = xmalloc(sizeof(char*));
					cv->host_count = 1;
				} else {
					cv->hosts = xrealloc(cv->hosts, sizeof(char*) * ++cv->host_count);
				}
				cv->hosts[cv->host_count - 1] = hnv;
				hnv = nph == NULL ? hnv + strlen(hnv) : nph;
			}
			if (cv->type == VHOST_HTDOCS) {
				struct vhost_htdocs* vhb = &cv->sub.htdocs;
				vhb->index = NULL;
				vhb->errpages = NULL;
				vhb->enableGzip = 1;
				vhb->cacheTypes = NULL;
				vhb->cacheType_count = 0;
				vhb->maxAge = 604800;
				vhb->cache.scache_size = 0;
				vhb->cache.scaches = NULL;
				if (pthread_rwlock_init(&vhb->cache.scachelock, NULL)) {
					errlog(slog, "Error initializing scachelock! %s", strerror(errno));
				}
				vhb->htdocs = getConfigValue(vcn, "htdocs");
				if (vhb->htdocs == NULL) {
					errlog(slog, "No htdocs at vhost: %s, assuming default", vcn->id);
					vhb->htdocs = "/var/www/html/";
				}
				vhb->htdocs = realpath(vhb->htdocs, NULL);
				if (vhb->htdocs == NULL) {
					recur_mkdir("/var/www/html/", 0750);
					vhb->htdocs = "/var/www/html/";
					vhb->htdocs = realpath(vhb->htdocs, NULL);
				}
				if (vhb->htdocs == NULL) {
					errlog(slog, "No htdocs at vhost %s, or does not exist and cannot be created.", vcn->id);
					xfree(cv);
					vohs = xrealloc(vohs, sizeof(struct vhost*) * --vhc);
					goto cont_vh;
				}
				size_t htl = strlen(vhb->htdocs);
				if (vhb->htdocs[htl - 1] != '/') {
					vhb->htdocs = xrealloc(vhb->htdocs, ++htl + 1);
					vhb->htdocs[htl - 1] = '/';
					vhb->htdocs[htl] = 0;
				}
				recur_mkdir(vhb->htdocs, 0750);
				const char* nhl = getConfigValue(vcn, "nohardlinks");
				vhb->nohardlinks = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No nohardlinks at vhost: %s, assuming default", vcn->id);
				}
				nhl = getConfigValue(vcn, "symlock");
				vhb->symlock = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No symlock at vhost: %s, assuming default", vcn->id);
				}
				nhl = getConfigValue(vcn, "scache");
				vhb->scacheEnabled = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No scache at vhost: %s, assuming default", vcn->id);
				}
				nhl = getConfigValue(vcn, "cache-maxage");
				if (nhl == NULL || !strisunum(nhl)) {
					errlog(slog, "No cache-maxage at vhost: %s, assuming default", vcn->id);
					nhl = "604800";
				}
				vhb->maxAge = atol(nhl);
				nhl = getConfigValue(vcn, "maxSCache");
				if (nhl == NULL || !strisunum(nhl)) {
					errlog(slog, "No maxSCache at vhost: %s, assuming default", vcn->id);
					nhl = "0";
				}
				vhb->maxCache = atol(nhl);
				nhl = getConfigValue(vcn, "enable-gzip");
				vhb->enableGzip = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No enable-gzip at vhost: %s, assuming default", vcn->id);
				}
				const char* ic = getConfigValue(vcn, "index");
				if (ic == NULL) {
					errlog(slog, "No index at vhost: %s, assuming default", vcn->id);
					ic = "index.php, index.html, index.htm";
				}
				char* ivh = xstrdup(ic, 0);
				char* npi = NULL;
				while ((npi = strchr(ivh, ',')) != NULL || strlen(ivh) > 0) {
					if (npi != NULL) {
						npi[0] = 0;
						npi++;
					}
					ivh = trim(ivh);
					if (vhb->index == NULL) {
						vhb->index = xmalloc(sizeof(char*));
						vhb->index_count = 1;
					} else {
						vhb->index = xrealloc(vhb->index, sizeof(char*) * ++vhb->index_count);
					}
					vhb->index[vhb->index_count - 1] = ivh;
					ivh = npi == NULL ? ivh + strlen(ivh) : npi;
				}
				ic = getConfigValue(vcn, "cache-types");
				if (ic == NULL) {
					errlog(slog, "No cache-types at vhost: %s, assuming default", vcn->id);
					ic = "text/css,application/javascript,image/*";
				}
				ivh = xstrdup(ic, 0);
				while ((npi = strchr(ivh, ',')) != NULL || strlen(ivh) > 0) {
					if (npi != NULL) {
						npi[0] = 0;
						npi++;
					}
					ivh = trim(ivh);
					if (vhb->cacheTypes == NULL) {
						vhb->cacheTypes = xmalloc(sizeof(char*));
						vhb->cacheType_count = 1;
					} else {
						vhb->cacheTypes = xrealloc(vhb->cacheTypes, sizeof(char*) * ++vhb->cacheType_count);
					}
					vhb->cacheTypes[vhb->cacheType_count - 1] = ivh;
					ivh = npi == NULL ? ivh + strlen(ivh) : npi;
				}
				vhb->errpage_count = 0;
				vhb->errpages = NULL;
				for (int i = 0; i < vcn->entries; i++) {
					if (startsWith_nocase(vcn->keys[i], "error-")) {
						const char* en = vcn->keys[i] + 6;
						if (!strisunum(en)) {
							errlog(slog, "Invalid error page specifier at vhost: %s", vcn->id);
							continue;
						}
						struct errpage* ep = xmalloc(sizeof(struct errpage));
						ep->code = strtol(en, NULL, 10);
						ep->page = vcn->values[i];
						if (vhb->errpages == NULL) {
							vhb->errpages = xmalloc(sizeof(struct errpage*));
							vhb->errpage_count = 1;
						} else {
							vhb->errpages = xrealloc(vhb->errpages, sizeof(struct errpage*) * ++vhb->errpage_count);
						}
						vhb->errpages[vhb->errpage_count - 1] = ep;
					}
				}
				vhb->fcgis = NULL;
				vhb->fcgi_count = 0;
				ic = getConfigValue(vcn, "fcgis");
				if (ic != NULL) {
					ivh = xstrdup(ic, 0);
					while ((npi = strchr(ivh, ',')) != NULL || strlen(ivh) > 0) {
						if (npi != NULL) {
							npi[0] = 0;
							npi++;
						}
						ivh = trim(ivh);
						struct cnode* fcgin = getCatByID(cfg, ivh);
						if (fcgin == NULL) {
							errlog(slog, "Could not find FCGI entry %s at vhost: %s", ivh, vcn->id);
							goto icc;
						}
						const char* fmode = getConfigValue(fcgin, "mode");
						struct fcgi* fcgi = xmalloc(sizeof(struct fcgi));
						fcgi->mimes = NULL;

						if (streq_nocase(fmode, "tcp")) {
							fcgi->addrlen = sizeof(struct sockaddr_in);
							struct sockaddr_in* ina = xmalloc(sizeof(struct sockaddr_in));
							fcgi->addr = ina;
							ina->sin_family = AF_INET;
							const char* fip = getConfigValue(fcgin, "ip");
							const char* fport = getConfigValue(fcgin, "port");
							if (fip == NULL || !inet_aton(fip, &ina->sin_addr)) {
								errlog(slog, "Invalid IP for FCGI node %s at vhost: %s", ivh, vcn->id);
								xfree(fcgi);
								xfree(ina);
								goto icc;
							}
							if (fport == NULL || !strisunum(fport)) {
								errlog(slog, "Invalid Port for FCGI node %s at vhost: %s", ivh, vcn->id);
								xfree(fcgi);
								xfree(ina);
								goto icc;
							}
							ina->sin_port = htons(atoi(fport));
						} else if (streq_nocase(fmode, "unix")) {
							fcgi->addrlen = sizeof(struct sockaddr_un);
							struct sockaddr_un* ina = xmalloc(sizeof(struct sockaddr_un));
							fcgi->addr = ina;
							ina->sun_family = AF_LOCAL;
							const char* ffile = getConfigValue(fcgin, "file");
							if (ffile == NULL || strlen(ffile) >= 107) {
								errlog(slog, "Invalid Unix Socket for FCGI node %s at vhost: %s", ivh, vcn->id);
								xfree(fcgi);
								xfree(ina);
								goto icc;
							}
							memcpy(ina->sun_path, ffile, strlen(ffile) + 1);
						} else {
							errlog(slog, "Invalid mode for FCGI node %s at vhost: %s", ivh, vcn->id);
							xfree(fcgi);
							goto icc;
						}
						const char* ic2 = getConfigValue(fcgin, "mime-types");
						if (ic2 != NULL) {
							char* ivh2 = xstrdup(ic2, 0);
							char* npi2 = NULL;
							while ((npi2 = strchr(ivh2, ',')) != NULL || strlen(ivh2) > 0) {
								if (npi2 != NULL) {
									npi2[0] = 0;
									npi2++;
								}
								ivh2 = trim(ivh2);
								if (fcgi->mimes == NULL) {
									fcgi->mimes = xmalloc(sizeof(char*));
									fcgi->mime_count = 1;
								} else {
									fcgi->mimes = xrealloc(fcgi->mimes, sizeof(char*) * ++fcgi->mime_count);
								}
								fcgi->mimes[fcgi->mime_count - 1] = ivh2;
								ivh2 = npi2 == NULL ? ivh2 + strlen(ivh2) : npi2;
							}
						}
						if (vhb->fcgis == NULL) {
							vhb->fcgis = xmalloc(sizeof(struct fcgi*));
							vhb->fcgi_count = 1;
						} else {
							vhb->fcgis = xrealloc(vhb->fcgis, sizeof(struct fcgi*) * ++vhb->fcgi_count);
						}
						vhb->fcgis[vhb->fcgi_count - 1] = fcgi;
						icc: ivh = npi == NULL ? ivh + strlen(ivh) : npi;
					}
				}
				vhb->fcgifds = xmalloc(sizeof(int*) * tc);
				for (int i = 0; i < tc; i++) {
					vhb->fcgifds[i] = xmalloc(sizeof(int) * vhb->fcgi_count);
					for (int f = 0; f < vhb->fcgi_count; f++) {
						struct fcgi* fcgi = vhb->fcgis[f];
						int fd = socket(fcgi->addr->sa_family == AF_INET ? PF_INET : PF_LOCAL, SOCK_STREAM, 0);
						if (fd < 0) {
							errlog(slog, "Error creating socket for FCGI Server! %s", strerror(errno));
							vhb->fcgifds[i][f] = -1;
							continue;
						}
						if (connect(fd, fcgi->addr, fcgi->addrlen)) {
							errlog(slog, "Error connecting socket to FCGI Server! %s", strerror(errno));
							vhb->fcgifds[i][f] = -1;
							close(fd);
							continue;
						}
						vhb->fcgifds[i][f] = fd;
						//TODO: perhaps it is worth getting FCGI_MAX_CONNS, FCGI_MAX_REQS, most impls do not multiplex, so we won't bother
					}
				}
			} else if (cv->type == VHOST_RPROXY) {
				struct vhost_rproxy* vhb = &cv->sub.rproxy;
				vhb->cache.scache_size = 0;
				vhb->cache.scaches = NULL;
				vhb->enableGzip = 1;
				vhb->cacheTypes = NULL;
				vhb->cacheType_count = 0;
				vhb->maxAge = 604800;
				if (pthread_rwlock_init(&vhb->cache.scachelock, NULL)) {
					errlog(slog, "Error initializing scachelock! %s", strerror(errno));
				}
				const char* fmode = getConfigValue(vcn, "forward-mode");
				if (streq_nocase(fmode, "tcp")) {
					vhb->fwaddrlen = sizeof(struct sockaddr_in);
					struct sockaddr_in* ina = xmalloc(sizeof(struct sockaddr_in));
					vhb->fwaddr = ina;
					ina->sin_family = AF_INET;
					const char* fip = getConfigValue(vcn, "forward-ip");
					const char* fport = getConfigValue(vcn, "forward-port");
					if (fip == NULL || !inet_aton(fip, &ina->sin_addr)) {
						errlog(slog, "Invalid IP for Reverse Proxy vhost: %s", vcn->id);
						xfree(ina);
						goto cont_vh;
					}
					if (fport == NULL || !strisunum(fport)) {
						errlog(slog, "Invalid Port for Reverse Proxy vhost: %s", vcn->id);
						xfree(ina);
						goto cont_vh;
					}
					ina->sin_port = htons(atoi(fport));
				} else if (streq_nocase(fmode, "unix")) {
					vhb->fwaddrlen = sizeof(struct sockaddr_un);
					struct sockaddr_un* ina = xmalloc(sizeof(struct sockaddr_un));
					vhb->fwaddr = ina;
					ina->sun_family = AF_LOCAL;
					const char* ffile = getConfigValue(vcn, "file");
					if (ffile == NULL || strlen(ffile) >= 107) {
						errlog(slog, "Invalid Unix Socket for Reverse Proxy vhost: %s", vcn->id);
						xfree(ina);
						goto cont_vh;
					}
					memcpy(ina->sun_path, ffile, strlen(ffile) + 1);
				} else {
					errlog(slog, "Invalid mode for Reverse Proxy vhost: %s", vcn->id);
					goto cont_vh;
				}
				vhb->headers = NULL;
				for (int i = 0; i < vcn->entries; i++) {
					if (startsWith_nocase(vcn->keys[i], "header-")) {
						const char* en = vcn->keys[i] + 7;
						if (vhb->headers == NULL) {
							vhb->headers = xmalloc(sizeof(struct headers));
							vhb->headers->count = 0;
							vhb->headers->names = NULL;
							vhb->headers->values = NULL;
						}
						header_add(vhb->headers, en, vcn->values[i]);
					}
				}
				const char* ic = getConfigValue(vcn, "cache-types");
				if (ic == NULL) {
					errlog(slog, "No cache-types at vhost: %s, assuming default", vcn->id);
					ic = "text/css,application/javascript,image/*";
				}
				char* ivh = xstrdup(ic, 0);
				char* npi = NULL;
				vhb->cacheTypes = NULL;
				while ((npi = strchr(ivh, ',')) != NULL || strlen(ivh) > 0) {
					if (npi != NULL) {
						npi[0] = 0;
						npi++;
					}
					ivh = trim(ivh);
					if (vhb->cacheTypes == NULL) {
						vhb->cacheTypes = xmalloc(sizeof(char*));
						vhb->cacheType_count = 1;
					} else {
						vhb->cacheTypes = xrealloc(vhb->cacheTypes, sizeof(char*) * ++vhb->cacheType_count);
					}
					vhb->cacheTypes[vhb->cacheType_count - 1] = ivh;
					ivh = npi == NULL ? ivh + strlen(ivh) : npi;
				}
				const char* nhl = getConfigValue(vcn, "scache");
				vhb->scacheEnabled = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No scache at vhost: %s, assuming default", vcn->id);
				}
				nhl = getConfigValue(vcn, "cache-maxage");
				if (nhl == NULL || !strisunum(nhl)) {
					errlog(slog, "No cache-maxage at vhost: %s, assuming default", vcn->id);
					nhl = "604800";
				}
				vhb->maxAge = atol(nhl);
				nhl = getConfigValue(vcn, "maxSCache");
				if (nhl == NULL || !strisunum(nhl)) {
					errlog(slog, "No maxSCache at vhost: %s, assuming default", vcn->id);
					nhl = "0";
				}
				vhb->maxCache = atol(nhl);
				nhl = getConfigValue(vcn, "enable-gzip");
				vhb->enableGzip = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				if (nhl == NULL) {
					errlog(slog, "No enable-gzip at vhost: %s, assuming default", vcn->id);
				}
				ic = getConfigValue(vcn, "dynamic-types");
				if (ic == NULL) {
					errlog(slog, "No dynamic-types at vhost: %s, assuming default", vcn->id);
					ic = "application/x-php";
				}
				ivh = xstrdup(ic, 0);
				npi = NULL;
				vhb->dmimes = NULL;
				while ((npi = strchr(ivh, ',')) != NULL || strlen(ivh) > 0) {
					if (npi != NULL) {
						npi[0] = 0;
						npi++;
					}
					ivh = trim(ivh);
					if (vhb->dmimes == NULL) {
						vhb->dmimes = xmalloc(sizeof(char*));
						vhb->dmime_count = 1;
					} else {
						vhb->dmimes = xrealloc(vhb->dmimes, sizeof(char*) * ++vhb->dmime_count);
					}
					vhb->dmimes[vhb->dmime_count - 1] = ivh;
					ivh = npi == NULL ? ivh + strlen(ivh) : npi;
				}
			} else if (cv->type == VHOST_REDIRECT) {
				struct vhost_redirect* vhb = &cv->sub.redirect;
				vhb->redir = getConfigValue(vcn, "redirect");
				if (vhb->redir == NULL) {
					errlog(slog, "No redirect at vhost: %s", vcn->id);
					if (cv->hosts != NULL) xfree(cv->hosts);
					xfree(hnv);
					xfree(cv);
					vohs[vhc - 1] = NULL;
					vhc--;
					goto cont_vh;
				}
			} else if (cv->type == VHOST_MOUNT) {
				struct vhost_mount* vhb = &cv->sub.mount;
				vhb->vhms = NULL;
				vhb->vhm_count = 0;
				for (int i = 0; i < vcn->entries; i++) {
					if (startsWith(vcn->keys[i], "/")) {
						if (vhb->vhms == NULL) {
							vhb->vhms = xmalloc(sizeof(struct vhmount));
							vhb->vhm_count = 1;
						} else {
							vhb->vhms = xrealloc(vhb->vhms, sizeof(struct vhmount) * ++vhb->vhm_count);
						}
						vhb->vhms[vhb->vhm_count - 1].path = vcn->keys[i];
						vhb->vhms[vhb->vhm_count - 1].vh = vcn->values[i];
					}
				}
			}
			cont_vh: ovh = np == NULL ? ovh + strlen(ovh) : np;
		}
		xfree(oovh);
		ap->works = xmalloc(sizeof(struct work_param*) * tc);
		for (int x = 0; x < tc; x++) {
			struct work_param* wp = xmalloc(sizeof(struct work_param));
			wp->conns = new_collection(mc < 1 ? 0 : mc / tc, sizeof(struct conn*));
			wp->logsess = slog;
			wp->vhosts = vohs;
			wp->vhosts_count = vhc;
			wp->i = x;
			wp->sport = port;
			wp->maxPost = mp;
			ap->works[x] = wp;
		}
		aps[i] = ap;
		sr++;
	}
	const char* uids = getConfigValue(dm, "uid");
	const char* gids = getConfigValue(dm, "gid");
	uid_t uid = uids == NULL ? 0 : atol(uids);
	uid_t gid = gids == NULL ? 0 : atol(gids);
	if (gid > 0) {
		if (setgid(gid) != 0) {
			errlog(delog, "Failed to setgid! %s", strerror(errno));
		}
	}
	if (uid > 0) {
		if (setuid(uid) != 0) {
			errlog(delog, "Failed to setuid! %s", strerror(errno));
		}
	}
	acclog(delog, "Running as UID = %u, GID = %u, starting workers.", getuid(), getgid());
	for (int i = 0; i < servsl; i++) {
		pthread_t pt;
		for (int x = 0; x < aps[i]->works_count; x++) {
			int c = pthread_create(&pt, NULL, (void *) run_work, aps[i]->works[x]);
			if (c != 0) {
				if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging @ %s server.", c, servs[i]->id);
				else errlog(delog, "Error creating thread: pthread errno = %i, this will cause occasional connection hanging.", c);
			}
		}
		int c = pthread_create(&pt, NULL, (void *) run_accept, aps[i]);
		if (c != 0) {
			if (servs[i]->id != NULL) errlog(delog, "Error creating thread: pthread errno = %i, server %s is shutting down.", c, servs[i]->id);
			else errlog(delog, "Error creating thread: pthread errno = %i, server is shutting down.", c);
			close(aps[i]->server_fd);
		}
	}
	while (sr > 0)
		sleep(1);
	return 0;
}
