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

int main(int argc, char* argv[]) {
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
	char* el = getConfigValue(dm, "error-log");
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
		errlog(delog, "Error making directories for PID file: %s.\n", strerror(errno));
		return 1;
	}
//TODO: chown group to de-escalated
	FILE *pfd = fopen(pid_file, "w");
	if (pfd == NULL) {
		errlog(delog, "Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		errlog(delog, "Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		errlog(delog, "Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
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
		if (streq(bind_mode, "tcp")) {
			bind_ip = getConfigValue(serv, "bind-ip");
			const char* bind_port = getConfigValue(serv, "bind-port");
			if (!strisunum(bind_port)) {
				if (serv->id != NULL) errlog(delog, "Invalid bind-port for server: %s\n", serv->id);
				else errlog(delog, "Invalid bind-port for server.\n");
				continue;
			}
			port = atoi(bind_port);
			namespace = PF_INET;
		} else if (streq(bind_mode, "unix")) {
			bind_file = getConfigValue(serv, "bind-file");
			namespace = PF_LOCAL;
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid bind-mode for server: %s\n", serv->id);
			else errlog(delog, "Invalid bind-mode for server.\n");
			continue;
		}
		const char* tcc = getConfigValue(serv, "threads");
		if (!strisunum(tcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid threads for server: %s\n", serv->id);
			else errlog(delog, "Invalid threads for server.\n");
			continue;
		}
		int tc = atoi(tcc);
		const char* mcc = getConfigValue(serv, "max-conn");
		if (!strisunum(mcc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-conn for server: %s\n", serv->id);
			else errlog(delog, "Invalid max-conn for server.\n");
			continue;
		}
		int mc = atoi(mcc);
		const char* mpc = getConfigValue(serv, "max-post");
		if (!strisunum(mpc)) {
			if (serv->id != NULL) errlog(delog, "Invalid max-post for server: %s\n", serv->id);
			else errlog(delog, "Invalid max-post for server.\n");
			continue;
		}
		int mp = atoi(mpc);
		int sfd = socket(namespace, SOCK_STREAM, 0);
		if (sfd < 0) {
			if (serv->id != NULL) errlog(delog, "Error creating socket for server: %s, %s\n", serv->id, strerror(errno));
			else errlog(delog, "Error creating socket for server, %s\n", strerror(errno));
			continue;
		}
		int one = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
			if (serv->id != NULL) errlog(delog, "Error setting SO_REUSEADDR for server: %s, %s\n", serv->id, strerror(errno));
			else errlog(delog, "Error setting SO_REUSEADDR for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}
		if (namespace == PF_INET) {
			struct sockaddr_in bip;
			bip.sin_family = AF_INET;
			if (!inet_aton(bind_ip, &(bip.sin_addr))) {
				close (sfd);
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, invalid bind-ip\n", serv->id);
				else errlog(delog, "Error binding socket for server, invalid bind-ip\n");
				continue;
			}
			bip.sin_port = htons(port);
			if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s\n", serv->id, strerror(errno));
				else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else if (namespace == PF_LOCAL) {
			struct sockaddr_un uip;
			strncpy(uip.sun_path, bind_file, 108);
			if (bind(sfd, (struct sockaddr*) &uip, sizeof(uip))) {
				if (serv->id != NULL) errlog(delog, "Error binding socket for server: %s, %s\n", serv->id, strerror(errno));
				else errlog(delog, "Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else {
			if (serv->id != NULL) errlog(delog, "Invalid family for server: %s\n", serv->id);
			else errlog(delog, "Invalid family for server\n");
			close (sfd);
			continue;
		}
		if (listen(sfd, 50)) {
			if (serv->id != NULL) errlog(delog, "Error listening on socket for server: %s, %s\n", serv->id, strerror(errno));
			else errlog(delog, "Error listening on socket for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}
		if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (serv->id != NULL) errlog(delog, "Error setting non-blocking for server: %s, %s\n", serv->id, strerror(errno));
			else errlog(delog, "Error setting non-blocking for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}
		struct logsess* slog = xmalloc(sizeof(struct logsess));
		slog->pi = 0;
		const char* lal = getConfigValue(serv, "access-log");
		slog->access_fd = lal == NULL ? NULL : fopen(lal, "a");
		const char* lel = getConfigValue(serv, "error-log");
		slog->error_fd = lel == NULL ? NULL : fopen(lel, "a");
		if (serv->id != NULL) acclog(slog, "Server %s listening for connections!", serv->id);
		else acclog(slog, "Server listening for connections!");
		struct accept_param* ap = xmalloc(sizeof(struct accept_param));
		ap->port = port;
		ap->server_fd = sfd;
		ap->config = serv;
		ap->works_count = tc;
		ap->logsess = slog;
		int vhc = 0;
		struct vhost** vohs = NULL;
		char* ovh = xstrdup(getConfigValue(serv, "vhosts"), 0);
		char* np = NULL;
		while ((np = strchr(ovh, ',')) != NULL || strlen(ovh) > 0) {
			if (np != NULL) {
				np[0] = 0;
				np++;
			}
			ovh = trim(ovh);
			struct cnode* vcn = getCatByID(cfg, trim(ovh));
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
			const char* vht = getConfigValue(vcn, "type");
			if (streq(vht, "htdocs")) {
				cv->type = VHOST_HTDOCS;
			} else if (streq(vht, "reverse-proxy")) {
				cv->type = VHOST_RPROXY;
			} else if (streq(vht, "redirect")) {
				cv->type = VHOST_REDIRECT;
			} else if (streq(vht, "proxy")) {
				cv->type = VHOST_PROXY;
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
				vhb->htdocs = getConfigValue(vcn, "htdocs");
				if (vhb->htdocs == NULL) {
					errlog(slog, "No htdocs at vhost: %s", vcn->id);
					if (cv->hosts != NULL) xfree(cv->hosts);
					free(hnv);
					xfree(cv);
					vohs[vhc - 1] = NULL;
					vhc--;
					goto cont_vh;
				}
				vhb->htdocs = realpath(vhb->htdocs, NULL);
				size_t htl = strlen(vhb->htdocs);
				if (vhb->htdocs[htl - 1] != '/') {
					vhb->htdocs = xrealloc(vhb->htdocs, ++htl + 1);
					vhb->htdocs[htl - 1] = '/';
					vhb->htdocs[htl] = 0;
				}
				recur_mkdir(vhb->htdocs, 0750);
				const char* nhl = getConfigValue(vcn, "nohardlinks");
				vhb->nohardlinks = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				nhl = getConfigValue(vcn, "symlock");
				vhb->symlock = nhl == NULL ? 1 : streq_nocase(nhl, "true");
				const char* ic = getConfigValue(vcn, "index");
				if (ic == NULL) {
					errlog(slog, "No index at vhost: %s", vcn->id);
					if (cv->hosts != NULL) xfree(cv->hosts);
					free(hnv);
					xfree(cv);
					vohs[vhc - 1] = NULL;
					vhc--;
					goto cont_vh;
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
					vhb->index[vhb->index_count] = ivh;
					ivh = npi == NULL ? ivh + strlen(ivh) : npi;
				}
				for (int i = 0; i < vcn->entries; i++) {
					if (startsWith_nocase(vcn->keys[i], "error-")) {
						const char* en = vcn->keys[i] + 6;
						if (!strisunum(en)) {
							errlog(slog, "Invalid error page specifier at vhost: %s", vcn->id);
						}
						struct errpage* ep = xmalloc(sizeof(struct errpage));
						ep->code = en;
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
			} else if (cv->type == VHOST_RPROXY) {
				struct vhost_rproxy* vhb = &cv->sub.rproxy;

			} else if (cv->type == VHOST_REDIRECT) {
				struct vhost_redirect* vhb = &cv->sub.redirect;
				vhb->redir = getConfigValue(vcn, "redirect");
				if (vhb->redir == NULL) {
					errlog(slog, "No redirect at vhost: %s", vcn->id);
					if (cv->hosts != NULL) xfree(cv->hosts);
					free(hnv);
					xfree(cv);
					vohs[vhc - 1] = NULL;
					vhc--;
					goto cont_vh;
				}
			} else if (cv->type == VHOST_PROXY) {
				struct vhost_proxy* vhb = &cv->sub.proxy;

			}
			cont_vh: ovh = np == NULL ? ovh + strlen(ovh) : np;
		}
		ap->works = xmalloc(sizeof(struct work_param*) * tc);
		for (int x = 0; x < tc; x++) {
			struct work_param* wp = xmalloc(sizeof(struct work_param));
			wp->conns = new_collection(mc < 1 ? 0 : mc / tc, sizeof(struct conn*));
			wp->logsess = slog;
			wp->vhosts = vohs;
			wp->vhosts_count = vhc;
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
		}
	}
	while (sr > 0)
		sleep(1);
	return 0;
}
