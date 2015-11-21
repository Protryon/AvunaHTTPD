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
		char* dn = (char*) xcopy(DAEMON_NAME, strlen(DAEMON_NAME), 0);
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
	int pfpl = strlen(pid_file);
	char* pfp = xcopy(pid_file, pfpl + 1, 0);
	for (int i = pfpl - 1; i--; i >= 0) {
		if (pfp[i] == '/') {
			pfp[i] = 0;
			break;
		}
	}
	if (recur_mkdir(pfp, 0750) == -1) {
		printf("Error making directories for PID file: %s.\n", strerror(errno));
		return 1;
	}
//TODO: chown group to de-escalated
	FILE *pfd = fopen(pid_file, "w");
	if (pfd == NULL) {
		printf("Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
	if (fprintf(pfd, "%i", getpid()) < 0) {
		printf("Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
	if (fclose(pfd) < 0) {
		printf("Error writing PID file: %s.\n", strerror(errno));
		return 1;
	}
	int servsl;
	struct cnode** servs = getCatsByCat(cfg, CAT_SERVER, &servsl);
	int sr = 0;
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
				if (serv->id != NULL) printf("Invalid bind-port for server: %s\n", serv->id);
				else printf("Invalid bind-port for server.\n");
				continue;
			}
			port = atoi(bind_port);
			namespace = PF_INET;
		} else if (streq(bind_mode, "unix")) {
			bind_file = getConfigValue(serv, "bind-file");
			namespace = PF_LOCAL;
		} else {
			if (serv->id != NULL) printf("Invalid bind-mode for server: %s\n", serv->id);
			else printf("Invalid bind-mode for server.\n");
			continue;
		}
		const char* tcc = getConfigValue(serv, "threads");
		if (!strisunum(tcc)) {
			if (serv->id != NULL) printf("Invalid threads for server: %s\n", serv->id);
			else printf("Invalid threads for server.\n");
			continue;
		}
		int tc = atoi(tcc);
		const char* mcc = getConfigValue(serv, "max-conn");
		if (!strisunum(mcc)) {
			if (serv->id != NULL) printf("Invalid max-conn for server: %s\n", serv->id);
			else printf("Invalid max-conn for server.\n");
			continue;
		}
		int mc = atoi(mcc);
		const char* mpc = getConfigValue(serv, "max-post");
		if (!strisunum(mpc)) {
			if (serv->id != NULL) printf("Invalid max-post for server: %s\n", serv->id);
			else printf("Invalid max-post for server.\n");
			continue;
		}
		int mp = atoi(mpc);
		int sfd = socket(namespace, SOCK_STREAM, 0);
		if (sfd < 0) {
			if (serv->id != NULL) printf("Error creating socket for server: %s, %s\n", serv->id, strerror(errno));
			else printf("Error creating socket for server, %s\n", strerror(errno));
			continue;
		}
		if (namespace == PF_INET) {
			struct sockaddr_in bip;
			bip.sin_family = AF_INET;
			if (!inet_aton(bind_ip, &(bip.sin_addr))) {
				close (sfd);
				if (serv->id != NULL) printf("Error binding socket for server: %s, invalid bind-ip\n", serv->id);
				else printf("Error binding socket for server, invalid bind-ip\n");
				continue;
			}
			bip.sin_port = htons(port);
			if (bind(sfd, (struct sockaddr*) &bip, sizeof(bip))) {
				if (serv->id != NULL) printf("Error binding socket for server: %s, %s\n", serv->id, strerror(errno));
				else printf("Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else if (namespace == PF_LOCAL) {
			struct sockaddr_un uip;
			strncpy(uip.sun_path, bind_file, 108);
			if (bind(sfd, (struct sockaddr*) &uip, sizeof(uip))) {
				if (serv->id != NULL) printf("Error binding socket for server: %s, %s\n", serv->id, strerror(errno));
				else printf("Error binding socket for server, %s\n", strerror(errno));
				close (sfd);
				continue;
			}
		} else {
			if (serv->id != NULL) printf("Invalid family for server: %s\n", serv->id);
			else printf("Invalid family for server\n");
			close (sfd);
			continue;
		}
		if (listen(sfd, 50)) {
			if (serv->id != NULL) printf("Error listening on socket for server: %s, %s\n", serv->id, strerror(errno));
			else printf("Error listening on socket for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}
		int one = 1;
		if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one)) == -1) {
			if (serv->id != NULL) printf("Error setting SO_REUSEADDR for server: %s, %s\n", serv->id, strerror(errno));
			else printf("Error setting SO_REUSEADDR for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}
		if (fcntl(sfd, F_SETFL, fcntl(sfd, F_GETFL) | O_NONBLOCK) < 0) {
			if (serv->id != NULL) printf("Error setting non-blocking for server: %s, %s\n", serv->id, strerror(errno));
			else printf("Error setting non-blocking for server, %s\n", strerror(errno));
			close (sfd);
			continue;
		}

		if (serv->id != NULL) printf("Server %s listening for connections!\n", serv->id);
		else printf("Server listening for connections!\n");
		struct accept_param* ap = xmalloc(sizeof(struct accept_param));
		ap->port = port;
		ap->server_fd = sfd;
		ap->config = serv;
		ap->works_count = tc;
		ap->works = xmalloc(sizeof(struct work_param*) * tc);
		for (int i = 0; i < tc; i++) {
			struct work_param* wp = xmalloc(sizeof(struct work_param));
			wp->conns = new_collection(mc < 1 ? 0 : mc / tc, sizeof(struct conn));
			ap->works[i] = wp;
		}
		pthread_t pt;
		for (int i = 0; i < tc; i++) {
			pthread_create(&pt, NULL, (void *) run_work, ap->works[i]);
		}
		pthread_create(&pt, NULL, (void *) run_accept, ap);
		sr++;
	}
	while (sr > 0)
		sleep(1);
	return 0;
}
