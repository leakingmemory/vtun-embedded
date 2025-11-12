/*  
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
	Copyright (C) 2025  Jan-Espen Oversand <sigsegv@radiotube.org>

    VTun has been derived from VPPP package by Maxim Krasnyansky. 

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 */

/*
 * Challenge based authentication. 
 * Thanx to Chris Todd<christ@insynq.com> for the good idea.
 */ 

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "lock.h"
#include "auth.h"
#include "auth_prim.h"
#include "dropcaps.h"

struct vtun_host * auth_server_v1(int fd, char *host);
struct vtun_host * auth_server_v2(int fd, char *host);

static struct vtun_host *auth_server_do(int fd)
{
    char buf[VTUN_MESG_SIZE], *str1, *str2;

    set_title("authentication");

    print_p(fd, "VTUN server ver %s\n", vtun.experimental ? VTUN_EXPERIMENTAL_VER : VTUN_VER);

    if (readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0) {
        buf[sizeof(buf) - 1] = '\0';
        strtok(buf, "\r\n");

        if ((str1 = strtok(buf, " :")) && (str2 = strtok(NULL, " :"))) {
            if (!strcmp(str1, "HOST")) {
                return auth_server_v1(fd, str2);
            } else if (!strcmp(str1, "HOS2")) {
                return auth_server_v2(fd, str2);
            }
        }
    }

    print_p(fd, "ERR\n");

    return NULL;
}

/* Authentication (Server side) */
static struct vtun_host * spawn_auth_server(int fd)
{
    if (vtun.setuid || vtun.setgid) {
        int fds[2];
        if (pipe(fds) < 0) {
            vtun_syslog(LOG_ERR, "pipe() failed: %s", strerror(errno));
            return NULL;
        }
        pid_t pid = fork();
        if (pid < 0) {
            vtun_syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
            close(fds[0]);
            close(fds[1]);
            return NULL;
        }
        if (pid == 0) {
            /* Child: drop privileges if root, perform authentication, serialize and write result */
            close(fds[0]);

            if (dropcaps_needed()) {
                if (!dropcaps_current_session()) {
                    _exit(3);
                }
                vtun_syslog(LOG_INFO, "Dropped privileges for authentication session");
            }

            struct vtun_host *h = auth_server_do(fd);
            if (h) {
                unlock_host(h);
                if (serialize_host_to_pipe(fds[1], h) == 0) {
                    _exit(0);
                } else {
                    _exit(2);
                }
            }
            _exit(1);
        } else {
            /* Parent: read child result, fix lock to our PID, and return host */
            close(fds[1]);
            int status = 0;
            struct vtun_host *res = NULL;

            struct vtun_host *child_host = deserialize_host_from_pipe(fds[0]);
            close(fds[0]);

            /* Wait for child to exit */
            while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR) continue;
                break;
            }

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && child_host) {
                /* Find host by name in our address space */
                res = find_host_server(child_host->host);
                if (!res) {
                    vtun_syslog(LOG_ERR, "Authenticated host '%s' not found in parent", child_host->host);
                    free_deserialized_host(child_host);
                    return NULL;
                }
                /* Apply fields from child to this host instance (native-endian) */
                int mismatch = res->flags != child_host->flags;
                mismatch |= res->timeout != child_host->timeout;
                mismatch |= res->spd_in != child_host->spd_in;
                mismatch |= res->spd_out != child_host->spd_out;
                mismatch |= res->zlevel != child_host->zlevel;
                mismatch |= res->cipher != child_host->cipher;
                mismatch |= res->experimental != child_host->experimental;
                mismatch |= res->persist != child_host->persist;
                mismatch |= res->multi != child_host->multi;
                mismatch |= res->ka_interval != child_host->ka_interval;
                mismatch |= res->ka_maxfail != child_host->ka_maxfail;
				if (mismatch) {
					vtun_syslog(LOG_ERR, "Host '%s' in parent differs from authenticated host", res->host);
					free_deserialized_host(child_host);
					return NULL;
				}
                /* Replace lock with parent PID */
                if (lock_host(res) < 0) {
                    vtun_syslog(LOG_ERR, "Failed to acquire lock for host '%s' in parent", child_host->host);
                    free_deserialized_host(child_host);
                    return NULL;
                }
                free_deserialized_host(child_host);
                return res;
            }
            if (child_host) {
                free_deserialized_host(child_host);
            }
            return NULL;
        }
    }

    /* Fallback: no setuid handling, do authentication inline */
    return auth_server_do(fd);
}

/* Authentication (Server side) */
struct vtun_host * auth_server(int fd) {
    struct vtun_host *host = spawn_auth_server(fd);
    if (host != NULL &&
        (host->requires_flags & VTUN_REQUIRES_ENCRYPTION) != 0 &&
        (host->flags & VTUN_ENCRYPT) == 0) {
        vtun_syslog(LOG_ERR, "Connection rejected because of lack of encryption (requires encryption configured)");
        return NULL;
    }
    return host;
}

int auth_client_v1(int fd, struct vtun_host *host);
int auth_client_v2(int fd, struct vtun_host *host);

static int do_auth_client(int fd, struct vtun_host *host)
{
	char buf[VTUN_MESG_SIZE];

	if( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
		buf[sizeof(buf)-1]='\0';
		if( strncmp(buf,"VTUN",4) ){
			return 0;
		}
		int proto_major = 3;
		int proto_minor = 0;
		if (!strncmp(buf, "VTUN server ver ", 16)) {
			char *end_major;
			proto_major = strtol(buf + 16, &end_major, 10);
			if (end_major != (buf + 16) && proto_major >= 3 && end_major[0] == '.' && end_major[1] != 'X') {
				char *end_minor;
				proto_minor = strtol(end_major + 1, &end_minor, 10);
			}
		}
		vtun_syslog(LOG_INFO, "Protocol version read as %d.%d", proto_major, proto_minor);
		if (!host->experimental && (proto_major > 3 || (proto_major == 3 && proto_minor > 0))) {
			proto_major = 3;
			proto_minor = 0;
		}
		if (proto_major > 3 || (proto_major == 3 && proto_minor > 0)) {
			vtun_syslog(LOG_INFO, "Using 3.1 authentication");
			return auth_client_v2(fd, host);
		} else {
			vtun_syslog(LOG_INFO, "Using 3.0 authentication");
			return auth_client_v1(fd, host);
		}
	}

	return 0;
}

static int spawn_auth_client(int fd, struct vtun_host *host)
{
    if (vtun.setuid || vtun.setgid) {
        int fds[2];
        if (pipe(fds) < 0) {
            vtun_syslog(LOG_ERR, "pipe() failed: %s", strerror(errno));
            return 0;
        }
        pid_t pid = fork();
        if (pid < 0) {
            vtun_syslog(LOG_ERR, "fork() failed: %s", strerror(errno));
            close(fds[0]);
            close(fds[1]);
            return 0;
        }
        if (pid == 0) {
            /* Child: drop privileges if root, perform authentication, serialize and write result */
            close(fds[0]);

            if (dropcaps_needed()) {
                if (!dropcaps_current_session()) {
                    _exit(3);
                }
                vtun_syslog(LOG_INFO, "Dropped privileges for authentication session");
            }

            int res = do_auth_client(fd, host);
            if (res) {
                if (serialize_host_to_pipe(fds[1], host) == 0) {
                    _exit(0);
                } else {
                    _exit(2);
                }
            }
            _exit(1);
        } else {
            /* Parent: read child result, fix lock to our PID, and return host */
            close(fds[1]);
            int status = 0;

            struct vtun_host *child_host = deserialize_host_from_pipe(fds[0]);
            close(fds[0]);

            /* Wait for child to exit */
            while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR) continue;
                break;
            }

            if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && child_host) {
                /* Apply fields from child to this host instance (native-endian) */
                host->flags = child_host->flags;
                host->timeout = child_host->timeout;
                host->spd_in = child_host->spd_in;
                host->spd_out = child_host->spd_out;
                host->zlevel = child_host->zlevel;
                host->cipher = child_host->cipher;
                host->experimental = child_host->experimental;
                host->persist = child_host->persist;
                host->multi = child_host->multi;
                host->ka_interval = child_host->ka_interval;
                host->ka_maxfail = child_host->ka_maxfail;
                free_deserialized_host(child_host);
                return 1;
            }
            if (child_host) {
                free_deserialized_host(child_host);
            }
            return 0;
        }
    }
	return do_auth_client(fd, host);
}

/* Authentication (Client side) */
int auth_client(int fd, struct vtun_host *host) {
    int result = spawn_auth_client(fd, host);
    if (result &&
        (host->requires_flags & VTUN_REQUIRES_ENCRYPTION) != 0 &&
        (host->flags & VTUN_ENCRYPT) == 0) {
        vtun_syslog(LOG_ERR, "Connection rejected because of lack of encryption (requires encryption configured)");
        return 0;
    }
    return result;
}
