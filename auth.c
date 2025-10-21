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

struct vtun_host * auth_server_v1(int fd, char *host);
struct vtun_host * auth_server_v2(int fd, char *host);

/* Authentication (Server side) */
struct vtun_host * auth_server(int fd)
{
	char buf[VTUN_MESG_SIZE], *str1, *str2;

	set_title("authentication");

	print_p(fd,"VTUN server ver %s\n", vtun.experimental ? VTUN_EXPERIMENTAL_VER : VTUN_VER);

	if ( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
		buf[sizeof(buf)-1]='\0';
		strtok(buf,"\r\n");

		if( (str1=strtok(buf," :")) &&
		    (str2=strtok(NULL," :")) ) {
			if( !strcmp(str1,"HOST") ){
				return auth_server_v1(fd, str2);
			} else if ( !strcmp(str1,"HOS2") ) {
				return auth_server_v2(fd, str2);
			}
		}
	}

	print_p(fd,"ERR\n");

	return NULL;
}

int auth_client_v1(int fd, struct vtun_host *host);
int auth_client_v2(int fd, struct vtun_host *host);

/* Authentication (Client side) */
int auth_client(int fd, struct vtun_host *host)
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
