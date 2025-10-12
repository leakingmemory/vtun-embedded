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

#include "config.h"

#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <errno.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "linkfd_buffers.h"

int tcp_write(int fd, LfdBuffer *buf, int flags)
{
	register char *ptr;

	if (buf->size > (VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)) {
		buf->size = VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
	}
	{
		size_t len = buf->size | (flags & ~VTUN_FSIZE_MASK);
		if (!lfd_extend_below(buf, sizeof(short))) {
            return -1;
        }
		ptr = buf->ptr;

		*((unsigned short *)ptr) = htons(len);
	}

	return write_n(fd, ptr, buf->size);
}

int tcp_read(int fd, LfdBuffer *buf)
{
	unsigned short len, flen;
	register int rlen;

	/* Read frame size */
	if( (rlen = read_n(fd, (char *)&len, sizeof(short)) ) <= 0) {
		return -1;
	}

	len = ntohs(len);
	flen = len & VTUN_FSIZE_MASK;

	if( flen > VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD ){
		/* Oversized frame, drop it. */
		while( flen ){
			len = min(flen, VTUN_FRAME_SIZE);
			if (!lfd_ensure_capacity(buf, len)) {
				return VTUN_BAD_FRAME;
			}
			if( (rlen = read_n(fd, buf->ptr, len)) <= 0 )
				break;
			flen -= rlen;
		}
		return VTUN_BAD_FRAME;
	}

	if( len & ~VTUN_FSIZE_MASK ){
		/* Return flags */
		return len;
	}

	/* Read frame */
	if (!lfd_ensure_capacity(buf, flen)) {
		return -1;
	}
	int res = read_n(fd, buf->ptr, flen);
	if (res < 0) {
		return res;
	}
	buf->size = res;
	return res;
}
