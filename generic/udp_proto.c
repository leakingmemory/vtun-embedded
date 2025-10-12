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
#include <ctype.h>
#include <stdarg.h>
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
#include <netinet/udp.h>
#endif

#include "vtun.h"
#include "lib.h"
#include "linkfd_buffers.h"

extern int is_rmt_fd_connected; 

/* Functions to read/write UDP frames. */
int udp_write(int fd, LfdBuffer *buf, int flags)
{
    register char *ptr;
    register int wlen;

    if (!is_rmt_fd_connected) return 0;

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

    while( 1 ){
        if( (wlen = write(fd, ptr, buf->size)) < 0 ){
            if( errno == EAGAIN || errno == EINTR )
                continue;
            if( errno == ENOBUFS )
                return 0;
        }
        /* Even if we wrote only part of the frame
        * we can't use second write since it will produce
        * another UDP frame */
        return wlen;
    }
}

int udp_read(int fd, LfdBuffer *buf)
{
    unsigned short hdr, flen;
    struct iovec iv[2];
    register int rlen;
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(struct sockaddr);

    lfd_reset(buf);
    /* Late connect (NAT hack enabled) */
    if (!is_rmt_fd_connected) {
        while( 1 ){
            if (!lfd_ensure_capacity(buf, 2)) return -1;
            if( (rlen = recvfrom(fd,buf->ptr,2,MSG_PEEK,(struct sockaddr *)&from,&fromlen)) < 0 ){
                if( errno == EAGAIN || errno == EINTR ) continue;
                else return rlen;
            }
            else break;
        }
        if( connect(fd,(struct sockaddr *)&from,fromlen) ){
            vtun_syslog(LOG_ERR,"Can't connect socket");
            return -1;
        }
        is_rmt_fd_connected = 1;
    }

    /* Read frame */
    if (!lfd_ensure_capacity(buf, VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD)) return -1;
    iv[0].iov_len  = sizeof(short);
    iv[0].iov_base = (char *) &hdr;
    iv[1].iov_len  = VTUN_FRAME_SIZE + VTUN_FRAME_OVERHEAD;
    iv[1].iov_base = buf->ptr;

    while( 1 ){
        if( (rlen = readv(fd, iv, 2)) < 0 ){
            if( errno == EAGAIN || errno == EINTR )
                continue;
            else
                return rlen;
        }
        hdr = ntohs(hdr);
        flen = hdr & VTUN_FSIZE_MASK;

        if( rlen < 2 || (rlen-2) != flen )
            return VTUN_BAD_FRAME;

        buf->size = flen;
        return hdr;
    }
}		
