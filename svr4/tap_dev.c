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
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <signal.h>
#include <stropts.h>
#include <net/if.h>
#include <net/if_tun.h>

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

/* 
 * Allocate Ether TAP device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */ 
int tap_open(char *dev)
{
    int tap_fd, if_fd, ppa = -1;
    static int ip_fd = 0;
    char *ptr;

    if( *dev ){
       ptr = dev;	
       while( *ptr && !isdigit((int)*ptr) ) ptr++; 
       ppa = atoi(ptr);
    }

    /* Check if IP device was opened */
    if( ip_fd )
       close(ip_fd);

    if( (ip_fd = open("/dev/ip", O_RDWR, 0)) < 0){
       syslog(LOG_ERR, "Can't open /dev/ip");
       return -1;
    }

    if( (tap_fd = open("/dev/tap", O_RDWR, 0)) < 0){
       syslog(LOG_ERR, "Can't open /dev/tap");
       return -1;
    }

    /* Assign a new PPA and get its unit number. */
    if( (ppa = ioctl(tap_fd, TUNNEWPPA, ppa)) < 0){
       syslog(LOG_ERR, "Can't assign new interface");
       return -1;
    }

    if( (if_fd = open("/dev/tap", O_RDWR, 0)) < 0){
       syslog(LOG_ERR, "Can't open /dev/tap (2)");
       return -1;
    }
    if(ioctl(if_fd, I_PUSH, "ip") < 0){
       syslog(LOG_ERR, "Can't push IP module");
       return -1;
    }

    /* Assign ppa according to the unit number returned by tap device */
    if(ioctl(if_fd, IF_UNITSEL, (char *)&ppa) < 0){
       syslog(LOG_ERR, "Can't set PPA %d", ppa);
       return -1;
    }
    if(ioctl(ip_fd, I_LINK, if_fd) < 0){
       syslog(LOG_ERR, "Can't link TAP device to IP");
       return -1;
    }

    sprintf(dev, "tap%d", ppa);
    return tap_fd;
}

int tap_close(int fd, char *dev)
{
    return close(fd);
}

int tap_write(int fd, LfdBuffer *buf)
{
    struct strbuf sbuf;
    sbuf.len = buf->size;
    sbuf.buf = buf->ptr;
    int res = putmsg(fd, NULL, &sbuf, 0) >= 0 ? sbuf.len : -1;
    lfd_reset(buf);
    return res;
}

int tap_read(int fd, LfdBuffer *buf)
{
    struct strbuf sbuf;
    int f = 0;

    lfd_reset(buf);
    if (!lfd_ensure_capacity(buf, VTUN_FRAME_SIZE)) {
         return -1;
    }
    sbuf.maxlen = VTUN_FRAME_SIZE;
    sbuf.buf = buf;      
    int res = getmsg(fd, NULL, &sbuf, &f) >= 0 ? sbuf.len : -1;
    if (res >= 0) {
        buf->size = res;
    }
    return res;
}
