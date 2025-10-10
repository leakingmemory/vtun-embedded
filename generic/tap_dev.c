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
#include <syslog.h>

#include "vtun.h"
#include "lib.h"
#include "linkfd_buffers.h"

/* 
 * Allocate Ether TAP device, returns opened fd. 
 * Stores dev name in the first arg(must be large enough).
 */ 
int tap_open(char *dev)
{
    char tapname[14];
    int i, fd;

    if( *dev ) {
       sprintf(tapname, "/dev/%s", dev);
       return open(tapname, O_RDWR);
    }

    for(i=0; i < 255; i++) {
       sprintf(tapname, "/dev/tap%d", i);
       /* Open device */
       if( (fd=open(tapname, O_RDWR)) > 0 ) {
          sprintf(dev, "tap%d",i);
          return fd;
       }
    }
    return -1;
}

int tap_close(int fd, char *dev)
{
    return close(fd);
}

/* Write frames to TAP device */
int tap_write(int fd, LfdBuffer *buf)
{
    auto res = write(fd, buf->ptr, buf->size);
    lfd_reset(buf);
    return res;
}

/* Read frames from TAP device */
int tap_read(int fd, LfdBuffer *buf)
{
    lfd_reset(buf);
    lfd_ensure_capacity(buf, VTUN_FRAME_SIZE);
    ssize_t rd = read(fd, buf->ptr, VTUN_FRAME_SIZE);
    if (rd >= 0) {
        buf->size = rd;
    }
    return rd;
}
