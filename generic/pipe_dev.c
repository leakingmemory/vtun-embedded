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
#include <sys/socket.h>

#include "vtun.h"
#include "lib.h"
#include "linkfd_buffers.h"

/* 
 * Create pipe. Return open fd. 
 */  
int pipe_open(int *fd)
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
}

/* Write frames to pipe */
int pipe_write(int fd, LfdBuffer *buf)
{
    int res = write_n(fd, buf->ptr, buf->size);
    lfd_reset(buf);
    return res;
}

/* Read frames from pipe */
int pipe_read(int fd, LfdBuffer *buf)
{
    lfd_reset(buf);
    lfd_ensure_capacity(buf, VTUN_FRAME_SIZE);
    ssize_t rd = read(fd, buf->ptr, VTUN_FRAME_SIZE);
    if (rd >= 0) {
        buf->size = rd;
    }
    return rd;
}
