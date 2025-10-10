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

#ifdef __linux__
#define _GNU_SOURCE // getpt, grantpt
#define _XOPEN_SOURCE // unlockpt
#endif

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
 * Allocate pseudo tty, returns master side fd. 
 * Stores slave name in the first arg(must be large enough).
 */  
int pty_open(char *sl_name)
{
    int  mr_fd;
#if defined (HAVE_GETPT) && defined (HAVE_GRANTPT) && defined (HAVE_UNLOCKPT) && defined (HAVE_PTSNAME)
    char *ptyname;

    if((mr_fd=getpt()) < 0)
 	return -1;
    if(grantpt(mr_fd) != 0)
	return -1;
    if(unlockpt(mr_fd) != 0)
	return -1;
    if ((ptyname = (char*)ptsname(mr_fd)) == NULL)
	return -1;
    strcpy(sl_name, ptyname);
    return mr_fd;

#else

    char ptyname[] = "/dev/ptyXY";
    char ch[] = "pqrstuvwxyz";
    char digit[] = "0123456789abcdefghijklmnopqrstuv";
    int  l, m;

    /* This algorithm should work for almost all standard Unices */	
    for(l=0; ch[l]; l++ ) {
        for(m=0; digit[m]; m++ ) {
	 	ptyname[8] = ch[l];
		ptyname[9] = digit[m];
		/* Open the master */
		if( (mr_fd=open(ptyname, O_RDWR)) < 0 )
	 	   continue;
		/* Check the slave */
		ptyname[5] = 't';
		if( (access(ptyname, R_OK | W_OK)) < 0 ){
		   close(mr_fd);
		   ptyname[5] = 'p';
		   continue;
		}
		strcpy(sl_name,ptyname);
		return mr_fd;
	    }
	}
	return -1;
#endif
}

/* Write frames to PTY device */
int pty_write(int fd, LfdBuffer *buf)
{
    int res = write_n(fd, buf->ptr, buf->size);
	lfd_reset(buf);
	return res;
}

/* Read frames from PTY device */
int pty_read(int fd, LfdBuffer *buf)
{
	lfd_reset(buf);
	lfd_ensure_capacity(buf, VTUN_FRAME_SIZE);
    ssize_t rd = read(fd, buf->ptr, VTUN_FRAME_SIZE);
	if (rd >= 0) {
		buf->size = rd;
	}
	return rd;
}
