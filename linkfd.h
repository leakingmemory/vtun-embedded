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

#ifndef _LINKFD_H
#define _LINKFD_H

#include <string.h>
#include "linkfd_types.h"

/* Priority of the process in the link_fd function */
/* Never set the priority to -19 without stating a good reason.
 *#define LINKFD_PRIO -19
 * Since the likely intent was just to give vtun an edge,
 * -1 will do nicely.
 */
#define LINKFD_PRIO -1

int linkfd(struct vtun_host *host);

/* Module */
struct lfd_mod {
   char *name;
   int (*alloc)(struct vtun_host *host);
   int (*encode)(LfdBuffer *buf);
   int (*avail_encode)(void);
   int (*decode)(LfdBuffer *buf);
   int (*avail_decode)(void);
   int (*free)(void);

   struct lfd_mod *next;
   struct lfd_mod *prev;
};

/* External LINKFD modules */

extern struct lfd_mod lfd_zlib;
extern struct lfd_mod lfd_lzo;
extern struct lfd_mod lfd_encrypt;
extern struct lfd_mod lfd_legacy_encrypt;
extern struct lfd_mod lfd_shaper;

#endif
