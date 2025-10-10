/*
    VTun - Virtual Tunnel over TCP/IP network.

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

#ifndef VTUN_EMBEDDED_LINKFD_TYPES_H
#define VTUN_EMBEDDED_LINKFD_TYPES_H

typedef struct {
    /*void *base*/ // The base ptr can be calculated by (ptr - offset)
    void *ptr; // base + offset
    size_t offset; // offset from base (base is the start of the memory allocation)
    size_t size; // size of the buffer (must be less than or equal to (total - offset))
    size_t total; // total size of the memory allocation
} LfdBuffer;

typedef struct {
    LfdBuffer *buf;
    size_t displaced_start; // start of the sub buffer is buf->ptr + displaced_start
    size_t displaced_end; // first byte after the sub buffer is buf->ptr + buf->size - displaced_end
} LfdSubBuffer;

#endif //VTUN_EMBEDDED_LINKFD_TYPES_H