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

#ifndef _LINKFD_BUFFERS_H
#define _LINKFD_BUFFERS_H

//#define DEBUG_LFD_ALLOC
//#define DEBUG_LFD_REALLOC
//#define DEBUG_LFD_EXTEND_BELOW
//#define DEBUG_LFD_REDUCE_BELOW
//#define DEBUG_LFD_ENSURE_CAPACITY
//#define DEBUG_LFD_SUB_EXTEND_BELOW
//#define DEBUG_LFD_SUB_EXTEND
//#define DEBUG_LFD_SUB_REDUCE
//#define DEBUG_LFD_SLOW
//#define DEBUG_LFD_SUB_SET_SIZE

#if defined(DEBUG_LFD_ALLOC)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_REALLOC)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_EXTEND_BELOW)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_REDUCE_BELOW)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_ENSURE_CAPACITY)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_SUB_EXTEND_BELOW)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_SUB_EXTEND)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_SUB_REDUCE)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_SLOW)
#define LINKFD_BUFFERS_DEBUG_MASTER
#elif defined(DEBUG_LFD_SUB_SET_SIZE)
#define LINKFD_BUFFERS_DEBUG_MASTER
#endif

#include <string.h>
#include <stdlib.h>
#ifdef LINKFD_BUFFERS_DEBUG_MASTER
#include <stdio.h>
#endif
#include "linkfd_types.h"

/* Frame alloc/free */
#define LINKFD_FRAME_RESERV 128
#define LINKFD_FRAME_APPEND 64

static inline LfdBuffer lfd_alloc(size_t size)
{
    register void * buf;

    size += LINKFD_FRAME_RESERV + LINKFD_FRAME_APPEND;

    LfdBuffer lfd;
    if ((buf = malloc(size)) != NULL) {
        lfd.ptr = buf+LINKFD_FRAME_RESERV;
        lfd.offset = LINKFD_FRAME_RESERV;
        lfd.size = 0;
        lfd.total = size;
    } else {
        lfd.ptr = NULL;
        lfd.offset = 0;
        lfd.size = 0;
        lfd.total = 0;
    }
#ifdef DEBUG_LFD_ALLOC
		printf("lfd_alloc: %p off=%zu %zu, requested %zu\n", lfd.ptr, lfd.offset, lfd.total, size - LINKFD_FRAME_RESERV - LINKFD_FRAME_APPEND);
#endif
    return lfd;
}

static inline void lfd_reset(LfdBuffer *buf) {
    buf->ptr = buf->ptr - buf->offset + LINKFD_FRAME_RESERV;
    buf->offset = LINKFD_FRAME_RESERV;
    buf->size = 0;
    if (buf->total < buf->offset) {
        buf->ptr = buf->ptr - buf->offset + buf->total;
        buf->offset = buf->total;
    }
}

static inline int lfd_realloc(LfdBuffer *buf, size_t size)
{
    void *ptr = buf->ptr;

    ptr  -= buf->offset;
    size += LINKFD_FRAME_RESERV;

    if ((ptr = realloc(ptr, size)) != NULL) {
        if (buf->offset > size) {
            buf->offset = size;
        }
        buf->ptr = ptr+buf->offset;
        buf->total = size;
        if (buf->size > (buf->total - buf->offset)) {
            buf->size = buf->total - buf->offset;
        }
    } else if (size == 0) {
        buf->ptr = NULL;
        buf->offset = 0;
        buf->size = 0;
        buf->total = 0;
    } else {
#ifdef DEBUG_LFD_ALLOC
		printf("lfd_realloc failed: %p off=%zu %zu, requested %zu\n", buf->ptr, buf->offset, buf->total, size - LINKFD_FRAME_RESERV);
#endif
        return 0;
    }
#ifdef DEBUG_LFD_ALLOC
		printf("lfd_realloc: %p off=%zu %zu, requested %zu\n", buf->ptr, buf->offset, buf->total, size - LINKFD_FRAME_RESERV);
#endif
    return 1;
}

static inline int lfd_extend_below(LfdBuffer *buf, size_t extend_by_size)
{
    if (extend_by_size <= buf->offset) {
        buf->offset -= extend_by_size;
        buf->ptr -= extend_by_size;
        buf->size += extend_by_size;
    } else {
        size_t expand = extend_by_size - buf->offset;
        size_t off_plus_size = buf->offset + buf->size;
        size_t available_extend = buf->total - off_plus_size;
        if (expand > available_extend) {
#if defined(DEBUG_LFD_EXTEND_BELOW) || defined(DEBUG_LFD_SLOW)
	    	printf("lfd_extend_below: realloc %zu + %zu\n", off_plus_size, expand);
#endif
            if (!lfd_realloc(buf, off_plus_size + expand)) {
                return 0;
            }
        }
#if defined(DEBUG_LFD_EXTEND_BELOW) || defined(DEBUG_LFD_SLOW)
	    printf("lfd_extend_below: memmove +%zu %zu\n", expand, buf->size);
#endif
        memmove(buf->ptr + expand, buf->ptr, buf->size);
        buf->ptr -= buf->offset;
        buf->offset = 0;
        buf->size += extend_by_size;
    }
#ifdef DEBUG_LFD_EXTEND_BELOW
	printf("lfd_extend_below: %p off=%zu %zu, requested %zu\n", buf->ptr, buf->offset, buf->total, extend_by_size);
#endif
    return 1;
}

static inline void lfd_reduce_below(LfdBuffer *buf, size_t reduce_by_size)
{
    if (reduce_by_size >= buf->size) {
#ifdef DEBUG_LFD_REDUCE_BELOW
		printf("lfd_reduce_below offset optimized +%zu -> +0 (size=0)\n", buf->size);
#endif
		buf->size = 0;
		return;
	}
    buf->ptr += reduce_by_size;
    buf->offset += reduce_by_size;
    buf->size -= reduce_by_size;
}

static inline int lfd_ensure_capacity(LfdBuffer *buf, size_t size)
{
    if ((size + buf->offset) > buf->total) {
#if defined(DEBUG_LFD_ENSURE_CAPACITY) || defined(DEBUG_LFD_SLOW)
		printf("lfd_ensure_capacity: insuficcient, realloc %zu + %zu > %zu\n", size, buf->offset, buf->total);
#endif
        if (!lfd_realloc(buf, size + buf->offset)) {
            return 0;
        }
    }
#ifdef DEBUG_LFD_ENSURE_CAPACITY
		printf("lfd_ensure_capacity: ok, %zu + %zu <= %zu\n", size, buf->offset, buf->total);
#endif
    return 1;
}

static inline int lfd_extend(LfdBuffer *buf, size_t extend_by)
{
    size_t caps = buf->offset + buf->size + extend_by;
    if (!lfd_ensure_capacity(buf, caps)) {
        return 0;
    }
    buf->size += extend_by;
    return 1;
}

static inline void lfd_free(LfdBuffer *buf)
{
    unsigned char *ptr = buf->ptr;

    if (ptr == NULL) return;

    free(ptr-buf->offset);
    buf->ptr = NULL;
    buf->offset = 0;
    buf->size = 0;
    buf->total = 0;
}

static inline void *lfd_get_ptr(LfdBuffer *buf, size_t offset)
{
    return buf->ptr + offset;
}

static inline LfdSubBuffer lfd_sub_buffer(LfdBuffer *buf, size_t displaced_start, size_t length)
{
    LfdSubBuffer sub;
    sub.buf = buf;
    if (displaced_start > buf->size) {
        displaced_start = buf->size;
    }
    sub.displaced_start = displaced_start;
    if (length > (buf->size - displaced_start)) {
        length = buf->size - displaced_start;
    }
    sub.displaced_end = buf->size - displaced_start - length;
    return sub;
}

static inline void *lfd_sub_get_ptr(LfdSubBuffer *sub, size_t offset) {
    return lfd_get_ptr(sub->buf, sub->displaced_start + offset);
}

static inline size_t lfd_sub_get_size(LfdSubBuffer *sub) {
    size_t size = sub->buf->size;
    if (size < sub->displaced_start) {
        return 0;
    }
    size -= sub->displaced_start;
    if (size < sub->displaced_end) {
        return 0;
    }
    return size - sub->displaced_end;
}

static inline int lfd_sub_extend_below(LfdSubBuffer *sub, size_t extend_by_size)
{
    if (!lfd_extend_below(sub->buf, extend_by_size)) {
        return 0;
    }
    if (sub->displaced_start > 0) {
#if defined(DEBUG_LFD_SUB_EXTEND_BELOW) || defined(DEBUG_LFD_SLOW)
		printf("lfd_sub_extend_below: +%zu -> +0, %zu\n", extend_by_size, sub->displaced_start);
#endif
        memmove(lfd_get_ptr(sub->buf, 0), lfd_get_ptr(sub->buf, extend_by_size), sub->displaced_start);
    } else {
#ifdef DEBUG_LFD_SUB_EXTEND_BELOW
		printf("lfd_sub_extend_below: %zu\n", extend_by_size);
#endif
	}
    return 1;
}

static inline int lfd_sub_extend(LfdSubBuffer *sub, size_t extend_by_size) {
    if (!lfd_extend(sub->buf, extend_by_size)) {
        return 0;
    }
    if (sub->displaced_end > 0) {
#if defined(DEBUG_LFD_SUB_EXTEND) || defined(DEBUG_LFD_SLOW)
		printf("lfd_sub_extend: +%zu -> +%zu, %zu\n", sub->buf->size - extend_by_size - sub->displaced_end, sub->buf->size - sub->displaced_end, sub->displaced_end);
#endif
        memmove(lfd_get_ptr(sub->buf, sub->buf->size - sub->displaced_end), lfd_get_ptr(sub->buf, sub->buf->size - extend_by_size - sub->displaced_end), sub->displaced_end);
    } else {
#ifdef DEBUG_LFD_SUB_EXTEND
		printf("lfd_sub_extend: %zu\n", sub->displaced_end);
#endif
	}
    return 1;
}

static inline int lfd_sub_reduce(LfdSubBuffer *sub, size_t reduce_by_size) {
    size_t size = lfd_sub_get_size(sub);
    if (reduce_by_size > size) {
        reduce_by_size = size;
    }
    if (reduce_by_size == 0) {
#ifdef DEBUG_LFD_SUB_REDUCE
		printf("lfd_sub_reduce: 0\n");
#endif
        return 1;
    }
    if (sub->displaced_end > 0) {
#if defined(DEBUG_LFD_SUB_REDUCE) || defined(DEBUG_LFD_SLOW)
		printf("lfd_sub_reduce: +%zu -> +%zu %zu\n", sub->buf->size - sub->displaced_end, sub->buf->size - sub->displaced_end - reduce_by_size, sub->displaced_end);
#endif
        memmove(lfd_get_ptr(sub->buf, sub->buf->size - sub->displaced_end - reduce_by_size), lfd_get_ptr(sub->buf, sub->buf->size - sub->displaced_end), sub->displaced_end);
    }
    sub->buf->size -= reduce_by_size;
    return 1;
}

static inline int lfd_sub_set_size(LfdSubBuffer *sub, size_t size) {
    size_t cur_size = lfd_sub_get_size(sub);
    if (cur_size < size) {
        return lfd_sub_extend(sub, size - cur_size);
    } else if (cur_size > size) {
        return lfd_sub_reduce(sub, cur_size - size);
    }
#ifdef DEBUG_LFD_SUB_SET_SIZE
    printf("lfd_sub_set_size: no change, %zu\n", size);
#endif
    return 1;
}

#endif
