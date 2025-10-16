/*
	VTun - Virtual Tunnel over TCP/IP network.

	Copyright (C) 2025  Jan-Espen Oversand <sigsegv@radiotube.org>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
 */

#ifndef VTUN_EMBEDDED_MD5_H
#define VTUN_EMBEDDED_MD5_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t a, b, c, d;
    uint64_t bits;
} Md5Context;

typedef uint8_t md5_hash[16];
typedef char md5_hex_str[33];

void md5_init(Md5Context *ctx);
size_t md5_update(Md5Context *ctx, void *buf, size_t len);
void md5_final(md5_hash *result, Md5Context *ctx, void *buf, size_t len);

inline void md5_tohex(md5_hex_str *result, md5_hash md) {
	for (int i = 0; i < 16; i++) {
		(*result)[i << 1] = (md[i] >> 4) <= 9 ? ((md[i] >> 4) + '0') : ((md[i] >> 4) + 'a' - 10);
		(*result)[(i << 1) + 1] = (md[i] & 0xf) <= 9 ? ((md[i] & 0xf) + '0') : ((md[i] & 0xf) + 'a' - 10);
	}
	(*result)[32] = '\0';
}

inline void md5(md5_hash *result, void *buf, size_t len) {
	Md5Context ctx;
	md5_init(&ctx);
	return md5_final(result, &ctx, buf, len);
}

inline void md5_hex(md5_hex_str *str, void *buf, size_t len) {
	md5_hash md;
	md5(&md, buf, len);
	md5_tohex(str, md);
}

#endif //VTUN_EMBEDDED_MD5_H