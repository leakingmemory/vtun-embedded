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

#include "md5.h"
#include <string.h>
#include <stdio.h>
#include <endian.h>

const uint32_t shifts[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

const uint32_t K[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

void md5_init(Md5Context *ctx) {
    ctx->a = 0x67452301;
    ctx->b = 0xefcdab89;
    ctx->c = 0x98badcfe;
    ctx->d = 0x10325476;
    ctx->bits = 0;
}

static void md5_round(Md5Context *ctx, void *msg) {
    uint32_t a = ctx->a,
             b = ctx->b,
             c = ctx->c,
             d = ctx->d;
    uint32_t m[16];
    {
        uint32_t *p = (uint32_t *) msg;
        int i;
        for (i = 0; i < 16; i++) {
            m[i] = le32toh(p[i]);
        }
    }
    int i;
    for (i = 0; i < 64; i++) {
        uint32_t f, g;
        if (i < 16) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32) {
            f = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        } else if (i < 48) {
            f = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        } else {
            f = c ^ (b | (~d));
            g = (7 * i) % 16;
        }
        f = f + a + K[i] + m[g];
        a = d;
        d = c;
        c = b;
        b = b + ((f << shifts[i]) | (f >> (32 - shifts[i])));
    }
    ctx->a += a;
    ctx->b += b;
    ctx->c += c;
    ctx->d += d;
}

size_t md5_update(Md5Context *ctx, void *buf, size_t len) {
    len &= ~((size_t) 63);
    size_t off;
	for (off = 0; off < len; off += 64) {
		md5_round(ctx, buf + off);
	}
	ctx->bits += len << 3;
	return len;
}

void md5_final(md5_hash *result, Md5Context *ctx, void *buf, size_t len) {
	if (len >= 64) {
		size_t end = len & 63;
		md5_update(ctx, buf, len - end);
		buf += len - end;
		len = end;
	}
	ctx->bits += len << 3;
	char padded[64];
	memcpy(padded, buf, len);
	padded[len] = 0x80;
	len++;
	if (len > 56) {
        size_t i;
		for (i = len; i < 64; i++) {
			padded[i] = 0;
		}
		md5_round(ctx, padded);
		len = 0;
	}
    size_t i;
	for (i = len; i < 56; i++) {
		padded[i] = 0;
	}
	ctx->bits = htole64(ctx->bits);
    memcpy(padded + 56, &ctx->bits, 8);
	md5_round(ctx, padded);
	((uint32_t *) result)[0] = htole32(ctx->a);
	((uint32_t *) result)[1] = htole32(ctx->b);
	((uint32_t *) result)[2] = htole32(ctx->c);
	((uint32_t *) result)[3] = htole32(ctx->d);
}
