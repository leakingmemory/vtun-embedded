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

#ifndef VTUN_EMBEDDED_BLOWFISH_H
#define VTUN_EMBEDDED_BLOWFISH_H

#include <stdint.h>

typedef struct {
    uint32_t p[18];
    uint32_t s[1024];
} BlowfishContext;

int blowfish_init(BlowfishContext *ctx, void *key, int key_length_bytes);
void blowfish_encrypt_8bytes_le(BlowfishContext *ctx, void *block);
void blowfish_decrypt_8bytes_le(BlowfishContext *ctx, void *block);
void blowfish_encrypt_8bytes_ecb(BlowfishContext *ctx, void *block);
void blowfish_decrypt_8bytes_ecb(BlowfishContext *ctx, void *block);

#endif //VTUN_EMBEDDED_BLOWFISH_H