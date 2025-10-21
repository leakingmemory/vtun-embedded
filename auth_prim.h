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

#ifndef VTUN_EMBEDDED_AUTH_PRIM_H
#define VTUN_EMBEDDED_AUTH_PRIM_H

void auth_prim_gen_chal(char *buf);
void auth_prim_encrypt_chal(char *chal, char *pwd);
void auth_prim_decrypt_chal(char *chal, char *pwd);
char *auth_prim_bf2cf(struct vtun_host *host);
int auth_prim_cf2bf(char *str, struct vtun_host *host);
int auth_prim_cs2cl(char *str, char *chal);
char *auth_prim_cl2cs(char *chal);

#define gen_chal auth_prim_gen_chal
#define bf2cf auth_prim_bf2cf
#define cf2bf auth_prim_cf2bf
#define encrypt_chal auth_prim_encrypt_chal
#define decrypt_chal auth_prim_decrypt_chal
#define cs2cl auth_prim_cs2cl
#define cl2cs auth_prim_cl2cs

#endif //VTUN_EMBEDDED_AUTH_PRIM_H