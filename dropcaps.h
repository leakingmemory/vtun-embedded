/*
    VTun-embedded - Virtual Tunnel over TCP/IP network.

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

#ifndef VTUN_EMBEDDED_DROPCAPS_H
#define VTUN_EMBEDDED_DROPCAPS_H

int serialize_host_to_pipe(int fd, const struct vtun_host *h);
struct vtun_host *deserialize_host_from_pipe(int fd);
void free_deserialized_host(struct vtun_host *h);
int dropcaps_needed();
int dropcaps_current_session();

#endif //VTUN_EMBEDDED_DROPCAPS_H