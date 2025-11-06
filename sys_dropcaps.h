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

#ifndef VTUN_EMBEDDED_SYS_DROPCAPS_H
#define VTUN_EMBEDDED_SYS_DROPCAPS_H

int dropcaps_supported();
int proc_dropcaps(int is_root, int will_setuid);

#endif //VTUN_EMBEDDED_SYS_DROPCAPS_H