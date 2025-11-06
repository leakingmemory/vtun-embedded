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

#include <stdio.h>
#include "vtun.h"
#include "lib.h"
#include <syslog.h>

int dropcaps_supported() {
    return 0;
}

int proc_dropcaps(int is_root, int will_setuid) {
    vtun_syslog(LOG_ERR, "Dropcaps not supported on this platform");
    return -1;
}
