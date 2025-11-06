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
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/capability.h>
#include <string.h>
#include <stdint.h>

int dropcaps_supported() {
    return 1;
}

int set_no_new_privs();
int drop_capsets(int drop_bounding, int drop_setuid);

int proc_dropcaps(int is_root, int will_setuid) {
    if (!is_root || !will_setuid) {
        if (set_no_new_privs() != 0) {
            vtun_syslog(LOG_ERR, "set_no_new_privs() failed");
            return -1;
        }
    }
    return drop_capsets(is_root, !is_root);
}

int set_no_new_privs() {
    int ret = prctl(PR_SET_NO_NEW_PRIVS, 1L, 0L, 0L, 0L);
    if (ret != 0) {
        vtun_syslog(LOG_ERR, "Unable to set no_new_privs");
        return -1;
    }
    return 0;
}

struct CapHdr {
    uint32_t version;
    uint32_t pid;
    uint64_t padding[7];
};

struct CapDataPoint {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};

struct CapData {
    struct CapDataPoint capabilities[8];
    uint32_t padding[8];
};

int drop_capsets(int drop_bounding, int drop_setuid) {
    if (drop_bounding) {
        long cap;
        for (cap = 0; cap < 63; cap++) {
            if (!drop_setuid && (cap == CAP_SETGID || cap == CAP_SETUID)) {
                continue;
            }
            int capread = prctl(PR_CAPBSET_READ, cap);
            if (capread < 0) {
                break;
            }
            if ((capread & 1) == 0) {
                continue;
            }
            if (prctl(PR_CAPBSET_DROP, cap, 0L, 0L, 0L) < 0) {
                vtun_syslog(LOG_ERR, "Unable to drop capability from bounding set");
            }
        }
    }

    // Drop ambient set capabilities
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0L, 0L, 0L) != 0) {
        vtun_syslog(LOG_ERR, "Unable to drop capabilities from ambient set");
    }

    // Drop effective, permitted and inheritable capabilities
    struct CapHdr hdr;
    struct CapData data;
    memset(&hdr, 0, sizeof(hdr));
    memset(&data, 0, sizeof(data));
    hdr.version = 0x20080522;
    hdr.pid = 0;
    if (syscall(SYS_capget, &hdr, &data) < 0) {
        vtun_syslog(LOG_ERR, "Unable to get capabilities: %s", strerror(errno));
    }
    uint32_t i;
    for (i = 0; i < 4; i++) {
        uint32_t base_cap = i * 32;
        uint32_t next_cap = base_cap + 32;
        uint32_t mask = 0;
        if (!drop_setuid) {
            if (CAP_SETGID >= base_cap && CAP_SETGID < next_cap) {
                mask |= 1 << (CAP_SETGID - base_cap);
            }
            if (CAP_SETUID >= base_cap && CAP_SETUID < next_cap) {
                mask |= 1 << (CAP_SETUID - base_cap);
            }
        }
        data.capabilities[i].effective &= mask;
        data.capabilities[i].permitted &= mask;
        data.capabilities[i].inheritable &= mask;
    }
    if (syscall(SYS_capset, &hdr, &data) < 0) {
        vtun_syslog(LOG_ERR, "Unable to set capabilities: %s", strerror(errno));
    }
    return 0;
}
