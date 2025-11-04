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

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "vtun.h"
#include "lib.h"
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <syslog.h>


/* Helpers for pipe I/O (native-endian, same-arch child/parent) */
static int write_full(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;
    while (len > 0) {
        ssize_t wr = write(fd, p, len);
        if (wr < 0) return -1;
        p += (size_t)wr;
        len -= (size_t)wr;
    }
    return 0;
}

static int read_full(int fd, void *buf, size_t len)
{
    char *p = (char *)buf;
    while (len > 0) {
        ssize_t rr = read(fd, p, len);
        if (rr <= 0) return -1;
        p += (size_t)rr;
        len -= (size_t)rr;
    }
    return 0;
}

/* Serialize minimal vtun_host state to pipe. Native endianness by design. */
int serialize_host_to_pipe(int fd, const struct vtun_host *h)
{
    const uint32_t magic = 0x7674756E; /* 'vtun' */
    const uint16_t host_len = (uint16_t)(h->host ? strlen(h->host) : 0);
    const char *hoststr = h->host ? h->host : "";
    uint32_t fields[12];
    fields[0]  = (uint32_t) h->flags;
    fields[1]  = (uint32_t) h->timeout;
    fields[2]  = (uint32_t) h->spd_in;
    fields[3]  = (uint32_t) h->spd_out;
    fields[4]  = (uint32_t) h->zlevel;
    fields[5]  = (uint32_t) h->cipher;
    fields[6]  = (uint32_t) h->experimental;
    fields[7]  = (uint32_t) h->persist;
    fields[8]  = (uint32_t) h->multi;
    fields[9]  = (uint32_t) h->ka_interval;
    fields[10] = (uint32_t) h->ka_maxfail;
    fields[11] = 0;

    if (write_full(fd, &magic, sizeof(magic)) < 0) {
        return -1;
    }
    if (write_full(fd, &host_len, sizeof(host_len)) < 0) {
        return -1;
    }
    if (host_len && write_full(fd, hoststr, host_len) < 0) {
        return -1;
    }
    if (write_full(fd, fields, sizeof(fields)) < 0) {
        return -1;
    }
    return 0;
}

/* Deserialize vtun_host state from pipe. Allocates and returns vtun_host. */
struct vtun_host *deserialize_host_from_pipe(int fd)
{
    uint32_t magic = 0;
    uint16_t host_len = 0, dev_len = 0;

    if (read_full(fd, &magic, sizeof(magic)) < 0) {
        return NULL;
    }
    if (read_full(fd, &host_len, sizeof(host_len)) < 0) {
        return NULL;
    }

    if (magic != 0x7674756E || host_len > 1024) {
        return NULL;
    }

    char *hoststr = (char *)malloc((size_t)host_len + 1);
    if (!hoststr) {
        return NULL;
    }

    if (host_len && read_full(fd, hoststr, host_len) < 0) {
        free(hoststr);
        return NULL;
    }
    hoststr[host_len] = '\0';

    uint32_t fields[12];
    if (read_full(fd, fields, sizeof(uint32_t) * 12) < 0) {
        free(hoststr);
        return NULL;
    }

    struct vtun_host *h = (struct vtun_host *)malloc(sizeof(struct vtun_host));
    if (!h) {
        free(hoststr);
        return NULL;
    }

    memset(h, 0, sizeof(struct vtun_host));

    h->host = hoststr;

    h->flags = (int)fields[0];
    h->timeout = (int)fields[1];
    h->spd_in = (int)fields[2];
    h->spd_out = (int)fields[3];
    h->zlevel = (int)fields[4];
    h->cipher = (int)fields[5];
    h->experimental = (int)fields[6];
    h->persist = (int)fields[7];
    h->multi = (int)fields[8];
    h->ka_interval = (int)fields[9];
    h->ka_maxfail = (int)fields[10];

    return h;
}

void free_deserialized_host(struct vtun_host *h)
{
    if (!h) return;
    free(h->host);
    free(h);
}

int dropcaps_needed() {
    int needed = (geteuid() == 0);
    if (!needed) {
        vtun_syslog(LOG_INFO, "Not running as root, will not setuid or drop capabilities");
    }
    return needed;
}

int dropcaps_current_session()
{
    if (vtun.setgid) {
        struct group *gr = getgrnam("nobody");
        if (gr) {
            vtun_syslog(LOG_INFO, "Setting gid of pid %d to %d\n", getpid(), gr->gr_gid);
            setgroups(0, NULL);
            if (setgid(gr->gr_gid) != 0) {
                vtun_syslog(LOG_ERR, "setgid failed: %s", strerror(errno));
                return 0;
            }
            if (setegid(gr->gr_gid) != 0) {
                vtun_syslog(LOG_ERR, "setegid failed: %s", strerror(errno));
                return 0;
            }
        } else {
            vtun_syslog(LOG_ERR, "group 'nobody' not found; unable to set group id");
            return 0;
        }
    }
    if (vtun.setuid) {
        struct passwd *pw = getpwnam("nobody");
        if (pw) {
            vtun_syslog(LOG_INFO, "Setting uid of pid %d to %d\n", getpid(), pw->pw_uid);
            if (setuid(pw->pw_uid) != 0) {
                vtun_syslog(LOG_ERR, "setuid failed: %s", strerror(errno));
                return 0;
            }
            if (seteuid(pw->pw_uid) != 0) {
                vtun_syslog(LOG_ERR, "setuid failed: %s", strerror(errno));
                return 0;
            }
        } else {
            vtun_syslog(LOG_ERR, "user 'nobody' not found; unable to set user id");
            return 0;
        }
    }
    return 1;
}
