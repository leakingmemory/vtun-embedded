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

#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>

#include "../../vtun.h"
#include "../../dropcaps.h"

static struct vtun_host *make_host(const char *host, const char *dev)
{
    struct vtun_host *h = (struct vtun_host *)calloc(1, sizeof(struct vtun_host));
    ck_assert_ptr_nonnull(h);
    h->host = strdup(host);
    h->passwd = strdup("secret");
    h->dev = dev ? strdup(dev) : NULL;

    h->flags = VTUN_TCP | VTUN_TUN | VTUN_KEEP_ALIVE | VTUN_ZLIB | VTUN_ENCRYPT;
    h->timeout = 42;
    h->spd_in = 1234;
    h->spd_out = 5678;
    h->zlevel = 7;
    h->cipher = VTUN_ENC_AES256GCM;
    h->persist = VTUN_PERSIST;
    h->multi = VTUN_MULTI_ALLOW;
    h->ka_interval = 9;
    h->ka_maxfail = 3;
    return h;
}

static void free_host(struct vtun_host *h)
{
    if (!h) return;
    free(h->host);
    free(h->passwd);
    if (h->dev != NULL) {
        free(h->dev);
    }
    free(h);
}

static void assert_hosts_equal(const struct vtun_host *a, const struct vtun_host *b)
{
    ck_assert_ptr_nonnull(a);
    ck_assert_ptr_nonnull(b);
    ck_assert_ptr_nonnull(a->host);
    ck_assert_ptr_nonnull(b->host);
    ck_assert_int_eq(strcmp(a->host, b->host), 0);
    ck_assert_int_eq(a->flags, b->flags);
    ck_assert_int_eq(a->timeout, b->timeout);
    ck_assert_int_eq(a->spd_in, b->spd_in);
    ck_assert_int_eq(a->spd_out, b->spd_out);
    ck_assert_int_eq(a->zlevel, b->zlevel);
    ck_assert_int_eq(a->cipher, b->cipher);
    ck_assert_int_eq(a->persist, b->persist);
    ck_assert_int_eq(a->multi, b->multi);
    ck_assert_int_eq(a->ka_interval, b->ka_interval);
    ck_assert_int_eq(a->ka_maxfail, b->ka_maxfail);
}

START_TEST(test_auth_pipe_roundtrip_with_dev)
{
    int fds[2];
    ck_assert_int_eq(pipe(fds), 0);

    struct vtun_host *src = make_host("unit-host", "tap0");

    /* Write entire payload to pipe */
    ck_assert_int_eq(serialize_host_to_pipe(fds[1], src), 0);
    close(fds[1]);

    struct vtun_host *dst = deserialize_host_from_pipe(fds[0]);
    close(fds[0]);

    ck_assert_ptr_nonnull(dst);
    assert_hosts_equal(src, dst);

    free_deserialized_host(dst);
    free_host(src);
}
END_TEST

START_TEST(test_auth_pipe_roundtrip_no_dev)
{
    int fds[2];
    ck_assert_int_eq(pipe(fds), 0);

    struct vtun_host *src = make_host("unit-host-nd", NULL);

    ck_assert_int_eq(serialize_host_to_pipe(fds[1], src), 0);
    close(fds[1]);

    struct vtun_host *dst = deserialize_host_from_pipe(fds[0]);
    close(fds[0]);

    ck_assert_ptr_nonnull(dst);
    assert_hosts_equal(src, dst);

    free_deserialized_host(dst);
    free_host(src);
}
END_TEST

Suite *auth_pipe_suite(void)
{
    Suite *s = suite_create("AuthPipe");
    TCase *tc = tcase_create("SerializeDeserialize");

    tcase_add_test(tc, test_auth_pipe_roundtrip_with_dev);
    tcase_add_test(tc, test_auth_pipe_roundtrip_no_dev);

    suite_add_tcase(s, tc);
    return s;
}
