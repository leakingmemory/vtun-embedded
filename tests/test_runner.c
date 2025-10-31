/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 2025  Jan-Espen Oversand <sigsegv@radiotube.org>

    test_runner.c - Test setup significantly AI assisted

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

extern Suite *buffers_suite(void);
extern Suite *legacy_crypto_suite(void);
extern Suite *config_suite(void);

int main(void)
{
    int number_failed;
    SRunner *sr;

    sr = srunner_create(buffers_suite());
	srunner_add_suite(sr, legacy_crypto_suite());
    srunner_add_suite(sr, config_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
