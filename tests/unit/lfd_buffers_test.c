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
#include "../../linkfd_buffers.h"

START_TEST(lfd_extend_below_test) {
	for (size_t ext = 0; ext < 8192; ext++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		{
			char *ptr = buf.ptr;
			memcpy(ptr, "hellohyper", 10);
		}
		buf.size = 10;
		if (!lfd_extend_below(&buf, ext)) {
			fail("lfd_extend_below failed");
		}
		if ((buf.offset + buf.size) > buf.total) {
			fail("lfd_extend_below created an invalid buffer");
		}
		if (buf.size != (ext + 10)) {
			fail("lfd_extend_below wrong size");
		}
		{
			char *ptr = buf.ptr;
			memset(ptr, 'a', ext);
		}
		if (!lfd_extend(&buf, 2)) {
			fail("lfd_extend failed");
		}
		char *ptr = buf.ptr;
		memcpy(ptr + ext + 10, "\0b", 2);
		for (size_t i = 0; i < ext; i++) {
			if (ptr[i] != 'a') {
				fail("wrong data below");
			}
		}
		if (strcmp(ptr + ext, "hellohyper") != 0) {
			fail("wrong data");
		}
		if (ptr[ext + 10] != '\0') {
			fail("nullterminator missing");
		}
		if (ptr[ext + 11] != 'b') {
			fail("wrong data above");
		}
    	lfd_free(&buf);
	}
} END_TEST;

START_TEST(lfd_reduce_below_test) {
	for (size_t red = 0; red < 12; red++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		char *ptr = buf.ptr;
		memcpy(ptr, "hellohype\0", 10);
		buf.size = 10;
		lfd_reduce_below(&buf, red);
		if (red < 10) {
			if (strcmp(&(((const char *) "hellohype")[red]), buf.ptr)) {
				fail("content");
			}
			if (buf.size != (10 - red)) {
				fail("wrong size (<10 range)");
			}
		} else {
			if (buf.size != 0) {
				fail("wrong size");
			}
		}
		lfd_free(&buf);
	}
} END_TEST;

START_TEST(lfd_extend_test) {
	for (size_t ext = 0; ext < 8192; ext++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		{
			char *ptr = buf.ptr;
			memcpy(ptr, "hellohyper", 10);
		}
		buf.size = 10;
		if (!lfd_extend(&buf, ext)) {
			fail("lfd_extend failed");
		}
		if ((buf.offset + buf.size) > buf.total) {
			fail("lfd_extend created an invalid buffer");
		}
		if (buf.size != (ext + 10)) {
			fail("lfd_extend wrong size");
		}
		char *ptr = buf.ptr;
		memset(ptr + 10, 's', ext);
		if (strncmp(ptr, "hellohyper", 10) != 0) {
			fail("wrong data");
		}
		for (size_t i = 0; i < ext; i++) {
			if (ptr[i + 10] != 's') {
				fail("wrong data (ext)");
			}
		}
    	lfd_free(&buf);
	}
} END_TEST;

START_TEST(lfd_sub_extend_below_test) {
	for (size_t ext = 0; ext < 8192; ext++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		{
			char *ptr = buf.ptr;
			memcpy(ptr, "hellohype\0", 10);
		}
		buf.size = 10;
		LfdSubBuffer sub = lfd_sub_buffer(&buf, 3, 4);
		if (lfd_sub_get_size(&sub) != 4) {
			fail("incorrect inital sub size");
		}
		if (strcmp(lfd_sub_get_ptr(&sub, 0), "lohype")) {
			fail("incorrect data at initial sub start");
		}
		if (!lfd_sub_extend_below(&sub, ext)) {
			fail("sub ext below failed");
		}
		if ((buf.offset + buf.size) > buf.total) {
			fail("lfd_sub_extend_below created an invalid buffer");
		}
		if (ext > 0) {
			char *subptr = ((char *) lfd_sub_get_ptr(&sub, 0));
			subptr[0] = '\0';
			for (size_t i = 1; i < ext; i++) {
				subptr[i] = 'z';
			}
		}
		if (buf.size != (ext + 10)) {
			fail("wrong buf size after");
		}
		char *ptr = buf.ptr;
		if (strcmp(ptr + ext + 3, "lohype")) {
			fail("wrong buf ending");
		}
		if (ext > 0) {
			if (ptr[3] != '\0') {
				fail("ext start nullterm missing");
			}
			for (size_t i = 1; i < ext; i++) {
				if (ptr[i + 3] != 'z') {
					fail("incorrect ext data");
				}
			}
		}
		if (ext > 0) {
			if (strcmp(ptr, "hel")) {
				fail("incorrect start");
			}
		} else {
			if (strcmp(ptr, "hellohype")) {
				fail("incorrect start");
			}
		}
	}
} END_TEST;

START_TEST(lfd_sub_extend_test) {
	for (size_t ext = 0; ext < 8192; ext++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		{
			char *ptr = buf.ptr;
			memcpy(ptr, "hellohype\0", 10);
		}
		buf.size = 10;
		LfdSubBuffer sub = lfd_sub_buffer(&buf, 3, 4);
		if (lfd_sub_get_size(&sub) != 4) {
			fail("incorrect inital sub size");
		}
		if (strcmp(lfd_sub_get_ptr(&sub, 0), "lohype")) {
			fail("incorrect data at initial sub start");
		}
		if (!lfd_sub_extend(&sub, ext)) {
			fail("sub ext below failed");
		}
		if ((buf.offset + buf.size) > buf.total) {
			fail("lfd_sub_extend created an invalid buffer");
		}
		if (ext > 0) {
			char *subptr = ((char *) lfd_sub_get_ptr(&sub, 0));
			subptr[4] = '\0';
			for (size_t i = 1; i < ext; i++) {
				subptr[i+4] = 'z';
			}
		}
		if (buf.size != (ext + 10)) {
			fail("wrong buf size after");
		}
		char *ptr = buf.ptr;
		if (strcmp(ptr + ext + 7, "pe")) {
			fail("wrong buf ending");
		}
		if (ext > 0) {
			if (ptr[7] != '\0') {
				fail("ext start nullterm missing");
			}
			for (size_t i = 1; i < ext; i++) {
				if (ptr[i + 7] != 'z') {
					fail("incorrect ext data");
				}
			}
		}
		if (ext > 0) {
			if (strcmp(ptr, "hellohy")) {
				fail("incorrect start");
			}
		} else {
			if (strcmp(ptr, "hellohype")) {
				fail("incorrect start");
			}
		}
	}
} END_TEST;

START_TEST(lfd_sub_reduce_test) {
	for (size_t red = 0; red < 6; red++) {
    	LfdBuffer buf = lfd_alloc(10);
		if (!lfd_ensure_capacity(&buf, 10)) {
			fail("lfd_ensure_capacity failed");
		}
		{
			char *ptr = buf.ptr;
			memcpy(ptr, "hellohype\0", 10);
		}
		buf.size = 10;
		LfdSubBuffer sub = lfd_sub_buffer(&buf, 3, 4);
		if (lfd_sub_get_size(&sub) != 4) {
			fail("incorrect inital sub size");
		}
		if (strcmp(lfd_sub_get_ptr(&sub, 0), "lohype")) {
			fail("incorrect data at initial sub start");
		}
		lfd_sub_reduce(&sub, red);
		if (red < 5 ? (buf.size != (10 - red)) : (buf.size != 6)) {
			fail("wrong buf size after");
		}
		char *ptr = buf.ptr;
		if (strncmp(ptr, "hel", 3)) {
			fail("incorrect start");
		}
		if (red < 5) {
			if (strncmp(ptr + 3, "lohy", 4 - red)) {
				fail("incorrect sub");
			}
			if (strcmp(ptr + 7 - red, "pe")) {
				fail("incorrect end");
			}
		} else {
			if (strcmp(ptr, "helpe")) {
				fail("incorrect end");
			}
		}
	}
} END_TEST;

Suite *buffers_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Buffers");
    tc_core = tcase_create("Buffers");

    tcase_add_test(tc_core, lfd_extend_below_test);
	tcase_add_test(tc_core, lfd_reduce_below_test);
	tcase_add_test(tc_core, lfd_extend_test);
	tcase_add_test(tc_core, lfd_sub_extend_below_test);
	tcase_add_test(tc_core, lfd_sub_extend_test);
	tcase_add_test(tc_core, lfd_sub_reduce_test);

    suite_add_tcase(s, tc_core);

    return s;
}
