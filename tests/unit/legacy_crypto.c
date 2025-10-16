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
#include "../../md5.h"
#include "../../blowfish.h"
#include <stdio.h>

static void verify_md5(char *str, char *expected) {
    size_t len = strlen(str);
    md5_hex_str result;
    printf("MD5: %s\n", str);
    md5_hex(&result, str, len);
    printf("Result: %s\n", result);
    printf("Expected: %s\n", expected);
    if (strcmp(result, expected)) {
        fail("MD5 test failed");
    }
}

START_TEST(md5_test) {
    char *str = "";
    char *expected = "d41d8cd98f00b204e9800998ecf8427e";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test2) {
    char *str = "The quick brown fox jumps over the lazy dog";
    char *expected = "9e107d9d372bb6826bd81d3542a419d6";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test3) {
    char *str = "The quick brown fox jumps over the lazy dog.";
    char *expected = "e4d909c290d0fb1ca068ffaddf22cbd0";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test4) {
    char *str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *expected = "eced9e0b81ef2bba605cbc5e2e76a1d0";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test5) {
    char *str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *expected = "ef1772b6dff9a122358552954ad0df65";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test6) {
    char *str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *expected = "3b0c8ac703f828b04c6c197006d17218";
    verify_md5(str, expected);
} END_TEST;

START_TEST(md5_test7) {
    char *str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    char *expected = "c743a45e0d2e6a95cb859adae0248435";
    verify_md5(str, expected);
} END_TEST;

void blowfish128_test(uint8_t key[16], uint8_t input[8], uint8_t expected[8]) {
    BlowfishContext ctx;
    uint8_t data[8];
    for (int i = 0; i < 8; i++) {
        data[i] = input[i];
    }
    printf("Key:");
    for (int i = 0; i < 16; i++) {
        printf(" %02x", key[i]);
    }
    printf("\n");
    blowfish_init(&ctx, key, 16);
    printf("Encrypt  :");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    blowfish_encrypt_8bytes_le(&ctx, data);
    printf("Encrypted:");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    for (int i = 0; i < 8; i++) {
        if (data[i] != expected[i]) {
            fail("incorrect encryption result");
        }
    }
    blowfish_decrypt_8bytes_le(&ctx, data);
    printf("Decrypted:");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    for (int i = 0; i < 8; i++) {
        if (data[i] != input[i]) {
            fail("incorrect encryption result");
        }
    }
}

void blowfish128ecb_test(uint8_t key[16], uint8_t input[8], uint8_t expected[8]) {
    BlowfishContext ctx;
    uint8_t data[8];
    for (int i = 0; i < 8; i++) {
        data[i] = input[i];
    }
    printf("Key:");
    for (int i = 0; i < 16; i++) {
        printf(" %02x", key[i]);
    }
    printf("\n");
    blowfish_init(&ctx, key, 16);
    printf("Encrypt  (ecb):");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    blowfish_encrypt_8bytes_ecb(&ctx, data);
    printf("Encrypted(ecb):");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    for (int i = 0; i < 8; i++) {
        if (data[i] != expected[i]) {
            fail("incorrect encryption result");
        }
    }
    blowfish_decrypt_8bytes_ecb(&ctx, data);
    printf("Decrypted(ecb):");
    for (int i = 0; i < 8; i++) {
        printf(" %02x", data[i]);
    }
    printf("\n");
    for (int i = 0; i < 8; i++) {
        if (data[i] != input[i]) {
            fail("incorrect encryption result");
        }
    }
}

START_TEST(blowfish_nullkey128_nulldata) {
    uint8_t key[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t input[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t expected[8] = {0x45, 0x97, 0xf9, 0x4e, 0x78, 0xdd, 0x98, 0x61};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test2) {
    uint8_t key[16] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t input[8] = {1, 1, 1, 1, 1, 1, 1, 1};
    uint8_t expected[8] = {0x0c, 0x1d, 0xca, 0xff, 0x3d, 0xc7, 0x85, 0x39};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test3) {
    uint8_t key[16] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
    uint8_t input[8] = {2, 2, 2, 2, 2, 2, 2, 2};
    uint8_t expected[8] = {0x83, 0xb7, 0x52, 0x84, 0x71, 0x37, 0x56, 0xcd};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test4) {
    uint8_t key[16] = {4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
    uint8_t input[8] = {4, 4, 4, 4, 4, 4, 4, 4};
    uint8_t expected[8] = {0x95, 0x46, 0x86, 0x96, 0x91, 0x68, 0x84, 0xc5};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test5) {
    uint8_t key[16] = {8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    uint8_t input[8] = {8, 8, 8, 8, 8, 8, 8, 8};
    uint8_t expected[8] = {0x20, 0x30, 0xd6, 0xdf, 0xff, 0x5a, 0xce, 0x11};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test6) {
    uint8_t key[16] = {16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16};
    uint8_t input[8] = {16, 16, 16, 16, 16, 16, 16, 16};
    uint8_t expected[8] = {0x46, 0x8e, 0xa9, 0x0d, 0x4c, 0xb9, 0x93, 0x93};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test7) {
    uint8_t key[16] = {32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32};
    uint8_t input[8] = {32, 32, 32, 32, 32, 32, 32, 32};
    uint8_t expected[8] = {0xeb, 0x9b, 0x03, 0x49, 0xe8, 0xeb, 0x00, 0x71};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test8) {
    uint8_t key[16] = {64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64};
    uint8_t input[8] = {64, 64, 64, 64, 64, 64, 64, 64};
    uint8_t expected[8] = {0x6a, 0xf4, 0x61, 0xf7, 0x8a, 0x7f, 0xd5, 0x32};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test9) {
    uint8_t key[16] = {128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128};
    uint8_t input[8] = {128, 128, 128, 128, 128, 128, 128, 128};
    uint8_t expected[8] = {0xc8, 0xb7, 0x5e, 0x83, 0x5e, 0xe5, 0x56, 0x99};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128_test10) {
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t input[8] = {17, 18, 19, 20, 21, 22, 23, 24};
    uint8_t expected[8] = {0x00, 0xcf, 0x12, 0x6b, 0xf4, 0xff, 0x06, 0x5d};
    blowfish128_test(key, input, expected);
}

START_TEST(blowfish128ecb_test1) {
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t input[8] = {17, 18, 19, 20, 21, 22, 23, 24};
    uint8_t expected[8] = {0x36, 0x21, 0x0c, 0xca, 0x54, 0x8b, 0x11, 0xa7};
    blowfish128ecb_test(key, input, expected);
}

Suite *legacy_crypto_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("LegacyCrypto");
    tc_core = tcase_create("LegacyCrypto");

    tcase_add_test(tc_core, md5_test);
    tcase_add_test(tc_core, md5_test2);
    tcase_add_test(tc_core, md5_test3);
    tcase_add_test(tc_core, md5_test4);
    tcase_add_test(tc_core, md5_test5);
    tcase_add_test(tc_core, md5_test6);
    tcase_add_test(tc_core, md5_test7);
    tcase_add_test(tc_core, blowfish_nullkey128_nulldata);
    tcase_add_test(tc_core, blowfish128_test2);
    tcase_add_test(tc_core, blowfish128_test3);
    tcase_add_test(tc_core, blowfish128_test4);
    tcase_add_test(tc_core, blowfish128_test5);
    tcase_add_test(tc_core, blowfish128_test6);
    tcase_add_test(tc_core, blowfish128_test7);
    tcase_add_test(tc_core, blowfish128_test8);
    tcase_add_test(tc_core, blowfish128_test9);
    tcase_add_test(tc_core, blowfish128_test10);
    tcase_add_test(tc_core, blowfish128ecb_test1);

    suite_add_tcase(s, tc_core);
    return s;
}
