//
// Created by sigsegv on 10/30/25.
//

#include <stdio.h>
#include "../../vtun.h"

#include <check.h>
#include <stdlib.h>

void init_config();
void before_read_config();
int after_read_config();
void parse_config_string(const char *str);
void set_cfg_error_printf();

static int read_config_from_string(const char *config) {
    set_cfg_error_printf();
    before_read_config();
    parse_config_string(config);
    return after_read_config();
}

static void free_config() {
    if (vtun.cfg_file != VTUN_CONFIG_FILE) {
        free(vtun.cfg_file);
    }
    if (vtun.pid_file != VTUN_PID_FILE) {
        free(vtun.pid_file);
    }

    /* Dup strings because parser will try to free them */
    free(vtun.ppp);
    free(vtun.ifcfg);
    free(vtun.route);
    free(vtun.fwall);
    free(vtun.iproute);

    if (vtun.svr_name != NULL) {
        free(vtun.svr_name);
    }
    if (vtun.svr_addr != NULL) {
        free(vtun.svr_addr);
    }
    memset(&vtun, 0, sizeof(vtun));
}

START_TEST(test_cfg_aes128gcm) {
    const char *test_config = "testhost {\n"
    " passwd test;\n"
    " type ether;\n"
    " proto tcp;\n"
    " encrypt aes128gcm;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    struct vtun_host *host = find_host("testhost");
    ck_assert_ptr_nonnull(host);
    ck_assert_int_eq(VTUN_ENC_AES128GCM, host->cipher);
    printf(" aes128gcm cipher num %d\n", host->cipher);
    free_config();
} END_TEST;

START_TEST(test_cfg_aes256gcm) {
    const char *test_config = "testhost {\n"
    " passwd test;\n"
    " type ether;\n"
    " proto tcp;\n"
    " encrypt aes256gcm;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    struct vtun_host *host = find_host("testhost");
    ck_assert_ptr_nonnull(host);
    ck_assert_int_eq(VTUN_ENC_AES256GCM, host->cipher);
    printf(" aes256gcm cipher num %d\n", host->cipher);
    free_config();
} END_TEST;

Suite *config_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Config");
    tc_core = tcase_create("Config");

    tcase_add_test(tc_core, test_cfg_aes128gcm);
    tcase_add_test(tc_core, test_cfg_aes256gcm);

    suite_add_tcase(s, tc_core);

    return s;
}
