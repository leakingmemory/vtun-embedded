//
// Created by sigsegv on 10/30/25.
//

#include <stdio.h>
#include "../../config.h"
#include "../../vtun.h"
#include "../../sys_dropcaps.h"

#include <check.h>
#include <stdlib.h>
#include <grp.h>
#include <pwd.h>

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
    struct vtun_host *host = find_host_server("testhost");
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
    struct vtun_host *host = find_host_server("testhost");
    ck_assert_ptr_nonnull(host);
    ck_assert_int_eq(VTUN_ENC_AES256GCM, host->cipher);
    printf(" aes256gcm cipher num %d\n", host->cipher);
    free_config();
} END_TEST;

START_TEST(test_not_setuid) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    ck_assert_int_eq(5001, vtun.bind_addr.port);
    ck_assert_int_eq(0, vtun.setuid);
    ck_assert_int_eq(0, vtun.setgid);
    free_config();
} END_TEST;

START_TEST(test_setuid) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    " hardening setuid;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    ck_assert_int_eq(5001, vtun.bind_addr.port);
    ck_assert_int_ne(0, vtun.setuid);
    ck_assert_int_eq(0, vtun.setgid);
    free_config();
    printf("hardening setuid ok\n");
}

START_TEST(test_setgid) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    " hardening setgid;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    ck_assert_int_eq(5001, vtun.bind_addr.port);
    ck_assert_int_eq(0, vtun.setuid);
    ck_assert_int_ne(0, vtun.setgid);
    free_config();
    printf("hardening setgid ok\n");
}

START_TEST(test_dropcaps) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    " hardening dropcaps;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    if (dropcaps_supported()) {
        ck_assert_int_eq(5001, vtun.bind_addr.port);
        ck_assert_int_eq(0, vtun.setuid);
        ck_assert_int_eq(0, vtun.setgid);
        ck_assert_int_ne(0, vtun.dropcaps);
        free_config();
        printf("hardening dropcaps ok\n");
    }
} END_TEST;

START_TEST(test_setuid_setgid_and_dropcaps) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    " hardening setuid setgid dropcaps;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    if (dropcaps_supported()) {
        ck_assert_int_eq(5001, vtun.bind_addr.port);
        ck_assert_int_ne(0, vtun.setuid);
        ck_assert_int_ne(0, vtun.setgid);
        ck_assert_int_ne(0, vtun.dropcaps);
        free_config();
        printf("hardening setuid, setgid and dropcaps ok\n");
    }
} END_TEST;

START_TEST(test_setuid_and_setgid) {
    const char *test_config = "options {\n"
    " port 5001;\n"
    " hardening setuid setgid;\n"
    "}";
    init_config();
    read_config_from_string(test_config);
    ck_assert_int_eq(5001, vtun.bind_addr.port);
    ck_assert_int_ne(0, vtun.setuid);
    ck_assert_int_ne(0, vtun.setgid);
    ck_assert_int_eq(0, vtun.dropcaps);
    free_config();
    printf("hardening setuid ok\n");
} END_TEST;

START_TEST(test_numeric_uid_gid)
{
    init_config();
    const char *cfg =
        "options {\n"
        " hardening setuid setgid;\n"
        " setuid 65534;\n"
        " setgid 65534;\n"
        "}\n"
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));
    ck_assert_int_ne(0, vtun.setuid);
    ck_assert_int_ne(0, vtun.setgid);
    ck_assert_int_eq(0, vtun.dropcaps);
    ck_assert_int_eq((uid_t)65534, vtun.setuid_uid);
    ck_assert_int_eq((gid_t)65534, vtun.setgid_gid);

    free_config();

	printf("Numeric setuid/setgid ok\n");
}
END_TEST

START_TEST(test_name_nobody)
{
    init_config();
    struct passwd *pw = getpwnam("nobody");
    struct group *gr = getgrnam("nobody");
    if (!pw || !gr) {
        printf("Skipping: nobody user or group not present on system.\n");
        free_config();
        return;
    }
    const char *cfg =
        "options {\n"
        " hardening setuid setgid;\n"
        " setuid nobody;\n"
        " setgid nobody;\n"
        "}\n";
    int ok = read_config_from_string(cfg);
	ck_assert_int_eq(0, ok);
    ck_assert_int_ne(0, vtun.setuid);
    ck_assert_int_ne(0, vtun.setgid);
    ck_assert_int_eq(0, vtun.dropcaps);

    ck_assert_int_eq(pw->pw_uid, vtun.setuid_uid);
    ck_assert_int_eq(gr->gr_gid, vtun.setgid_gid);

    free_config();

	printf("Setuid/setgid by name ok\n");
}
END_TEST

START_TEST(test_unknown_user_group_fails)
{
    init_config();
    const char *cfg =
        "options {\n"
        " hardening setuid setgid;\n"
        " setuid definitelynotarealuserxyz;\n"
        "}\n";
    int ok = read_config_from_string(cfg);
    ck_assert_int_eq(0, ok);
    free_config();

	printf("Setuid with unknown user is ok\n");
}
END_TEST

START_TEST(test_fallback_nobody_when_ids_unset)
{
    init_config();
    const char *cfg =
        "options {\n"
        " hardening setuid setgid;\n"
        "}\n"
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    /* IDs remain unset (-1) */
    ck_assert_int_eq((uid_t)-1, vtun.setuid_uid);
    ck_assert_int_eq((gid_t)-1, vtun.setgid_gid);

    free_config();
}
END_TEST

#ifdef ENABLE_NAT_HACK
START_TEST(test_nathack_client)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto udp;\n"
        " nat_hack client;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_server("dummy");
    int not_expected_flags = VTUN_TCP;
    int expected_flags = VTUN_UDP | VTUN_NAT_HACK_CLIENT;
    ck_assert_int_eq(0, (dummy->flags & not_expected_flags));
    ck_assert_int_eq(expected_flags, (dummy->flags & expected_flags));

    free_config();
}
END_TEST
#endif

START_TEST(test_requires_none)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_server("dummy");
    ck_assert_int_eq(0, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_client)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires client;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_CLIENT, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_bidirauth)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires bidirauth;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_BIDIRAUTH, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_3_1)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires \"3.1\";\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_BIDIRAUTH, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_encryption)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires encryption;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_ENCRYPTION, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_integrity)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires integrity;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_ENCRYPTION | VTUN_REQUIRES_INTEGRITY, dummy->requires_flags);

    free_config();
}
END_TEST

START_TEST(test_requires_all)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " requires client bidirauth \"3.1\" encryption integrity;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(VTUN_REQUIRES_CLIENT | VTUN_REQUIRES_BIDIRAUTH | VTUN_REQUIRES_ENCRYPTION | VTUN_REQUIRES_INTEGRITY, dummy->requires_flags);
    ck_assert_int_eq(0, dummy->accept_encrypt_bits_0_31);

    free_config();
}
END_TEST

START_TEST(test_accept_encrypt_legacy)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " accept_encrypt oldblowfish128ecb;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(1, dummy->accept_encrypt_bits_0_31);

    free_config();
}
END_TEST

START_TEST(test_accept_encrypt_one)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " accept_encrypt blowfish128ecb;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(2, dummy->accept_encrypt_bits_0_31);

    free_config();
}
END_TEST

START_TEST(test_accept_encrypt_two_independent)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " accept_encrypt blowfish128cbc;\n"
        " accept_encrypt blowfish128cfb;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(12, dummy->accept_encrypt_bits_0_31);

    free_config();
}
END_TEST

START_TEST(test_accept_encrypt_two_joined)
{
    init_config();
    const char *cfg =
        "dummy {\n"
        " passwd x;\n"
        " type ether;\n"
        " proto tcp;\n"
        " accept_encrypt blowfish128ofb blowfish256ecb;\n"
        "}\n";
    ck_assert_int_ne(0, read_config_from_string(cfg));

    struct vtun_host *dummy = find_host_client("dummy");
    ck_assert_int_eq(48, dummy->accept_encrypt_bits_0_31);

    free_config();
}
END_TEST


Suite *config_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Config");
    tc_core = tcase_create("Config");

    tcase_add_test(tc_core, test_cfg_aes128gcm);
    tcase_add_test(tc_core, test_cfg_aes256gcm);
    tcase_add_test(tc_core, test_not_setuid);
    tcase_add_test(tc_core, test_setuid);
    tcase_add_test(tc_core, test_setgid);
    tcase_add_test(tc_core, test_dropcaps);
    tcase_add_test(tc_core, test_setuid_setgid_and_dropcaps);
    tcase_add_test(tc_core, test_setuid_and_setgid);
    tcase_add_test(tc_core, test_numeric_uid_gid);
    tcase_add_test(tc_core, test_name_nobody);
    tcase_add_test(tc_core, test_unknown_user_group_fails);
    tcase_add_test(tc_core, test_fallback_nobody_when_ids_unset);
#ifdef ENABLE_NAT_HACK
    tcase_add_test(tc_core, test_nathack_client);
#endif
    tcase_add_test(tc_core, test_requires_none);
    tcase_add_test(tc_core, test_requires_client);
    tcase_add_test(tc_core, test_requires_bidirauth);
    tcase_add_test(tc_core, test_requires_3_1);
    tcase_add_test(tc_core, test_requires_encryption);
    tcase_add_test(tc_core, test_requires_integrity);
    tcase_add_test(tc_core, test_requires_all);
    tcase_add_test(tc_core, test_accept_encrypt_legacy);
    tcase_add_test(tc_core, test_accept_encrypt_one);
    tcase_add_test(tc_core, test_accept_encrypt_two_independent);
    tcase_add_test(tc_core, test_accept_encrypt_two_joined);

    suite_add_tcase(s, tc_core);

    return s;
}
