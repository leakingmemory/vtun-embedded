/*
    VTun - Virtual Tunnel over TCP/IP network.

    Copyright (C) 1998-2016  Maxim Krasnyansky <max_mk@yahoo.com>
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

#include "auth.h"
#include "auth_prim.h"
#include "config.h"

#include <unistd.h>

#include "lock.h"

#include <stdio.h>

#include "vtun.h"
#include "lib.h"
#include <string.h>
#include <syslog.h>

static int warn_incompat = 0;

#ifdef HAVE_SSL

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

void mix_in_bytes(void *chal, void *data, size_t len) {
    if ((VTUN_CHAL_SIZE + len) > 768) {
        return;
    }
    uint8_t mdbuf[SHA256_DIGEST_LENGTH];
    uint8_t *h;
    {
        uint8_t buf[768];
        memcpy(buf, chal, VTUN_CHAL_SIZE);
        memcpy(buf + VTUN_CHAL_SIZE, data, len);
        h = SHA256(buf, VTUN_CHAL_SIZE + len, mdbuf);
    }
    size_t cplen = VTUN_CHAL_SIZE < SHA256_DIGEST_LENGTH ? VTUN_CHAL_SIZE : SHA256_DIGEST_LENGTH;
    for (size_t i = 0; i < cplen; i++) {
        ((uint8_t *) chal)[i] = h[i];
    }
}

static void decrypt_chal_v2(char *chal, char *pwd) {
    uint8_t mdbuf[SHA256_DIGEST_LENGTH];
    uint8_t *key;

    key = SHA256((unsigned char *)pwd, strlen(pwd), mdbuf);
    if (key == NULL) {
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for(int i=0; i < VTUN_CHAL_SIZE; i += 16 ) {
        int outlen = 16;
        EVP_DecryptUpdate(ctx, (unsigned char *) (chal + i), &outlen, (unsigned char *) (chal + i), 16 <= (VTUN_CHAL_SIZE - i) ? 16 : VTUN_CHAL_SIZE - i);
    }

    EVP_CIPHER_CTX_free(ctx);
}

static void encrypt_chal_v2(char *chal, char *pwd) {
    uint8_t mdbuf[SHA256_DIGEST_LENGTH];
    uint8_t *key;

    key = SHA256((unsigned char *)pwd, strlen(pwd), mdbuf);
    if (key == NULL) {
        return;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    for(int i=0; i < VTUN_CHAL_SIZE; i += 16 ) {
        int outlen = 16;
        EVP_EncryptUpdate(ctx, (unsigned char *) (chal + i), &outlen, (unsigned char *) (chal + i), 16 <= (VTUN_CHAL_SIZE - i) ? 16 : VTUN_CHAL_SIZE - i);
    }

    EVP_CIPHER_CTX_free(ctx);
}

#else

#include "md5.h"

void mix_in_bytes(void *chal, void *data, size_t len) {
    if (!warn_incompat) {
        warn_incompat = 1;
        vtun_syslog(LOG_WARNING, "OpenSSL is not available, and therefore using md5 and blowfish instead of sha256 and aes256 for authentication. This may not be compatible with other implementations.");
    }
    md5_hash h;
    {
        Md5Context m;
        md5_init(&m);
        size_t done = md5_update(&m, chal, VTUN_CHAL_SIZE);
        if (done < VTUN_CHAL_SIZE) {
            if ((VTUN_CHAL_SIZE - done + len) > 512) {
                return;
            }
            uint8_t buf[512];
            memcpy(buf, chal + done, VTUN_CHAL_SIZE - done);
            memcpy(buf + done, data, len);
            md5_final(&h, &m, buf, VTUN_CHAL_SIZE - done + len);
        } else {
            md5_final(&h, &m, data, len);
        }
    }
    int md_len = 16;
    if (md_len > VTUN_CHAL_SIZE) {
        md_len = VTUN_CHAL_SIZE;
    }
    for (int i = 0; i < 16; i++) {
        ((uint8_t *) chal)[i] = h[i];
    }
}

static void decrypt_chal_v2(char *chal, char *pwd) {
    if (!warn_incompat) {
        warn_incompat = 1;
        vtun_syslog(LOG_WARNING, "OpenSSL is not available, and therefore using md5 and blowfish instead of sha256 and aes256 for authentication. This may not be compatible with other implementations.");
    }
    decrypt_chal(chal, pwd);
}

static void encrypt_chal_v2(char *chal, char *pwd) {
    if (!warn_incompat) {
        warn_incompat = 1;
        vtun_syslog(LOG_WARNING, "OpenSSL is not available, and therefore using md5 and blowfish instead of sha256 and aes256 for authentication. This may not be compatible with other implementations.");
    }
    encrypt_chal(chal, pwd);
}

#endif

/* Authentication (Server side) */
struct vtun_host * auth_server_v2(int fd, char *host)
{
    char chal_req[VTUN_CHAL_SIZE], chal_res[VTUN_CHAL_SIZE], chal[VTUN_CHAL_SIZE];
    char buf[VTUN_MESG_SIZE], *str1, *str2;
    char *flags = NULL;
    struct vtun_host *h = NULL;
    int state = ST_HOST;

    gen_chal(chal_req);
    print_p(fd,"OK CHAL: %s\n", cl2cs(chal_req));

    mix_in_bytes(chal_req, host, strlen(host));

    while ( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
        switch (state) {
            case ST_HOST:
                buf[sizeof(buf)-1]='\0';
                strtok(buf,"\r\n");

                if( (str1=strtok(buf," :")) &&
                    (str2=strtok(NULL," :")) ) {
                    if( !strcmp(str1,"CHAL") ){
                        if( cs2cl(str2,chal_res) &&
                            (h = find_host(host)) ) {

                            decrypt_chal_v2(chal_res, h->passwd);

                            if( !memcmp(chal_req, chal_res, VTUN_CHAL_SIZE) ){
                                /* Auth successeful. */

                                /* Lock host */
                                if( lock_host(h) >= 0 ){
                                    flags = strdup(bf2cf(h));
                                    print_p(fd,"OK FLAGS: %s\n", flags);
                                    state = ST_CHAL;
                                    continue;
                                } else {
                                    /* Multiple connections are denied */
                                    h = NULL;
                                }
                            } else {
                                h = NULL;
                            }
                        }
                    }
                }
                break;
            case ST_CHAL:
                buf[sizeof(buf)-1]='\0';
                strtok(buf,"\r\n");

                if( flags != NULL && !strncmp(buf,"OK CHAL",7) && cs2cl(buf,chal)){
                    {
                        char *mix;
                        size_t mixlen;
                        {
                            size_t flagslen = strlen(flags);
                            size_t hostlen = strlen(host);
                            mixlen = flagslen + hostlen + 1;
                            mix = malloc(mixlen);
                            memcpy(mix, flags, flagslen);
                            mix[flagslen] = ':';
                            memcpy(mix + flagslen + 1, host, hostlen);
                        }
                        mix_in_bytes(chal, mix, mixlen);
                        free(mix);
                    }
                    encrypt_chal_v2(chal,h->passwd);
                    print_p(fd,"CHAL: %s\n", cl2cs(chal));
                    state = ST_CLICHAL;

                    continue;
                }
                h = NULL;
                break;
            case ST_CLICHAL:
                buf[sizeof(buf)-1]='\0';
                strtok(buf,"\r\n");

                if( strncmp(buf,"OK",2)){
                    h = NULL;
                }
                break;
        }
        break;
    }

    if (flags != NULL) {
        free(flags);
    }
    if( !h )
        print_p(fd,"ERR\n");

    return h;
}

/* Authentication (Client side) */
int auth_client_v2(int fd, struct vtun_host *host)
{
    char buf[VTUN_MESG_SIZE], chal[VTUN_CHAL_SIZE], chal_res[VTUN_CHAL_SIZE];
    int stage, success=0 ;

    print_p(fd,"HOS2: %s\n",host->host);

    stage = ST_HOST;

    while( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
        buf[sizeof(buf)-1]='\0';
        switch( stage ){
            case ST_HOST:
                if( !strncmp(buf,"OK",2) && cs2cl(buf,chal)){
                    stage = ST_CHAL;

                    mix_in_bytes(chal, host->host, strlen(host->host));
                    encrypt_chal_v2(chal,host->passwd);
                    print_p(fd,"CHAL: %s\n", cl2cs(chal));

                    continue;
                }
                break;

            case ST_CHAL:
                if (!strncmp(buf,"OK FLAGS: ",10)) {
                    char *flags = buf + 10;
                    while (*flags != '<' && *flags != '\0') {
                        flags++;
                    }
                    {
                        int i = 0;
                        while (flags[i] != '>' && flags[i] != '\0') {
                            i++;
                        }
                        if (flags[i] == '>') {
                            flags[i + 1] = '\0';
                        }
                    }
                    if (cf2bf(flags, host)) {
                        gen_chal(chal);
                        print_p(fd,"OK CHAL: %s\n", cl2cs(chal));
                        {
                            char *mix;
                            size_t mixlen;
                            {
                                size_t flagslen = strlen(flags);
                                size_t hostlen = strlen(host->host);
                                mixlen = flagslen + hostlen + 1;
                                mix = malloc(mixlen);
                                memcpy(mix, flags, flagslen);
                                mix[flagslen] = ':';
                                memcpy(mix + flagslen + 1, host->host, hostlen);
                            }
                            mix_in_bytes(chal, mix, mixlen);
                            free(mix);
                        }
                        stage = ST_CLICHAL;
                        continue;
                    }
                }
                break;
            case ST_CLICHAL:
                if( !strncmp(buf,"CHAL",2) && cs2cl(buf,chal_res)){
                    decrypt_chal_v2(chal_res, host->passwd);

                    if( !memcmp(chal, chal_res, VTUN_CHAL_SIZE) ){
                        /* Auth successeful. */
                        print_p(fd,"OK\n");
                        success = 1;
                    }
                }
                break;
        }
        break;
    }

    return success;
}
