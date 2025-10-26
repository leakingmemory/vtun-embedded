/*
    VTun - Virtual Tunnel over TCP/IP network.

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
#include "linkfd.h"

#include <syslog.h>

#include "linkfd_buffers.h"

#ifdef HAVE_SSL

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <time.h>

/* lfd_encrypt.c: */
int lfd_encrypt_prep_key(char **key, int size, struct vtun_host *host);
void lfd_encrypt_free_key (char *key);

#define MAX_GIBBERISH	10
#define MIN_GIBBERISH   1
#define MAX_GIBBERISH_TIME   2

extern int send_a_packet;

static EVP_CIPHER_CTX *ctx_enc;
static EVP_CIPHER_CTX *ctx_dec;
static EVP_CIPHER_CTX *ctx_enc_sideband;
static EVP_CIPHER_CTX *ctx_dec_sideband;
static int cipher_no;
static char *pkey;
static uint8_t enc_iv[16];
static uint8_t dec_iv[16];
static uint64_t enc_seq;
static uint64_t dec_seq;
static uint32_t enc_seq_base;
static uint32_t dec_msg_seq;
static uint32_t gibberish_counter;
static time_t gibberish_time;
static int encryption_inited;
static int decryption_inited;
static int request_reinit;

static int alloc_gcm_encrypt(struct vtun_host *host) {
    const EVP_CIPHER *sideband_cipher;
    int key_size;

    vtun_syslog(LOG_INFO, "AES-GCM initing");
    ctx_enc = EVP_CIPHER_CTX_new();
    ctx_dec = EVP_CIPHER_CTX_new();
    ctx_enc_sideband = EVP_CIPHER_CTX_new();
    ctx_dec_sideband = EVP_CIPHER_CTX_new();
    cipher_no = host->cipher;
    switch (cipher_no) {
        case VTUN_ENC_AES128GCM:
            sideband_cipher = EVP_aes_128_ecb();
            key_size = 16;
            break;
        case VTUN_ENC_AES256GCM:
            sideband_cipher = EVP_aes_256_ecb();
            key_size = 32;
            break;
    }
    if (lfd_encrypt_prep_key(&pkey, key_size, host) != 0) {
        return -1;
    }
    if (!EVP_EncryptInit_ex(ctx_enc_sideband, sideband_cipher, NULL, (unsigned char *) pkey, NULL) ||
        !EVP_DecryptInit_ex(ctx_dec_sideband, sideband_cipher, NULL, (unsigned char *) pkey, NULL)) {
        vtun_syslog(LOG_ERR,"Can't initialize cipher");
        return -1;
    }
    EVP_CIPHER_CTX_set_padding(ctx_enc_sideband, 0);
    EVP_CIPHER_CTX_set_padding(ctx_dec_sideband, 0);
    enc_seq = 0;
    dec_seq = 0;
    gibberish_counter = 0;
    encryption_inited = 0;
    decryption_inited = 0;
    request_reinit = 0;
    vtun_syslog(LOG_WARNING, "AES-GCM is experimental, compatibility is not guaranteed");
    vtun_syslog(LOG_INFO, "AES-GCM is ready to start");
}

static int free_gcm_encrypt() {
    lfd_encrypt_free_key(pkey);

    EVP_CIPHER_CTX_free(ctx_dec_sideband);
    EVP_CIPHER_CTX_free(ctx_enc_sideband);
    EVP_CIPHER_CTX_free(ctx_dec);
    EVP_CIPHER_CTX_free(ctx_enc);
}

static int gcm_set_up_encryption(LfdBuffer *buf);
static int gcm_add_inband(LfdSubBuffer *sub);

static int gcm_encrypt(LfdBuffer *buf) {
    int off = 0;
    if (!encryption_inited) {
        off = gcm_set_up_encryption(buf);
        if (off < 0) {
            vtun_syslog(LOG_ERR, "Failed to generate init message for AES-GCM");
            return -1;
        }
        encryption_inited = 1;
    }
    LfdSubBuffer sub = lfd_sub_buffer(buf, off, buf->size - off);
    const EVP_CIPHER *cipher;
    switch (cipher_no) {
        case VTUN_ENC_AES128GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case VTUN_ENC_AES256GCM:
            cipher = EVP_aes_256_gcm();
            break;
    }
    if (!gcm_add_inband(&sub)) {
        return -1;
    }
    uint8_t ivdata[32];
    memcpy(ivdata, enc_iv, 16);
    *((uint64_t *)(ivdata + 16)) = htobe64(enc_seq++);
    memset(ivdata + 24, 0, 8);
    uint8_t noncebuf[SHA256_DIGEST_LENGTH];
    uint8_t *nonce = SHA256(ivdata, 32, noncebuf);
    EVP_EncryptInit_ex(ctx_enc, cipher, NULL, pkey, nonce);
    EVP_CIPHER_CTX_set_padding(ctx_enc, 0);
    size_t len = lfd_sub_get_size(&sub);
    size_t pad = 16 - (len & 15);
    len += pad;
    lfd_sub_set_size(&sub, len);
    if (pad > 1) {
        RAND_bytes(lfd_sub_get_ptr(&sub, len - pad), pad - 1);
    }
    ((uint8_t *) lfd_sub_get_ptr(&sub, len - 1))[0] = (uint8_t) pad;
    for (size_t off = 0; off < len; off += 16) {
        int blkout = 0;
        void *ptr = lfd_sub_get_ptr(&sub, off);
        if (!EVP_EncryptUpdate(ctx_enc, ptr, &blkout, ptr, 16) ||
            blkout != 16) {
            vtun_syslog(LOG_ERR, "Failed to encrypt AES-GCM block");
            return -1;
        }
    }
    int finalout = 0;
    void *ptr = lfd_sub_get_ptr(&sub, 0);
    if (!EVP_EncryptFinal_ex(ctx_enc, ptr, &finalout) ||
        finalout != 0) {
        vtun_syslog(LOG_ERR, "Failed to finalize AES-GCM message");
        return -1;
    }
    lfd_sub_extend(&sub, 16);
    if (!EVP_CIPHER_CTX_ctrl(ctx_enc, EVP_CTRL_GCM_GET_TAG, 16, lfd_sub_get_ptr(&sub, len))) {
        vtun_syslog(LOG_ERR, "Failed to get message tag for AES-GCM message");
        return -1;
    }

    return buf->size;
}

static int gcm_set_up_decryption(LfdBuffer *buf);
static int read_inband_message(LfdBuffer *buf);

static int gcm_decrypt(LfdBuffer *buf) {
    if (!decryption_inited) {
        if (gcm_set_up_decryption(buf) < 0) {
            vtun_syslog(LOG_ERR, "Set up decryption failed for AES-GCM");
            return -1;
        }
        if (!decryption_inited) {
            lfd_reset(buf);
            return 0;
        }
    }
    const EVP_CIPHER *cipher;
    switch (cipher_no) {
        case VTUN_ENC_AES128GCM:
            cipher = EVP_aes_128_gcm();
            break;
        case VTUN_ENC_AES256GCM:
            cipher = EVP_aes_256_gcm();
            break;
    }
    uint8_t ivdata[32];
    memcpy(ivdata, dec_iv, 16);
    *((uint64_t *)(ivdata + 16)) = htobe64(dec_seq++);
    memset(ivdata + 24, 0, 8);
    uint8_t noncebuf[SHA256_DIGEST_LENGTH];
    uint8_t *nonce = SHA256(ivdata, 32, noncebuf);
    EVP_DecryptInit_ex(ctx_dec, cipher, NULL, pkey, nonce);
    EVP_CIPHER_CTX_set_padding(ctx_dec, 0);
    size_t len = buf->size;
    if (len < 16 || (len & 15) != 0) {
        vtun_syslog(LOG_ERR, "Size is of packet not appropriate for AES-GCM decryption");
        return -1;
    }
    len -= 16;
    for (size_t off = 0; off < len; off += 16) {
        int blkout = 0;
        EVP_DecryptUpdate(ctx_dec, buf->ptr+off, &blkout, buf->ptr+off, 16);
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx_dec, EVP_CTRL_GCM_SET_TAG, 16, buf->ptr+len)) {
        vtun_syslog(LOG_ERR, "Failed to stage the AES-GCM tag for verification");
        return -1;
    }
    int finalout = 0;
    if (EVP_DecryptFinal(ctx_dec, buf->ptr+len, &finalout) <= 0) {
        vtun_syslog(LOG_ERR, "Failed to verify the integrity of the AES-GCM message");
        return -1;
    }
    buf->size -= 16;
    uint8_t pad = ((uint8_t *) buf->ptr)[buf->size - 1];
    if (pad <= 0 || pad > 16 || pad > buf->size) {
        vtun_syslog(LOG_ERR, "Incorrect message padding");
        return -1;
    }
    buf->size -= pad;
    if (!read_inband_message(buf)) {
        return -1;
    }
    return buf->size;
}

static int gcm_set_up_encryption(LfdBuffer *buf) {
    if (!lfd_extend_below(buf, 32)) {
        return -1;
    }
    memcpy(buf->ptr, "ivec", 4);
    RAND_bytes(buf->ptr+4, 28);
    memcpy(enc_iv, buf->ptr+4, 16);
    RAND_bytes((unsigned char *) &enc_seq_base, sizeof(enc_seq_base));
    int outlen = 16;
    EVP_EncryptUpdate(ctx_enc_sideband, buf->ptr, &outlen, buf->ptr, 16);
    if (outlen != 16) {
        return -1;
    }
    EVP_EncryptUpdate(ctx_enc_sideband, buf->ptr+16, &outlen, buf->ptr+16, 16);
    return outlen == 16 ? 32 : -1;
}

static int gcm_receive_gibberish(LfdBuffer *buf);

static int gcm_set_up_decryption(LfdBuffer *buf) {
    if (buf->size < 32) {
        return -1;
    }
    int outlen = 16;
    EVP_DecryptUpdate(ctx_dec_sideband, buf->ptr, &outlen, buf->ptr, 16);
    if (outlen != 16 || memcmp(buf->ptr, "ivec", 4) != 0) {
        return gcm_receive_gibberish(buf);
    }
    EVP_DecryptUpdate(ctx_dec_sideband, buf->ptr+16, &outlen, buf->ptr+16, 16);
    if (outlen != 16) {
        return -1;
    }
    memcpy(dec_iv, buf->ptr + 4, 16);
    lfd_reduce_below(buf, 32);
    decryption_inited = 1;
    return 32;
}

static int gcm_add_inband(LfdSubBuffer *sub) {
    if (!lfd_sub_extend_below(sub, 16)) {
        return 0;
    }
    char *buf = lfd_sub_get_ptr(sub, 0);
    if (request_reinit) {
        request_reinit = 0;
        buf[0] = 'r';
        buf[1] = 's';
        buf[2] = 'y';
        buf[3] = 'n';
    } else {
        buf[0] = 's';
        buf[1] = 'e';
        buf[2] = 'q';
        buf[3] = '#';
    }
    ((uint32_t *) buf)[1] = htobe32(enc_seq + enc_seq_base);
    RAND_bytes(buf + 8, 8);
    return 1;
}

static int read_inband_message(LfdBuffer *buf) {
    if (buf->size < 16) {
        vtun_syslog(LOG_ERR, "Message is not large enough for containing the sequencing part");
        return 0;
    }
    if (!memcmp(buf->ptr, "seq#", 4)) {
    } else if (!memcmp(buf->ptr, "rsyn", 4)) {
        vtun_syslog(LOG_INFO, "Reinit request received");
        decryption_inited = 0;
        send_a_packet = 1;
    } else {
        vtun_syslog(LOG_ERR, "Inband message is invalid");
        return 0;
    }
    dec_msg_seq = be32toh(((uint32_t *) buf->ptr)[1]);
    lfd_reduce_below(buf, 16);
    return 1;
}

static int gcm_receive_gibberish(LfdBuffer *buf) {
    int first_gibberish = (gibberish_counter == 0);
    ++gibberish_counter;
    time_t gibberish_elapsed;
    if (first_gibberish) {
        gibberish_time = time(NULL);
        gibberish_elapsed = 0;
    } else {
        gibberish_elapsed = time(NULL) - gibberish_time;
    }
    if (gibberish_counter == MIN_GIBBERISH) {
        request_reinit = 1;
        send_a_packet = 1;
    }
    if (gibberish_counter >= MAX_GIBBERISH || gibberish_elapsed >= MAX_GIBBERISH_TIME) {
        request_reinit = 0;
        send_a_packet = 1;
        vtun_syslog(LOG_ERR, "Other end is taking too long to respond to reinit request, resetting encoder");
        encryption_inited = 0;
    }
    lfd_reset(buf);
    return 0;
}

struct lfd_mod lfd_gcm_encrypt = {
    "GCMEncryptor",
    alloc_gcm_encrypt,
    gcm_encrypt,
    NULL,
    gcm_decrypt,
    NULL,
    free_gcm_encrypt,
    NULL,
    NULL
};

#else

static int alloc_gcm_encrypt(struct vtun_host *host) {
    vtun_syslog(LOG_ERR, "AES-GCM is not supported without openssl");
    return -1;
}

struct lfd_mod lfd_gcm_encrypt = {
    "GCMEncryptor",
    alloc_gcm_encrypt,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

#endif
