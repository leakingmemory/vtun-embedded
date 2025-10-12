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

/*
   Encryption module uses software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)       
   Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 */

/*
 * This lfd_encrypt module uses MD5 to create 128 bits encryption
 * keys and BlowFish for actual data encryption.
 * It is based on code written by Chris Todd<christ@insynq.com> with 
 * several improvements and modifications.  
 */

#include "config.h"

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <strings.h>
#include <string.h>

#include "vtun.h"
#include "linkfd.h"
#include "lib.h"
#include "linkfd_buffers.h"

#ifdef HAVE_SSL

#ifndef __APPLE_CC__
/* OpenSSL includes */
#include <openssl/md5.h>
#include <openssl/blowfish.h>
#else /* YAY - We're MAC OS */
#include <sys/md5.h>
#include <crypto/blowfish.h>
#endif  /* __APPLE_CC__ */

#define ENC_BUF_SIZE VTUN_FRAME_SIZE + 16 
#define ENC_KEY_SIZE 16

static BF_KEY key;
static LfdBuffer enc_buf;

static int alloc_legacy_encrypt(struct vtun_host *host)
{
   if ((enc_buf = lfd_alloc(ENC_BUF_SIZE)).ptr == NULL) {
      vtun_syslog(LOG_ERR,"Can't allocate buffer for legacy encryptor");
      return -1;
   }

   BF_set_key(&key, ENC_KEY_SIZE, MD5(host->passwd,strlen(host->passwd),NULL));

   vtun_syslog(LOG_INFO, "BlowFish legacy encryption initialized");
   return 0;
}

static int free_legacy_encrypt()
{
   lfd_free(&enc_buf);
   return 0;
}

static int legacy_encrypt_buf(LfdBuffer *buf)
{ 
   register int pad, p;

   /* 8 - ( len % 8 ) */
   {
      size_t len = buf->size;
      pad = (~len & 0x07) + 1; p = 8 - pad;


      if (!lfd_extend_below(buf, pad)) {
         lfd_reset(buf);
         return 0;
      }
      memset(buf->ptr, 0, pad);
      *((char *) buf->ptr) = (char) pad;
   }

   if (!lfd_ensure_capacity(&enc_buf, buf->size)) {
      lfd_reset(buf);
      return 0;
   }
   for (size_t off=0; off < buf->size; off += 8)
      BF_ecb_encrypt(buf->ptr + off,  enc_buf.ptr + off, &key, BF_ENCRYPT);

   memcpy(buf->ptr, enc_buf.ptr, buf->size);

   return buf->size;
}

static int legacy_decrypt_buf(LfdBuffer *buf)
{
   for (size_t p = 0; p < buf->size; p += 8) {
      void *blk = lfd_get_ptr(buf, p);
      BF_ecb_encrypt(blk, blk, &key, BF_DECRYPT);
   }

   int p = ((char *) buf->ptr)[0];
   if (p < 1 || p > 8) {
      vtun_syslog(LOG_INFO, "legacy_decrypt_buf: bad pad length");
      return 0;
   }

   lfd_reduce_below(buf, p);

   return buf->size;
}

/* 
 * Module structure.
 */
struct lfd_mod lfd_legacy_encrypt = {
     "Encryptor",
     alloc_legacy_encrypt,
     legacy_encrypt_buf,
     NULL,
     legacy_decrypt_buf,
     NULL,
     free_legacy_encrypt,
     NULL,
     NULL
};

#else  /* HAVE_SSL */

static int no_legacy_encrypt(struct vtun_host *host)
{
     vtun_syslog(LOG_INFO, "Encryption is not supported");
     return -1;
}

struct lfd_mod lfd_legacy_encrypt = {
     "Encryptor",
     no_legacy_encrypt, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

#endif /* HAVE_SSL */
