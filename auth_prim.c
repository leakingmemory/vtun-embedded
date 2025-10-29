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

#include <stdio.h>

#include "config.h"
#include "vtun.h"
#include "lib.h"

#include "md5.h"
#include "blowfish.h"
#include <string.h>
#include <syslog.h>

/* Encryption and Decryption of the challenge key */
#ifdef HAVE_SSL

#include <openssl/rand.h>

void auth_prim_gen_chal(char *buf)
{
    RAND_bytes((unsigned char *) buf, VTUN_CHAL_SIZE);
}

#else /* HAVE_SSL */

/* Generate PSEUDO random challenge key. */
void auth_prim_gen_chal(char *buf)
{
    register int i;

    srand(time(NULL));

    for(i=0; i < VTUN_CHAL_SIZE; i++)
        buf[i] = (unsigned int)(255.0 * rand()/RAND_MAX);
}

#endif /* HAVE_SSL */

void auth_prim_encrypt_chal(char *chal, char *pwd)
{
    register int i;
    BlowfishContext key;
    md5_hash hash;

    md5(&hash, (unsigned char *)pwd, strlen(pwd));
    blowfish_init(&key, &hash, 16);

    for(i=0; i < VTUN_CHAL_SIZE; i += 8 )
        blowfish_encrypt_8bytes_ecb(&key, chal + i);
}

void auth_prim_decrypt_chal(char *chal, char *pwd)
{
    register int i;
    BlowfishContext key;
    md5_hash hash;

    md5(&hash, (unsigned char *)pwd, strlen(pwd));
    blowfish_init(&key, &hash, 16);

    for(i=0; i < VTUN_CHAL_SIZE; i += 8 )
        blowfish_decrypt_8bytes_ecb(&key, chal + i);
}

/*
 * Functions to convert binary flags to character string.
 * string format:  <CS64>
 * C - compression, S - speed for shaper and so on.
 */

char *auth_prim_bf2cf(struct vtun_host *host)
{
    static char str[20], *ptr = str;

    *(ptr++) = '<';

    switch( host->flags & VTUN_PROT_MASK ){
        case VTUN_TCP:
            *(ptr++) = 'T';
            break;

        case VTUN_UDP:
            *(ptr++) = 'U';
            break;
    }

    switch( host->flags & VTUN_TYPE_MASK ){
        case VTUN_TTY:
            *(ptr++) = 't';
            break;

        case VTUN_PIPE:
            *(ptr++) = 'p';
            break;

        case VTUN_ETHER:
            *(ptr++) = 'e';
            break;

        case VTUN_TUN:
            *(ptr++) = 'u';
            break;
    }

    if( (host->flags & VTUN_SHAPE) /* && host->spd_in */)
        ptr += sprintf(ptr,"S%d",host->spd_in);

    if( host->flags & VTUN_ZLIB )
        ptr += sprintf(ptr,"C%d", host->zlevel);

    if( host->flags & VTUN_LZO )
        ptr += sprintf(ptr,"L%d", host->zlevel);

    if( host->flags & VTUN_KEEP_ALIVE )
        *(ptr++) = 'K';

    if( host->flags & VTUN_ENCRYPT ) {
        if (host->cipher == VTUN_LEGACY_ENCRYPT) { /* use old flag method */
            ptr += sprintf(ptr,"E");
        } else {
            ptr += sprintf(ptr,"E%d", host->cipher);
        }
    }

    strcat(ptr,">");

    return str;
}

/* return 1 on success, otherwise 0
   Example:
   FLAGS: <TuE1>
*/

int auth_prim_cf2bf(char *str, struct vtun_host *host)
{
    char *ptr, *p;
    int s;

    if( (ptr = strchr(str,'<')) ){
        vtun_syslog(LOG_DEBUG,"Remote Server sends %s.", ptr);
        ptr++;
        while(*ptr){
            switch(*ptr++){
                case 't':
                    host->flags |= VTUN_TTY;
                    break;
                case 'p':
                    host->flags |= VTUN_PIPE;
                    break;
                case 'e':
                    host->flags |= VTUN_ETHER;
                    break;
                case 'u':
                    host->flags |= VTUN_TUN;
                    break;
                case 'U':
                    host->flags &= ~VTUN_PROT_MASK;
                    host->flags |= VTUN_UDP;
                    break;
                case 'T':
                    host->flags &= ~VTUN_PROT_MASK;
                    host->flags |= VTUN_TCP;
                    break;
                case 'K':
                    host->flags |= VTUN_KEEP_ALIVE;
                    break;
                case 'C':
                    if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p)
                        return 0;
                    host->flags |= VTUN_ZLIB;
                    host->zlevel = s;
                    ptr = p;
                    break;
                case 'L':
                    if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p)
                        return 0;
                    host->flags |= VTUN_LZO;
                    host->zlevel = s;
                    ptr = p;
                    break;
                case 'E':
                    /* new form is 'E10', old form is 'E', so remove the
                   ptr==p check */
                    if((s = strtol(ptr,&p,10)) == ERANGE) {
                        vtun_syslog(LOG_ERR,"Garbled encryption method.  Bailing out.");
                        return 0;
                    }
                    host->flags |= VTUN_ENCRYPT;
                    if (0 == s) {
                        host->cipher = VTUN_LEGACY_ENCRYPT;
                        vtun_syslog(LOG_INFO,"Remote server using older encryption.");
                    } else {
                        host->cipher = s;
                    }
                    ptr = p;
                    break;
                case 'S':
                    if((s = strtol(ptr,&p,10)) == ERANGE || ptr == p)
                        return 0;
                    if( s ){
                        host->flags |= VTUN_SHAPE;
                        host->spd_out = s;
                    }
                    ptr = p;
                    break;
                case 'F':
                    /* reserved for Feature transmit */
                    break;
                case '>':
                    return 1;
                default:
                    return 0;
            }
        }
    }
    return 0;
}

int auth_prim_cs2cl(char *str, char *chal)
{
    register char *ptr = str;
    register int i;

    if( !(ptr = strchr(str,'<')) )
        return 0;
    ptr++;
    if( !strtok(ptr,">") || strlen(ptr) != VTUN_CHAL_SIZE*2 )
        return 0;

    for(i=0; i<VTUN_CHAL_SIZE && *ptr; i++, ptr+=2) {
        chal[i]  = (*ptr - 'a') << 4;
        chal[i] |= *(ptr+1) - 'a';
    }

    return 1;
}

/*
 * Functions to convert binary key data to character string.
 * string format:  <char_data>
 */

char *auth_prim_cl2cs(char *chal)
{
    static char str[VTUN_CHAL_SIZE*2+3], *chr="abcdefghijklmnop";
    register char *ptr = str;
    register int i;

    *(ptr++) = '<';
    for(i=0; i<VTUN_CHAL_SIZE; i++){
        *(ptr++) = chr[ ((chal[i] & 0xf0) >> 4) ];
        *(ptr++) = chr[ (chal[i] & 0x0f) ];
    }

    *(ptr++) = '>';
    *ptr = '\0';

    return str;
}
