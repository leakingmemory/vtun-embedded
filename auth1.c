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

#include <unistd.h>

#include "lock.h"

#include <stdio.h>

#include "vtun.h"
#include "lib.h"
#include <string.h>

/* Authentication (Server side) */
struct vtun_host * auth_server_v1(int fd, char *host)
{
    char chal_req[VTUN_CHAL_SIZE], chal_res[VTUN_CHAL_SIZE];
    char buf[VTUN_MESG_SIZE], *str1, *str2;
    struct vtun_host *h = NULL;

    gen_chal(chal_req);
    print_p(fd,"OK CHAL: %s\n", cl2cs(chal_req));

    if ( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
        buf[sizeof(buf)-1]='\0';
        strtok(buf,"\r\n");

        if( (str1=strtok(buf," :")) &&
            (str2=strtok(NULL," :")) ) {
            if( !strcmp(str1,"CHAL") ){
                if( cs2cl(str2,chal_res) &&
                    (h = find_host_server(host)) ) {

                    decrypt_chal(chal_res, h->passwd);

                    if( !memcmp(chal_req, chal_res, VTUN_CHAL_SIZE) &&
                        (h->requires_flags & VTUN_REQUIRES_BIDIRAUTH) == 0 ){
                        /* Auth successeful. */

                        /* Lock host */
                        if( lock_host(h) >= 0 ){
                            print_p(fd,"OK FLAGS: %s\n", bf2cf(h));
                        } else {
                            /* Multiple connections are denied */
                            h = NULL;
                        }
                    } else
                        h = NULL;
                }
            }
        }
    }

    if( !h )
        print_p(fd,"ERR\n");

    return h;
}

/* Authentication (Client side) */
int auth_client_v1(int fd, struct vtun_host *host)
{
    char buf[VTUN_MESG_SIZE], chal[VTUN_CHAL_SIZE];
    int stage, success=0 ;

    if ((host->requires_flags & VTUN_REQUIRES_BIDIRAUTH) != 0) {
        print_p(fd, "ERR\n");
        return success;
    }

    print_p(fd,"HOST: %s\n",host->host);

    stage = ST_HOST;

    while( readn_t(fd, buf, VTUN_MESG_SIZE, vtun.timeout) > 0 ){
        buf[sizeof(buf)-1]='\0';
        switch( stage ){
            case ST_HOST:
                if( !strncmp(buf,"OK",2) && cs2cl(buf,chal)){
                    stage = ST_CHAL;

                    encrypt_chal(chal,host->passwd);
                    print_p(fd,"CHAL: %s\n", cl2cs(chal));

                    continue;
                }
                break;

            case ST_CHAL:
                if( !strncmp(buf,"OK",2) && cf2bf(buf,host) )
                    success = 1;
                break;
        }
        break;
    }

    return success;
}
