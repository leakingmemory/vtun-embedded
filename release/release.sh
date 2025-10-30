#!/bin/sh

version=$1

autoconf
rm -f vtun-embedded-$version.tar.gz
tar -czvf vtun-embedded-$version.tar.gz freebsd generic linux openbsd packages scripts svr4 tests *.m4 auth.c client.c lfd_encrypt.c lfd_legacy_encrypt.c lfd_lzo.c lfd_shaper.c lfd_zlib.c lib.c linkfd.c llist.c lock.c main.c netlib.c server.c tunnel.c vtun.c md5.c blowfish.c auth_prim.c auth1.c auth2.c *.h *.l *.y ChangeLog config.guess *.in config.sub configure.ac configure Credits FAQ install-sh README README.LZO README.OpenSSL README.Setup README.Shaper TODO vtun.drivers vtunemd.8 vtunemd.conf vtunemd.conf.5 license.txt
rm -rf vtun-embedded-$version
mkdir vtun-embedded-$version
cd vtun-embedded-$version
tar xzvf ../vtun-embedded-$version.tar.gz
cd ..
rm -f vtun-embedded-$version.tar.gz
tar -czvf vtun-embedded-$version.tar.gz vtun-embedded-$version
rm -rf vtun-embedded-$version
