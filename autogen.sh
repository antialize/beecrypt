#! /bin/sh
export CFLAGS
export LDFLAGS
libtoolize --force --copy
aclocal -I .
automake -a -c
autoconf
autoheader
