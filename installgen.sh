#! /bin/sh
libtoolize --force
aclocal
autoheader
automake -a Makefile docs/Makefile gas/Makefile masm/Makefile mwerks/Makefile tests/Makefile
autoconf
