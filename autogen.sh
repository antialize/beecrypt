#! /bin/sh
libtoolize --force --copy
aclocal
automake -a Makefile docs/Makefile gas/Makefile masm/Makefile mwerks/Makefile tests/Makefile
autoconf
autoheader
