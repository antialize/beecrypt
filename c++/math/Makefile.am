INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxmath.la

cxxmathdir=$(pkgincludedir)/c++/math

libcxxmath_la_SOURCES = \
BigInteger.cxx

cxxmath_HEADERS = \
BigInteger.h

TESTS = testbigint

check_PROGRAMS = testbigint

testbigint_SOURCES = testbigint.cxx
testbigint_LDADD = ../libbeecrypt_cxx.la ../../libbeecrypt.la
