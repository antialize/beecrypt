LIBBEECRYPT_CXX_LT_CURRENT = 11
LIBBEECRYPT_CXX_LT_AGE = 5
LIBBEECRYPT_CXX_LT_REVISION = 0

INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

SUBDIRS = lang math io nio util security crypto beeyond . provider

libaltdir=$(prefix)/lib@LIBALT@
cxxdir=$(pkgincludedir)/c++

libalt_LTLIBRARIES = libbeecrypt_cxx.la

libbeecrypt_cxx_la_SOURCES = \
adapter.cxx \
resource.cxx

libbeecrypt_cxx_la_LIBADD = ../libbeecrypt.la lang/libcxxlang.la math/libcxxmath.la io/libcxxio.la nio/libcxxnio.la util/libcxxutil.la security/libcxxsecurity.la crypto/libcxxcrypto.la beeyond/libcxxbeeyond.la -licuuc -licuio
libbeecrypt_cxx_la_LDFLAGS = -no-undefined -version-info $(LIBBEECRYPT_CXX_LT_CURRENT):$(LIBBEECRYPT_CXX_LT_REVISION):$(LIBBEECRYPT_CXX_LT_AGE)

cxx_HEADERS = \
array.h

noinst_HEADERS = \
adapter.h \
resource.h

EXTRA_DIST = Doxyheader

TESTS = testks testdsa testrsa testdhaes 

check_PROGRAMS = testks testdsa testrsa testdhaes 

testks_SOURCES = testks.cxx
testks_LDADD = libbeecrypt_cxx.la

testdsa_SOURCES = testdsa.cxx
testdsa_LDADD = libbeecrypt_cxx.la

testrsa_SOURCES = testrsa.cxx
testrsa_LDADD = libbeecrypt_cxx.la

testdhaes_SOURCES = testdhaes.cxx
testdhaes_LDADD = libbeecrypt_cxx.la
