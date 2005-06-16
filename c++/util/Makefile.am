INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

SUBDIRS = concurrent .

noinst_LTLIBRARIES = libcxxutil.la
cxxutildir= $(pkgincludedir)/c++/util

libcxxutil_la_SOURCES =\
Date.cxx \
Properties.cxx

libcxxutil_la_LIBADD = concurrent/libcxxutilconcurrent.la

cxxutil_HEADERS =\
AbstractCollection.h \
AbstractList.h \
AbstractMap.h \
AbstractSet.h \
ArrayList.h \
Collection.h \
ConcurrentModificationException.h \
Date.h \
Enumeration.h \
Hashtable.h \
Iterable.h \
Iterator.h \
Map.h \
NoSuchElementException.h \
Properties.h \
RandomAccess.h \
Queue.h \
Set.h

TESTS = testlist testdate testprop

check_PROGRAMS = testlist testdate testprop

testlist_SOURCES = testlist.cxx
testlist_LDADD = ../libbeecrypt_cxx.la

testdate_SOURCES = testdate.cxx
testdate_LDADD = ../libbeecrypt_cxx.la

testprop_SOURCES = testprop.cxx
testprop_LDADD = ../libbeecrypt_cxx.la
