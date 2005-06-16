INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxutilconcurrentlocks.la
cxxutilconcurrentlocksdir= $(pkgincludedir)/c++/util/concurrent/locks

libcxxutilconcurrentlocks_la_SOURCES = \
ReentrantLock.cxx

cxxutilconcurrentlocks_HEADERS = \
Lock.h \
ReentrantLock.h

TESTS = testthread

check_PROGRAMS = testthread

testthread_SOURCES = testthread.cxx
testthread_LDADD = ../../../libbeecrypt_cxx.la
