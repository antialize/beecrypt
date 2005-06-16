INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxlang.la

cxxlangdir=$(pkgincludedir)/c++/lang

libcxxlang_la_SOURCES = \
Character.cxx \
Integer.cxx \
Long.cxx \
Object.cxx \
String.cxx \
StringBuffer.cxx \
StringBuilder.cxx \
System.cxx \
Thread.cxx \
Throwable.cxx

cxxlang_HEADERS = \
Appendable.h \
ArithmeticException.h \
Character.h \
CharSequence.h \
ClassCastException.h \
Cloneable.h \
CloneNotSupportedException.h \
Comparable.h \
Error.h \
Exception.h \
IllegalArgumentException.h \
IllegalMonitorStateException.h \
IllegalStateException.h \
IllegalThreadStateException.h \
IndexOutOfBoundsException.h \
Integer.h \
InterruptedException.h \
Long.h \
NullPointerException.h \
Number.h \
NumberFormatException.h \
Object.h \
OutOfMemoryError.h \
Runnable.h \
RuntimeException.h \
String.h \
StringBuffer.h \
StringBuilder.h \
System.h \
Thread.h \
Throwable.h \
UnsupportedOperationException.h

TESTS = teststring testthread testnotify

check_PROGRAMS = teststring testthread testnotify

teststring_SOURCES = teststring.cxx
teststring_LDADD = ../libbeecrypt_cxx.la

testthread_SOURCES = testthread.cxx
testthread_LDADD = ../libbeecrypt_cxx.la

testnotify_SOURCES = testnotify.cxx
testnotify_LDADD = ../libbeecrypt_cxx.la
