INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxlang.la

cxxlangdir=$(pkgincludedir)/c++/lang

libcxxlang_la_SOURCES = \
ArithmeticException.cxx \
Character.cxx \
ClassCastException.cxx \
CloneNotSupportedException.cxx \
Error.cxx \
Exception.cxx \
IllegalArgumentException.cxx \
IllegalMonitorStateException.cxx \
IllegalStateException.cxx \
IllegalThreadStateException.cxx \
IndexOutOfBoundsException.cxx \
Integer.cxx \
InterruptedException.cxx \
Long.cxx \
NullPointerException.cxx \
NumberFormatException.cxx \
Object.cxx \
OutOfMemoryError.cxx \
RuntimeException.cxx \
String.cxx \
StringBuffer.cxx \
StringBuilder.cxx \
System.cxx \
Thread.cxx \
Throwable.cxx \
UnsupportedOperationException.cxx

cxxlang_HEADERS = \
ArithmeticException.h \
Character.h \
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
