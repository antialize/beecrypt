INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxio.la
cxxiodir= $(pkgincludedir)/c++/io

libcxxio_la_SOURCES =\
ByteArrayInputStream.cxx \
ByteArrayOutputStream.cxx \
DataInputStream.cxx \
DataOutputStream.cxx \
EOFException.cxx \
FileInputStream.cxx \
FileOutputStream.cxx \
FilterInputStream.cxx \
FilterOutputStream.cxx \
InputStream.cxx \
IOException.cxx \
OutputStream.cxx \
PrintStream.cxx \
PushbackInputStream.cxx \
Writer.cxx

libcxxio_la_LIBADD = -licuuc

cxxio_HEADERS =\
ByteArrayInputStream.h \
ByteArrayOutputStream.h \
Closeable.h \
DataInput.h \
DataOutput.h \
DataInputStream.h \
DataOutputStream.h \
EOFException.h \
FileInputStream.h \
FileOutputStream.h \
FilterInputStream.h \
FilterOutputStream.h \
Flushable.h \
InputStream.h \
IOException.h \
OutputStream.h \
PrintStream.h \
PushbackInputStream.h \
Writer.h

TESTS = test

check_PROGRAMS = test

test_SOURCES = test.cxx
test_LDADD = $(top_builddir)/c++/libbeecrypt_cxx.la $(top_builddir)/libbeecrypt.la -licuuc -licuio
