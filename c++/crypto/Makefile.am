INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

SUBDIRS = interfaces spec

noinst_LTLIBRARIES = libcxxcrypto.la

cxxcryptodir=$(pkgincludedir)/c++/crypto

libcxxcrypto_la_SOURCES = \
Cipher.cxx \
CipherSpi.cxx \
KeyAgreement.cxx \
Mac.cxx \
MacInputStream.cxx \
MacOutputStream.cxx \
NullCipher.cxx \
SecretKeyFactory.cxx

libcxxcrypto_la_LIBADD = spec/libcxxcryptospec.la

cxxcrypto_HEADERS = \
BadPaddingException.h \
Cipher.h \
CipherSpi.h \
IllegalBlockSizeException.h \
KeyAgreement.h \
KeyAgreementSpi.h \
Mac.h \
MacInputStream.h \
MacOutputStream.h \
MacSpi.h \
NoSuchPaddingException.h \
NullCipher.h \
SecretKey.h \
SecretKeyFactory.h \
SecretKeyFactorySpi.h
