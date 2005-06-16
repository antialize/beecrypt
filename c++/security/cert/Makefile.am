INCLUDES = -I$(top_srcdir)/..

AUTOMAKE_OPTIONS = gnu

noinst_LTLIBRARIES = libcxxsecuritycert.la

cxxsecuritycertdir=$(pkgincludedir)/c++/security/cert

libcxxsecuritycert_la_SOURCES =\
Certificate.cxx \
CertificateFactory.cxx \
CertPath.cxx \
CertPathValidator.cxx

cxxsecuritycert_HEADERS =\
Certificate.h \
CertificateEncodingException.h \
CertificateException.h \
CertificateExpiredException.h \
CertificateFactory.h \
CertificateFactorySpi.h \
CertificateNotYetValidException.h \
CertPath.h \
CertPathParameters.h \
CertPathValidator.h \
CertPathValidatorException.h \
CertPathValidatorResult.h \
CertPathValidatorSpi.h
