#
# $Id: Makefile.am,v 1.7 2010/02/04 10:27:09 aland Exp $
#
# Copyright (C) 1995,1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

AUTOMAKE_OPTIONS = foreign

RC_LOG_FACILITY = @RC_LOG_FACILITY@
LIBVERSION = @LIBVERSION@

AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir) $(CRYPTO_CFLAGS) -Wall
DEFS = @DEFS@ -DRC_LOG_FACILITY=$(RC_LOG_FACILITY)

CLEANFILES = *~

# Pkg-config script.
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = radcli.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES =  libradcli.la
libradcli_la_SOURCES = buildreq.c sendserver.c \
	avpair.c config.c dict.c ip_util.c log.c util.c  \
	options.h rc-md5.h rc-md5.c util.h tls.c tls.h

if !ENABLE_NETTLE
libradcli_la_SOURCES += md5.c md5.h
endif

libradcli_la_LDFLAGS = -version-info $(LIBVERSION)

libradcli_la_LIBADD = $(CRYPTO_LIBS)

install-exec-hook:
	cd $(DESTDIR)$(libdir) && $(LN_S) libradcli.so libfreeradius-client.so
