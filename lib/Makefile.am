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

AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir) $(CRYPTO_CFLAGS)
DEFS = @DEFS@ -DRC_LOG_FACILITY=$(RC_LOG_FACILITY)

CLEANFILES = *~

lib_LTLIBRARIES =   libfreeradius-client.la
libfreeradius_client_la_SOURCES = buildreq.c clientid.c env.c sendserver.c \
	avpair.c config.c dict.c ip_util.c log.c util.c  \
	options.h rc-md5.h rc-md5.c

if !ENABLE_NETTLE
libfreeradius_client_la_SOURCES += md5.c md5.h
endif

libfreeradius_client_la_LDFLAGS = -version-info $(LIBVERSION)

libfreeradius_client_la_LIBADD = $(CRYPTO_LIBS)
