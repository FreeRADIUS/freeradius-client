#
# $Id: Makefile.am,v 1.3 2005/03/01 14:58:44 janakj Exp $
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

INCLUDES = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)
DEFS = @DEFS@ -DRC_LOG_FACILITY=$(RC_LOG_FACILITY)

CLEANFILES = *~

noinst_HEADERS = options.h

#radiusclient_ng_SOURCES = buildreq.c clientid.c env.c sendserver.c avpair.c \
#	config.c dict.c ip_util.c log.c md5.c util.c lock.c

#radiusclient_ng_LIBADD = @LIBOBJS@

#lib_LIBRARIES = radiusclient-ng

lib_LTLIBRARIES = libradiusclient-ng.la
libradiusclient_ng_la_SOURCES = buildreq.c clientid.c env.c sendserver.c \
	avpair.c config.c dict.c ip_util.c log.c md5.c util.c lock.c
libradiusclient_ng_la_LDFLAGS = -version-info $(LIBVERSION)
#libradiusclient_ng_la_LIBADD = @LTLIBOBJS@
