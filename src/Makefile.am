#
# $Id: Makefile.am,v 1.7 2007/03/01 17:50:38 cparker Exp $
#
# Copyright (C) 1995,1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
#

AUTOMAKE_OPTIONS = foreign

pkgsysconfdir=@pkgsysconfdir@

DEFS = @DEFS@ -DRC_CONFIG_FILE=\"${pkgsysconfdir}/radiusclient.conf\" \
	      -DRC_SECURE_PATH=\"@RC_SECURE_PATH@\"
AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)
LDADD = ../lib/libradcli.la

CLEANFILES = *~

noinst_LIBRARIES = libtools.a
libtools_a_SOURCES = common.c common.h

noinst_PROGRAMS = radstatus radacct radexample radiusclient radembedded
radacct_SOURCES = radacct.c
radstatus_SOURCES = radstatus.c

radexample_SOURCES = radexample.c
radexample_LDADD = ../lib/libradcli.la libtools.a

radiusclient_SOURCES = radiusclient.c
radiusclient_LDADD = ../lib/libradcli.la libtools.a


radembedded_SOURCES = radembedded.c
