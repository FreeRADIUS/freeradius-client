#
# $Id: Makefile.am,v 1.6 2007/02/19 22:14:11 cparker Exp $
#
# Copyright (C) 1995,1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
#

AUTOMAKE_OPTIONS = foreign

pkgsysconfdir=@pkgsysconfdir@

DEFS = @DEFS@ -DRC_CONFIG_FILE=\"${pkgsysconfdir}/radiusclient.conf\" \
	      -DRC_SECURE_PATH=\"@RC_SECURE_PATH@\"
INCLUDES = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)
LDADD = ../lib/libfreeradius-client.la

CLEANFILES = *~

noinst_HEADERS = radlogin.h

sbin_PROGRAMS = radlogin radstatus radacct radexample radiusclient radembeded
radlogin_SOURCES = radlogin.c radius.c local.c
radacct_SOURCES = radacct.c
radstatus_SOURCES = radstatus.c
radexample_SOURCES = radexample.c
radiusclient_SOURCES = radiusclient.c
radembedded_SOURCES = radembedded.c
