# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

SUBDIRS = docker
EXTRA_DIST = radiusclient-ipv6.conf servers-ipv6 \
	radiusclient.conf servers README

nodist_check_SCRIPTS = basic-tests.sh ipv6-tests.sh
check_PROGRAMS = bindaddr
bindaddr_SOURCES = bindaddr.c
bindaddr_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)
bindaddr_LDADD = $(top_builddir)/lib/libfreeradius-client.la
TESTS = bindaddr basic-tests.sh ipv6-tests.sh

TESTS_ENVIRONMENT = \
	top_builddir="$(top_builddir)"                          \
	srcdir="$(srcdir)"

