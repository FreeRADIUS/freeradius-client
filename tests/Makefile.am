# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

SUBDIRS = docker
EXTRA_DIST = radiusclient-ipv6.conf servers-ipv6 \
	radiusclient.conf servers README \
	dtls/ca.pem dtls/clicert.pem \
	dtls/clikey.pem dtls/radiusclient-tls.conf \
	dtls/radsecproxy.conf

AM_CPPFLAGS = -I$(srcdir) -I$(top_srcdir)/include -I$(top_builddir)
LDADD = ../lib/libfreeradius-client.la

nodist_check_SCRIPTS = basic-tests.sh ipv6-tests.sh tls-tests.sh
TESTS = basic-tests.sh ipv6-tests.sh
check_PROGRAMS =

if ENABLE_GNUTLS
TESTS += tls-tests.sh

check_PROGRAMS += tls-restart

tls_restart_SOURCES = tls-restart.c
tls_restart_LDADD = ../src/libtools.a ../lib/libradcli.la
endif


TESTS_ENVIRONMENT = \
	top_builddir="$(top_builddir)"                          \
	srcdir="$(srcdir)"

