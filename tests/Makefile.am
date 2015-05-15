# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# License: BSD

SUBDIRS = docker
EXTRA_DIST = radiusclient-ipv6.conf servers-ipv6 \
	radiusclient.conf servers README \
	dtls/ca.pem dtls/cert-rsa.pem dtls/clicert.pem \
	dtls/clikey.pem dtls/key-rsa.pem dtls/radiusclient-tls.conf \
	dtls/radsecproxy.conf

nodist_check_SCRIPTS = basic-tests.sh ipv6-tests.sh tls-tests.sh
TESTS = basic-tests.sh ipv6-tests.sh

if ENABLE_GNUTLS
TESTS += tls-tests.sh
endif

TESTS_ENVIRONMENT = \
	top_builddir="$(top_builddir)"                          \
	srcdir="$(srcdir)"

