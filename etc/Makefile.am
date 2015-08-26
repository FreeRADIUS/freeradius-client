#
# $Id: Makefile.am,v 1.5 2008/01/05 03:04:46 sobomax Exp $
#
# Copyright (C) 1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions.
# If the file is missing contact me at lf@elemental.net
# and I'll send you a copy.
#

AUTOMAKE_OPTIONS = foreign

CLEANFILES = *~ radiusclient.conf radiusclient-tls.conf

sbindir = @sbindir@
pkgsysconfdir = @pkgsysconfdir@
pkgsysconf_DATA = radiusclient.conf radiusclient-tls.conf

sharedir = $(datadir)/@PACKAGE@
share_DATA = dictionary dictionary.microsoft dictionary.roaringpenguin

EXTRA_DIST = dictionary servers servers-tls radiusclient.conf.in \
	radiusclient-tls.conf.in

radiusclient.conf: radiusclient.conf.in
	sed -e 's|@sbin''dir@|$(sbindir)|g' \
	    -e 's|@pkgsysconf''dir@|$(pkgsysconfdir)|g' \
	    <$(srcdir)/radiusclient.conf.in >radiusclient.conf
	chmod ogu-w $@

install-data-local: servers servers-tls
	$(mkinstalldirs) $(DESTDIR)$(pkgsysconfdir); \
	echo " $(INSTALL) -m 600 $(srcdir)/servers $(DESTDIR)$(pkgsysconfdir)/servers"; \
	echo " $(INSTALL) -m 600 $(srcdir)/servers-tls $(DESTDIR)$(pkgsysconfdir)/servers-tls"
	$(INSTALL) -m 600 $(srcdir)/servers $(DESTDIR)$(pkgsysconfdir)/servers
	$(INSTALL) -m 600 $(srcdir)/servers-tls $(DESTDIR)$(pkgsysconfdir)/servers-tls

radiusclient-tls.conf: radiusclient-tls.conf.in
	sed -e 's|@sbin''dir@|$(sbindir)|g' \
	    -e 's|@pkgsysconf''dir@|$(pkgsysconfdir)|g' \
	    <$(srcdir)/radiusclient-tls.conf.in >radiusclient-tls.conf
	chmod ogu-w $@

uninstall-local:
	rm -f $(DESTDIR)$(pkgsysconfdir)/servers
	rm -f $(DESTDIR)$(pkgsysconfdir)/servers-tls
