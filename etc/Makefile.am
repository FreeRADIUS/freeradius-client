#
# $Id: Makefile.am,v 1.3 2005/11/07 22:55:34 sobomax Exp $
#
# Copyright (C) 1997,1998 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

AUTOMAKE_OPTIONS = foreign

CLEANFILES = *~ radiusclient.conf

sbindir = @sbindir@
pkgsysconfdir = @pkgsysconfdir@
pkgsysconf_DATA = issue port-id-map radiusclient.conf \
	dictionary dictionary.ascend dictionary.compat dictionary.merit \
	dictionary.sip

EXTRA_DIST = issue port-id-map dictionary dictionary.ascend \
	dictionary.compat dictionary.merit servers radiusclient.conf.in \
	dictionary.sip

radiusclient.conf: radiusclient.conf.in
	sed -e 's|@sbin''dir@|$(sbindir)|g' \
	    -e 's|@pkgsysconf''dir@|$(pkgsysconfdir)|g' \
	    <$(srcdir)/radiusclient.conf.in >radiusclient.conf

install-data-local: servers
	$(mkinstalldirs) $(pkgsysconfdir); \
        echo " $(INSTALL) -m 600 $(srcdir)/servers $(pkgsysconfdir)/servers"; \
        $(INSTALL) -m 600 $(srcdir)/servers $(pkgsysconfdir)/servers

uninstall-local:
	rm -f $(pkgsysconfdir)/servers
