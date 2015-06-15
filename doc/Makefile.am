#
# $Id: Makefile.am,v 1.1 2003/12/02 10:39:22 sobomax Exp $
#
# Copyright (C) 1997 Lars Fenneberg
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

include $(top_srcdir)/doc/doc.mk

APIMANS += man/radcli.h.3

CLEANFILES = *~
DISTCLEANFILES = stamp_mans

EXTRA_DIST = Doxyfile.in scripts/getfuncs.pl scripts/getfuncs-map.pl doc.mk

dist_man_MANS = $(APIMANS)

$(APIMANS): stamp_mans

stamp_mans: ../include/radcli/radcli.h
	-doxygen Doxyfile
	-doxy2man -i radcli/ --short-pkg radcli --pkg 'Simple radius library'  --out man --novalidate xml/radcli_8h.xml
	echo > $@

update-doc: stamp_mans
	FUNCS=`cat $(top_srcdir)/include/radcli/radcli.h | $(top_srcdir)/doc/scripts/getfuncs.pl|sort -d|uniq`; \
	MANS=""; \
	for i in $$FUNCS; do \
		MANS="$$MANS\nAPIMANS += man\/$$i.3"; \
	done; \
	grep -v -e '^APIMANS += ' doc.mk | \
		perl -p -e "s/^APIMANS =/APIMANS =$$MANS/" > tmp-$@; \
	diff -u $(srcdir)/doc.mk tmp-$@ || mv tmp-$@ doc.mk
	rm -f tmp-$@

dist-hook: update-doc
