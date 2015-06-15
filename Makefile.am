# 
#  $Id: Makefile.am,v 1.3 2006/03/14 17:14:27 janakj Exp $
# 
#  Copyright (C) 1997 Lars Fenneberg
# 
#  See the file COPYRIGHT for the respective terms and conditions. 
#  If the file is missing contact me at lf@elemental.net 
#  and I'll send you a copy.
# 
#

AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -D_GNU_SOURCE

ACLOCAL = @ACLOCAL@
LTLIBOBJS = @LTLIBOBJS@

SUBDIRS = include lib src etc man doc tests
EXTRA_DIST = NEWS COPYRIGHT README.rst

compare-exported: include/radcli/radcli.h
	doc/scripts/getfuncs.pl <$^|sort -u >tmp-head-$@
	doc/scripts/getfuncs-map.pl <lib/radcli.map|sort -u >tmp-exp-$@
	@echo "******************************************************************************"
	@echo "If the following step fails there is a symbol in headers that is not exported or vice-versa"
	@echo "******************************************************************************"
	diff -u tmp-exp-$@ tmp-head-$@
	rm -f tmp-exp-$@ tmp-head-$@

dist-hook: compare-exported

CLEANFILES = *~
