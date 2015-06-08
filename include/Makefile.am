# 
#  $Id: Makefile.am,v 1.3 2007/01/06 20:15:28 pnixon Exp $
# 
#  Copyright (C) 1997 Lars Fenneberg
# 
#  See the file COPYRIGHT for the respective terms and conditions. 
#  If the file is missing contact me at lf@elemental.net 
#  and I'll send you a copy.
# 
#

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = radcli/version.h.in

noinst_HEADERS = pathnames.h messages.h includes.h

if ENABLE_LEGACY_COMPAT
include_HEADERS = freeradius-client.h radiusclient-ng.h
endif

nobase_include_HEADERS = radcli/version.h radcli/radcli.h

