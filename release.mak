######################################################################
#
#  Make a release.
#
######################################################################

# Update before making a release.
VERSION=1.1.6

freeradius-client-$(VERSION): CVS
	@CVSROOT=`cat CVS/Root`; \
	cvs -d $$CVSROOT checkout -P -d freeradius-client-$(VERSION) radiusclient

freeradius-client-$(VERSION).tar.gz: freeradius-client-$(VERSION)
	@tar --exclude=CVS -zcf  $@ $<

freeradius-client-$(VERSION).tar.gz.sig: freeradius-client-$(VERSION).tar.gz
	gpg --default-key aland@freeradius.org -b $<

freeradius-client-$(VERSION).tar.bz2: freeradius-client-$(VERSION)
	@tar --exclude=CVS -jcf $@ $<

freeradius-client-$(VERSION).tar.bz2.sig: freeradius-client-$(VERSION).tar.bz2
	gpg --default-key aland@freeradius.org -b $<

dist: freeradius-client-$(VERSION).tar.gz freeradius-client-$(VERSION).tar.bz2

dist-sign: freeradius-client-$(VERSION).tar.gz.sig freeradius-client-$(VERSION).tar.bz2.sig

dist-publish: freeradius-client-$(VERSION).tar.gz.sig freeradius-client-$(VERSION).tar.gz freeradius-client-$(VERSION).tar.gz.sig freeradius-client-$(VERSION).tar.bz2 freeradius-client-$(VERSION).tar.gz.sig freeradius-client-$(VERSION).tar.bz2.sig
	scp $^ freeradius.org@freeradius.org:public_ftp

#
#  Note that we do NOT do the tagging here!  We just print out what
#  to do!
#
dist-tag: freeradius-client-$(VERSION).tar.gz freeradius-client-$(VERSION).tar.bz2
	@echo "cd freeradius-client-$(VERSION) && cvs tag release_`echo $(VERSION) | tr .- __` && cd .."
