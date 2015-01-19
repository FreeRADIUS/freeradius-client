######################################################################
#
#  Make a release.
#
######################################################################

# Update before making a release.
VERSION=1.1.7

dist-sign: freeradius-client-$(VERSION).tar.gz.sig

dist: freeradius-client-$(VERSION).tar.gz

.PHONY: freeradius-client-$(VERSION).tar.gz
freeradius-client-$(VERSION).tar.gz:
	@git archive --format=tar --prefix=freeradius-client-$(VERSION)/ master | gzip > $@

freeradius-client-$(VERSION).tar.gz.sig: freeradius-client-$(VERSION).tar.gz
	gpg --default-key aland@freeradius.org -b $<

#
#  Note that we do NOT do the tagging here!  We just print out what
#  to do!
#
dist-tag: freeradius-client-$(VERSION).tar.gz freeradius-client-$(VERSION).tar.bz2
	@echo "cd freeradius-client-$(VERSION) && cvs tag release_`echo $(VERSION) | tr .- __` && cd .."
