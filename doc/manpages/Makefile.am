#
# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# See the file COPYRIGHT for the respective terms and conditions. 
# If the file is missing contact me at lf@elemental.net 
# and I'll send you a copy.
#

EXTRA_DIST = gdoc getfuncs

C_SOURCE_FILES = $(top_srcdir)/lib/*.c

stamp_mans: $(top_srcdir)/include/freeradius-client.h
	@echo $(ECHO_N) "Creating man pages..." && \
	for i in `$(top_srcdir)/doc/manpages/getfuncs <$^`;do \
		$(top_srcdir)/doc/manpages/gdoc -man \
			-module $(PACKAGE) -sourceversion $(VERSION) \
			-pkg-site "http://freeradius.org/freeradius-client/" \
			-include "freeradius-client.h" \
			-seeinfo $(PACKAGE) -verbatimcopying \
			-function $$i \
			$(C_SOURCE_FILES) > $$i.3 2>/dev/null && \
		echo $(ECHO_N) "."; \
	done
	echo ""
	echo $@ > $@


APIMANS =
APIMANS += rc_aaa.3
APIMANS += rc_acct.3
APIMANS += rc_acct_proxy.3
APIMANS += rc_add_config.3
APIMANS += rc_add_env.3
APIMANS += rc_auth.3
APIMANS += rc_auth_proxy.3
APIMANS += rc_avpair_assign.3
APIMANS += rc_avpair_free.3
APIMANS += rc_avpair_gen.3
APIMANS += rc_avpair_get.3
APIMANS += rc_avpair_insert.3
APIMANS += rc_avpair_log.3
APIMANS += rc_avpair_new.3
APIMANS += rc_avpair_parse.3
APIMANS += rc_avpair_readin.3
APIMANS += rc_avpair_tostr.3
APIMANS += rc_buildreq.3
APIMANS += rc_check.3
APIMANS += rc_config_free.3
APIMANS += rc_config_init.3
APIMANS += rc_conf_int.3
APIMANS += rc_conf_srv.3
APIMANS += rc_conf_str.3
APIMANS += rc_destroy.3
APIMANS += rc_dict_findattr.3
APIMANS += rc_dict_findval.3
APIMANS += rc_dict_findvend.3
APIMANS += rc_dict_free.3
APIMANS += rc_dict_getattr.3
APIMANS += rc_dict_getval.3
APIMANS += rc_dict_getvend.3
APIMANS += rc_fgetln.3
APIMANS += rc_find_server.3
APIMANS += rc_free_env.3
APIMANS += rc_getctime.3
APIMANS += rc_getifname.3
APIMANS += rc_get_ipaddr.3
APIMANS += rc_getport.3
APIMANS += rc_get_srcaddr.3
APIMANS += rc_getstr.3
APIMANS += rc_good_ipaddr.3
APIMANS += rc_import_env.3
APIMANS += rc_ip_hostname.3
APIMANS += rc_log.3
APIMANS += rc_map2id.3
APIMANS += rc_map2id_free.3
APIMANS += rc_md5_calc.3
APIMANS += rc_mdelay.3
APIMANS += rc_mksid.3
APIMANS += rc_new.3
APIMANS += rc_openlog.3
APIMANS += rc_own_bind_ipaddress.3
APIMANS += rc_own_hostname.3
APIMANS += rc_own_ipaddress.3
APIMANS += rc_read_config.3
APIMANS += rc_read_dictionary.3
APIMANS += rc_read_mapfile.3
APIMANS += rc_send_server.3
APIMANS += rc_str2tm.3

$(APIMANS): stamp_mans

dist_man_MANS = $(APIMANS)

compare-makefile:
	@echo "******************************************************************************"
	@echo "If the following step fails copy $(srcdir)/doc/manpages/tmp-compare-makefile to doc/manpages/Makefile.am"
	@echo "******************************************************************************"
	@FUNCS=`cat $(top_srcdir)/include/freeradius-client.h | $(top_srcdir)/doc/manpages/getfuncs|sort -d`; \
	MANS=""; \
	for i in $$FUNCS; do \
		MANS="$$MANS\nAPIMANS += $$i.3"; \
	done; \
	grep -v -e '^APIMANS += ' Makefile.am | \
		perl -p -e "s/^APIMANS =/APIMANS =$$MANS/" > tmp-$@
	diff -u $(srcdir)/Makefile.am tmp-$@ >/dev/null 2>&1
	rm -f tmp-$@

.PHONY: compare-makefile
