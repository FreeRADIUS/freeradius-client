/*
 * Copyright (c) 2015, Nikos Mavrogiannopoulos.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#include <radcli/radcli.h>

int main(int argc, char **argv)
{
	VALUE_PAIR **vp = NULL;
	VALUE_PAIR *vp2, *send = NULL;
	rc_handle *rh;
	int checks;
	int ret, prev;

	if ((rh = rc_read_config("radiusclient.conf")) == NULL) {
		fprintf(stderr, "%s: error opening radius configuration file\n", argv[0]);
		exit(1);
	}

	vp = &send;
	/* insert values */
	ret = rc_avpair_parse(rh, "User-Name=test", vp);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	ret = rc_avpair_parse(rh, "Idle-Timeout=1821", vp);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	ret = rc_avpair_parse(rh, "Framed-IP-Address=192.168.1.1", vp);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	ret = rc_avpair_parse(rh, "Framed-IPv6-Address=::1", vp);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	ret = rc_avpair_parse(rh, "Route-IPv6-Information=fc64:5f83:803:e88a:4d74:5f71:16fd:0/112", vp);
	if (ret < 0) {
		fprintf(stderr, "error in %d\n", __LINE__);
		exit(1);
	}

	/* check if values match using the structs directly */
	vp2 = send;
	checks = 0;
	prev = -1;
	while(vp2 != NULL) {
		if (vp2->attribute == PW_USER_NAME && (memcmp(vp2->strvalue, "test", 4) != 0 || vp2->type != PW_TYPE_STRING)) {
			fprintf(stderr, "%d: error checking username: %s/%d\n", __LINE__, vp2->strvalue, vp2->lvalue);
			exit(1);
		} else if (vp2->attribute == PW_IDLE_TIMEOUT && (vp2->lvalue != 1821 || vp2->type != PW_TYPE_INTEGER)) {
			fprintf(stderr, "%d: error checking Idle-Timeout: %d\n", __LINE__, vp2->lvalue);
			exit(1);
		} else if (vp2->attribute == PW_FRAMED_IP_ADDRESS && (vp2->lvalue != 3232235777 || vp2->type != PW_TYPE_IPADDR)) {
			fprintf(stderr, "%d: error checking Framed-IP-Address: %u\n", __LINE__, vp2->lvalue);
			exit(1);
		} else if (vp2->attribute == PW_FRAMED_IPV6_ADDRESS && 
			   (memcmp(vp2->strvalue, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) != 0 ||
			    vp2->type != PW_TYPE_IPV6ADDR)) {
			fprintf(stderr, "%d: error checking Framed-IPv6-Address\n", __LINE__);
			exit(1);
		} else if (vp2->attribute == PW_ROUTE_IPV6_INFORMATION &&
			   (memcmp(vp2->strvalue+2, "\xfc\x64\x5f\x83\x08\x03\xe8\x8a\x4d\x74\x5f\x71\x16\xfd\x00\x00", 16) != 0 ||
			    vp2->strvalue[1] != 112 || vp2->type != PW_TYPE_IPV6PREFIX)) {
			fprintf(stderr, "%d: error checking Route-IPv6-Information: %d\n", __LINE__, vp2->strvalue[1]);
			exit(1);
		}

		if (prev != vp2->attribute) {
			checks++;
			prev = vp2->attribute;
		}
		vp2 = vp2->next;
	};

	if (checks != 5) {
		fprintf(stderr, "%s: error: not all attributes were found\n", __LINE__);
		exit(1);
	}

	/* check if values match using the new API */
	vp2 = send;
	checks = 0;
	prev = -1;
	while(vp2 != NULL) {
		unsigned type, id, len;
		uint32_t uint;
		char *p;
		struct in6_addr ip6;

		rc_avpair_get_attr(vp2, &type, &id);
		
		if (id == PW_USER_NAME) {
			if (rc_avpair_get_raw(vp2, &p, &len) != 0) {
				fprintf(stderr, "error in %d\n", __LINE__);
				exit(1);
			}
			
			if (len != 4 || strcmp(p, "test") != 0 || type != PW_TYPE_STRING) {
				fprintf(stderr, "%d: error checking username: %s/%d\n", __LINE__, vp2->strvalue, vp2->lvalue);
				exit(1);
			}
		} else if (id == PW_IDLE_TIMEOUT) {
			if (rc_avpair_get_uint32(vp2, &uint) != 0) {
				fprintf(stderr, "error in %d\n", __LINE__);
				exit(1);
			}
			if (uint != 1821 || type != PW_TYPE_INTEGER) {
				fprintf(stderr, "%d: error checking Idle-Timeout: %d\n", __LINE__, vp2->lvalue);
				exit(1);
			}
		} else if (id == PW_FRAMED_IP_ADDRESS) {
			if (rc_avpair_get_uint32(vp2, &uint) != 0) {
				fprintf(stderr, "error in %d\n", __LINE__);
				exit(1);
			}
			
			if (uint != 3232235777 || type != PW_TYPE_IPADDR) {
				fprintf(stderr, "%d: error checking Framed-IP-Address: %u\n", __LINE__, vp2->lvalue);
				exit(1);
			}
		} else if (id == PW_FRAMED_IPV6_ADDRESS) {
			if (rc_avpair_get_in6(vp2, &ip6, NULL) != 0) {
				fprintf(stderr, "error in %d\n", __LINE__);
				exit(1);
			}

			if (memcmp(&ip6, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01", 16) != 0 ||
			    type != PW_TYPE_IPV6ADDR) {
				fprintf(stderr, "%d: error checking Framed-IPv6-Address\n", __LINE__);
				exit(1);
			}
		} else if (id == PW_ROUTE_IPV6_INFORMATION) {
			if (rc_avpair_get_in6(vp2, &ip6, &len) != 0) {
				fprintf(stderr, "error in %d\n", __LINE__);
				exit(1);
			}

			if (memcmp(&ip6, "\xfc\x64\x5f\x83\x08\x03\xe8\x8a\x4d\x74\x5f\x71\x16\xfd\x00\x00", 16) != 0 ||
			    len != 112 || type != PW_TYPE_IPV6PREFIX) {
				fprintf(stderr, "%d: error checking Route-IPv6-Information: %d\n", __LINE__, vp2->strvalue[1]);
				exit(1);
			}
		}

		if (prev != id) {
			checks++;
			prev = id;
		}
		vp2 = rc_avpair_next(vp2);
	};

	if (checks != 5) {
		fprintf(stderr, "%s: error: not all attributes were found\n", __LINE__);
		exit(1);
	}
	rc_avpair_free(send);

	return 0;

}
