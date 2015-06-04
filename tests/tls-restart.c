/*
 * Copyright (c) 2004 Maxim Sobolev <sobomax@FreeBSD.org>
 * Copyright (c) 2015 Nikos Mavrogiannopoulos <nmav@redhat.com>
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <radcli.h>

#define BUF_LEN 4096

int process(void *, VALUE_PAIR *, int, int);

int main(int argc, char **argv)
{
	int i, nas_port, ch, acct, server, ecount, firstline, theend;
	void *rh;
	size_t len;
	VALUE_PAIR *send, **vp;
	char *rc_conf, *cp;
	char lbuf[4096];

	rc_conf = "";
	nas_port = 5060;

	acct = 0;
	server = 0;
	while ((ch = getopt(argc, argv, "af:p:s")) != -1) {
		switch (ch) {
		case 'f':
			rc_conf = optarg;
			break;

		case 'p':
			nas_port = atoi(optarg);
			break;

		case 'a':
			acct = 1;
			break;

		case 's':
			server = 1;
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if ((argc == 0 && server == 0) || (argc != 0 && server != 0))
		exit(1);

	if ((rh = rc_read_config(rc_conf)) == NULL) {
		fprintf(stderr, "tls-restart: error opening radius configuration file\n");
		exit(1);
	}

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
		fprintf(stderr, "tls-restart: error reading radius dictionary\n");
		exit(2);
	}

	if (server == 0) {
		send = NULL;
		vp = &send;
		for (i = 0; i < argc; i++) {
			if (rc_avpair_parse(rh, argv[i], vp) < 0) {
				fprintf(stderr, "%s: can't parse AV pair\n",
					argv[i]);
				exit(3);
			}
			vp = &send->next;
		}
		exit(process(rh, send, acct, nas_port));
	}
	while (1 == 1) {
		send = NULL;
		vp = &send;
		ecount = 0;
		firstline = 1;
		acct = 0;
		do {
			len = 0;
			cp = rc_fgetln(stdin, &len);
			theend = 1;
			if (cp != NULL && len > 0) {
				if (firstline != 0) {
					if (len >= 4
					    && memcmp(cp, "ACCT", 4) == 0)
						acct = 1;
					firstline = 0;
					theend = 0;
					continue;
				}
				for (i = 0; i < len; i++) {
					if (!isspace(cp[i])) {
						theend = 0;
						break;
					}
				}
				if (theend == 0) {
					memcpy(lbuf, cp, len);
					lbuf[len] = '\0';
					if (rc_avpair_parse(rh, lbuf, vp) < 0) {
						fprintf(stderr,
							"%s: can't parse AV pair\n",
							lbuf);
						ecount++;
					} else {
						vp = &send->next;
					}
				}
			}
		} while (theend == 0);

		if (send != NULL && ecount == 0)
			printf("%d\n\n", process(rh, send, acct, nas_port));
		else
			printf("%d\n\n", -1);
		fflush(stdout);
		if (send != NULL)
			rc_avpair_free(send);
		if (cp == NULL || len == 0)
			break;
	}
	exit(0);
}

int process(void *rh, VALUE_PAIR * send, int acct, int nas_port)
{
	VALUE_PAIR *received;
	char msg[PW_MAX_MSG_SIZE];
	char buf[BUF_LEN];
	int i, fd;

	fd = rc_tls_fd(rh);
	if (fd >= 0) {
		dup(fd);
		close(fd);
	}

	received = NULL;
	if (acct == 0) {
		i = rc_auth(rh, nas_port, send, &received, msg);
		if (i != OK_RC) {
			fprintf(stderr, "tls-restart: error sending 1 (ok)\n");
		}

		i = rc_auth(rh, nas_port, send, &received, msg);
		if (i != OK_RC) {
			fprintf(stderr, "tls-restart: error sending 2\n");
			exit(2);
		}
		if (received != NULL) {
			printf("%s", rc_avpair_log(rh, received, buf, BUF_LEN));
			rc_avpair_free(received);
		}
	} else {
		i = rc_acct(rh, nas_port, send);
	}

	return (i == OK_RC) ? 0 : 1;
}
