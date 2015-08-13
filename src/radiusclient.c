/*
 * Copyright (c) 2004 Maxim Sobolev <sobomax@FreeBSD.org>
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
#include <syslog.h>
#include	"common.h"

#include <radcli/radcli.h>

#define BUF_LEN 4096

int process(void *, VALUE_PAIR *, int, int, int);

static void
usage(void)
{

    fprintf(stderr, "usage: radiusclient [-D] [-f config_file] [-p nas_port] [-i] [-s | [-a] a1=v1 [a2=v2[...[aN=vN]...]]]\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    int i, nas_port, ch, acct, server, ecount, firstline, theend;
    void *rh;
    size_t len;
    VALUE_PAIR *send;
    char *rc_conf, *cp;
    char lbuf[4096];
    int info = 0;
    int debug = 0;

    rc_conf = RC_CONFIG_FILE;
    nas_port = 5060;

    acct = 0;
    server = 0;
    while ((ch = getopt(argc, argv, "Daf:p:si")) != -1) {
        switch (ch) {
        case 'D':
          debug = 1;
          break;
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

        case 'i':
            info = 1;
            break;

        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if ((argc == 0 && server == 0) || (argc != 0 && server != 0))
        usage();

    if(debug) {
      rc_setdebug(1);
      openlog("radiusclient", LOG_PERROR|LOG_NDELAY, LOG_LOCAL7);
    } else {
      openlog("radiusclient", LOG_NDELAY, LOG_AUTH);
    }

    if ((rh = rc_read_config(rc_conf)) == NULL) {
        fprintf(stderr, "error opening radius configuration file\n");
        exit(1);
    }

    if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
        fprintf(stderr, "error reading radius dictionary\n");
        exit(2);
    }

    if (server == 0) {
        send = NULL;
        for (i = 0; i < argc; i++) {
            if (rc_avpair_parse(rh, argv[i], &send) < 0) {
                fprintf(stderr, "%s: can't parse AV pair\n", argv[i]);
                exit(3);
            }
        }
        exit(process(rh, send, acct, nas_port, info));
    }
    while (1 == 1) {
        send = NULL;
        ecount = 0;
        firstline = 1;
        acct = 0;
        do {
            len = 0;
            cp = rc_fgetln(stdin, &len);
            theend = 1;
            if (cp != NULL && len > 0) {
                if (firstline != 0) {
                    if (len >= 4 && memcmp(cp, "ACCT", 4) == 0)
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
                    if (rc_avpair_parse(rh, lbuf, &send) < 0) {
                        fprintf(stderr, "%s: can't parse AV pair\n", lbuf);
                        ecount++;
                    }
                }
            }
        } while (theend == 0);
        if (send != NULL && ecount == 0)
            printf("%d\n\n", process(rh, send, acct, nas_port, info));
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

int
process(void *rh, VALUE_PAIR *send, int acct, int nas_port, int send_info)
{
    VALUE_PAIR *received = NULL;
    char buf[BUF_LEN];
    RC_AAA_CTX *ctx = NULL;
    const unsigned char *p;
    int i, j;

    received = NULL;
    if (acct == 0) {
        i = rc_aaa_ctx(rh, &ctx, nas_port, send, &received, NULL, 1, PW_ACCESS_REQUEST);
        if (received != NULL) {
            printf("%s", rc_avpair_log(rh, received, buf, BUF_LEN));
            rc_avpair_free(received);
        }
        if (ctx) {
	    if (send_info) {
		    printf("Request-Info-Secret = %s\n", rc_aaa_ctx_get_secret(ctx));
		    printf("Request-Info-Vector = ");
		    p = rc_aaa_ctx_get_vector(ctx);
		    for (j=0;j<AUTH_VECTOR_LEN;j++) {
		    	printf("%.2x", (unsigned)p[j]);
		    }
		    printf("\n");
	    }
	    rc_aaa_ctx_free(ctx);
        }
    } else {
        i = rc_acct(rh, nas_port, send);
    }

    return (i == OK_RC) ? 0 : 1;
}
