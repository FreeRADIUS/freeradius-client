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
 * $Id: radiusclient.c,v 1.8 2010/02/04 10:30:26 aland Exp $
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <freeradius-client.h>

#define BUF_LEN 4096

int process(void *, VALUE_PAIR *, int, int);

static void
usage(void)
{

    fprintf(stderr, "usage: radiusclient [-f config_file] [-p nas_port] [-s | [-a] [-e hex-bytes] a1=v1 [a2=v2[...[aN=vN]...]]]\n");
    fprintf(stderr, "       -e hex-bytes - Specify an EAP message with colon-separated hex bytes. Ex. -e 2:0:0:9:1:74:65:73:74\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    int i, nas_port, ch, acct, server, ecount, firstline, theend;
    void *rh;
    size_t len;
    VALUE_PAIR *send, **vp;
    char *rc_conf, *cp;
    char lbuf[4096];
    size_t  eap_len = 0;
    uint8_t eap_msg[255];

    rc_conf = RC_CONFIG_FILE;
    nas_port = 5060;

    acct = 0;
    server = 0;
    while ((ch = getopt(argc, argv, "af:p:se:")) != -1) {
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

        case 'e':
            if (optarg && *optarg != '\0') {
                char   *next = optarg;
                while (*next != '\0') {
                    char    *endptr;
                    long int l = strtol(next, &endptr, 16);
                    if (l > 0xFF) {
                        fprintf(stderr, "-e: hex-bytes invalid. %X greater than 0xFF\n", (unsigned int)l);
                        exit(3);
                    }
                    eap_msg[eap_len++] = (uint8_t)l;
                    if (*endptr == '\0')
                        break;
                    next = endptr + 1;
                }
            } else {
                fprintf(stderr, "-e: can't parse hex-bytes buffer\n");
                exit(3);
            }
            break;
        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if ((argc == 0 && server == 0) || (argc != 0 && server != 0))
        usage();

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
        vp = &send;
        for (i = 0; i < argc; i++) {
            if (rc_avpair_parse(rh, argv[i], vp) < 0) {
                fprintf(stderr, "%s: can't parse AV pair\n", argv[i]);
                exit(3);
            }
            vp = &send->next;
        }
        if (eap_len > 0) {

            if (rc_avpair_add(rh, vp, PW_EAP_MESSAGE, eap_msg, eap_len, 0) == NULL) {
                fprintf(stderr, "Can't add EAP-Message AV pair\n");
                exit(3);
            }
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
                    if (rc_avpair_parse(rh, lbuf, vp) < 0) {
                        fprintf(stderr, "%s: can't parse AV pair\n", lbuf);
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

int
process(void *rh, VALUE_PAIR *send, int acct, int nas_port)
{
    VALUE_PAIR *received = NULL;
    char msg[PW_MAX_MSG_SIZE];
    char buf[BUF_LEN];
    int i;

    received = NULL;
    if (acct == 0) {
        i = rc_auth(rh, nas_port, send, &received, msg);
        if (received != NULL) {
            printf("%s", rc_avpair_log(rh, received, buf, BUF_LEN));
            rc_avpair_free(received);
        }
    } else {
        i = rc_acct(rh, nas_port, send);
    }

    return (i == OK_RC) || (i == CHALLENGE_RC) ? 0 : 1;
}
