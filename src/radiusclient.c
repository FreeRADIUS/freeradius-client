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
 * $Id: radiusclient.c,v 1.1 2004/10/04 10:15:20 sobomax Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <radiusclient.h>

static void
usage(void)
{

    fprintf(stderr, "usage: radiusclient [-a] [-f config_file] [-p nas_port] a1=v1 [a2=v2[...[aN=vN]...]]\n");
    exit(1);
}

int
main(int argc, char **argv)
{
    int i, nas_port, ch, acct;
    void *rh;
    VALUE_PAIR *received, *send, **vp;
    char msg[4096];
    char *rc_conf;

    rc_conf = RC_CONFIG_FILE;
    nas_port = 5060;

    acct = 0;
    while ((ch = getopt(argc, argv, "af:p:")) != -1) {
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

        default:
            usage();
        }
    }
    argc -= optind;
    argv += optind;

    if (argc == 0)
        usage();

    if ((rh = rc_read_config(rc_conf)) == NULL) {
        fprintf(stderr, "error opening radius configuration file");
        exit(1);
    }

    if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0) {
        fprintf(stderr, "error reading radius dictionary");
        exit(2);
    }

    send = NULL;
    vp = &send;
    for (i = 0; i < argc; i++) {
        if (rc_avpair_parse(rh, argv[i], vp) < 0) {
            fprintf(stderr, "%s: can't parse AV pair", argv[i]);
            exit(3);
        }
        vp = &send->next;
    }

    received = NULL;
    if (acct == 0) {
        i = rc_auth(rh, nas_port, send, &received, msg);
        if (received != NULL)
            printf("%s", rc_avpair_log(rh, received));
    } else {
        i = rc_acct(rh, nas_port, send);
    }

    exit((i == OK_RC) ? 0 : 4);
}
