/*
 * $Id: util.c,v 1.10 2010/02/04 10:31:41 aland Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * Copyright 1992 Livingston Enterprises, Inc.
 *
 * Copyright 1992,1993, 1994,1995 The Regents of the University of Michigan
 * and Merit Network, Inc. All Rights Reserved
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <sys/time.h>

#include <config.h>
#include <includes.h>
#include <radcli.h>
#include "util.h"

#define	RC_BUFSIZ	1024


static char const * months[] =
		{
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
		};

/** Turns printable string into correct tm struct entries
 *
 * @param valstr the printable date in 'day month year' format.
 * @param tm the output struct.
 */
void rc_str2tm (char const *valstr, struct tm *tm)
{
	int             i;

	/* Get the month */
	for (i = 0; i < 12; i++)
	{
		if (strncmp (months[i], valstr, 3) == 0)
		{
			tm->tm_mon = i;
			i = 13;
		}
	}

	/* Get the Day */
	tm->tm_mday = atoi (&valstr[4]);

	/* Now the year */
	tm->tm_year = atoi (&valstr[7]) - 1900;
}

void rc_mdelay(int msecs)
{
	struct timeval tv;

	tv.tv_sec = (int) msecs / 1000;
	tv.tv_usec = (msecs % 1000) * 1000;

	select(0, NULL, NULL, NULL, &tv);
}

/** Initialises new Radius Client handle
 *
 * @return a new rc_handle (free with rc_destroy).
 */
rc_handle *rc_new(void)
{
	rc_handle *rh;

	rh = calloc(1, sizeof(*rh));
	if (rh == NULL) {
                rc_log(LOG_CRIT, "rc_new: out of memory");
                return NULL;
        }
	return rh;
}

/** Destroys Radius Client handle reclaiming all memory
 *
 * @param rh The Radius client handle to free.
 */
void rc_destroy(rc_handle *rh)
{
	rc_map2id_free(rh);
	rc_dict_free(rh);
	rc_config_free(rh);
	free(rh);
}

/** Returns the current time as a double.
 *
 * @return current time (seconds since epoch) expressed as
 * 	double-precision floating point number.
 */
double rc_getctime(void)
{
    struct timeval timev;

    if (gettimeofday(&timev, NULL) == -1)
        return -1;

    return timev.tv_sec + ((double)timev.tv_usec) / 1000000.0;
}

/*
 * Copyright (c) 1998 Todd C. Miller <Todd.Miller@courtesan.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Copyright 2006  The FreeRADIUS server project
 */

#ifndef HAVE_STRLCPY

/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t
rc_strlcpy(char *dst, char const *src, size_t siz)
{
    char *d = dst;
    char const *s = src;
    size_t n = siz;

    /* Copy as many bytes as will fit */
    if (n != 0 && --n != 0) {
        do {
            if ((*d++ = *s++) == 0)
                break;
        } while (--n != 0);
    }

    /* Not enough room in dst, add NUL and traverse rest of src */
    if (n == 0) {
        if (siz != 0)
            *d = '\0';      /* NUL-terminate dst */
        while (*s++)
            ;
    }

    return(s - src - 1);    /* count does not include NUL */
}

#endif

