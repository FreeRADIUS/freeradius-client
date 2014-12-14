/*
 * $Id: util.c,v 1.10 2010/02/04 10:31:41 aland Exp $
 *
 * Copyright (c) 1998 The NetBSD Foundation, Inc.
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
#include <freeradius-client.h>
#include "util.h"

#define	RC_BUFSIZ	1024

/*
 * Function: rc_str2tm
 *
 * Purpose: Turns printable string into correct tm struct entries.
 *
 */

static char const * months[] =
		{
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
		};

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

/*
 * Function: rc_getifname
 *
 * Purpose: get the network interface name associated with this tty
 *
 */

char *rc_getifname(rc_handle *rh, char const *tty)
{
#if defined(BSD4_4) || defined(linux)
	int		fd;

	if ((fd = open(tty, O_RDWR|O_NDELAY)) < 0) {
		rc_log(LOG_ERR, "rc_getifname: can't open %s: %s", tty, strerror(errno));
		return NULL;
	}
#endif

#ifdef BSD4_4
	strcpy(rh->ifname,ttyname(fd));
	if (strlen(rh->ifname) < 1) {
		rc_log(LOG_ERR, "rc_getifname: can't get attached interface of %s: %s", tty, strerror(errno));
		close(fd);
		return NULL;
	}
#elif linux
	if (ioctl(fd, SIOCGIFNAME, rh->ifname) < 0) {
		rc_log(LOG_ERR, "rc_getifname: can't ioctl %s: %s", tty, strerror(errno));
		close(fd);
		return NULL;
	}
#else
	return NULL;
#endif

#if defined(BSD4_4) || defined(linux)
	close(fd);
	return rh->ifname;
#endif
}

/*
 * Function: rc_getstr
 *
 * Purpose: Reads in a string from the user (with or witout echo)
 *
 */
#ifndef _MSC_VER
char *rc_getstr (rc_handle *rh, char const *prompt, int do_echo)
{
	int             in, out;
	char           *p;
	struct termios  term_old, term_new;
	int		is_term, flags, old_flags;
	char		c;
	int		flushed = 0;
	sigset_t        newset;
	sigset_t        oldset;

	in = fileno(stdin);
	out = fileno(stdout);

	(void) sigemptyset (&newset);
	(void) sigaddset (&newset, SIGINT);
	(void) sigaddset (&newset, SIGTSTP);
	(void) sigaddset (&newset, SIGQUIT);

	(void) sigprocmask (SIG_BLOCK, &newset, &oldset);

	if ((is_term = isatty(in)))
	{

		(void) tcgetattr (in, &term_old);
		term_new = term_old;
		if (do_echo)
			term_new.c_lflag |= ECHO;
		else
			term_new.c_lflag &= ~ECHO;

		if (tcsetattr (in, TCSAFLUSH, &term_new) == 0)
			flushed = 1;

	}
	else
	{
		is_term = 0;
		if ((flags = fcntl(in, F_GETFL, 0)) >= 0) {
			old_flags = flags;
			flags |= O_NONBLOCK;

			fcntl(in, F_SETFL, flags);

			while (read(in, &c, 1) > 0)
				/* nothing */;

			fcntl(in, F_SETFL, old_flags);

			flushed = 1;
		}
	}

	(void)write(out, prompt, strlen(prompt));

	/* well, this looks ugly, but it handles the following end of line
	   markers: \r \r\0 \r\n \n \n\r, at least at a second pass */

	p = rh->buf;
	for (;;)
	{
		if (read(in, &c, 1) <= 0)
			return NULL;

		if (!flushed && ((c == '\0') || (c == '\r') || (c == '\n'))) {
			flushed = 1;
			continue;
		}

		if ((c == '\r') || (c == '\n'))
			break;

		flushed = 1;

		if (p < rh->buf + GETSTR_LENGTH)
		{
			if (do_echo && !is_term)
				(void)write(out, &c, 1);
			*p++ = c;
		}
	}

	*p = '\0';

	if (!do_echo || !is_term) (void)write(out, "\r\n", 2);

	if (is_term)
		tcsetattr (in, TCSAFLUSH, &term_old);
	else {
		if ((flags = fcntl(in, F_GETFL, 0)) >= 0) {
			old_flags = flags;
			flags |= O_NONBLOCK;

			fcntl(in, F_SETFL, flags);

			while (read(in, &c, 1) > 0)
				/* nothing */;

			fcntl(in, F_SETFL, old_flags);
		}
	}

	(void) sigprocmask (SIG_SETMASK, &oldset, NULL);

	return rh->buf;
}
#endif
void rc_mdelay(int msecs)
{
	struct timeval tv;

	tv.tv_sec = (int) msecs / 1000;
	tv.tv_usec = (msecs % 1000) * 1000;

	select(0, NULL, NULL, NULL, &tv);
}

/*
 * Function: rc_mksid
 *
 * Purpose: generate a quite unique string
 *
 * Remarks: not that unique at all...
 *
 */

char *
rc_mksid (rc_handle *rh)
{
  snprintf (rh->buf1, sizeof(rh->buf1), "%08lX%04X", (unsigned long int) time (NULL), (unsigned int) getpid ());
  return rh->buf1;
}

/*
 * Function: rc_new
 *
 * Purpose: Initialises new Radius Client handle
 *
 */

rc_handle *
rc_new(void)
{
	rc_handle *rh;

	rh = malloc(sizeof(*rh));
	if (rh == NULL) {
                rc_log(LOG_CRIT, "rc_new: out of memory");
                return NULL;
        }
	memset(rh, 0, sizeof(*rh));
	return rh;
}

/*
 * Function: rc_destroy
 *
 * Purpose: Destroys Radius Client handle reclaiming all memory
 *
 */

void
rc_destroy(rc_handle *rh)
{

	rc_map2id_free(rh);
	rc_dict_free(rh);
	rc_config_free(rh);
	if (rh->this_host_bind_ipaddr != NULL)
		free(rh->this_host_bind_ipaddr);
	free(rh);
}

/*
 * Function: rc_fgetln
 *
 * Purpose: Get next line from the stream.
 *
 */

char *
rc_fgetln(FILE *fp, size_t *len)
{
	static char *buf = NULL;
	static size_t bufsiz = 0;
	char *ptr;

	if (buf == NULL) {
		bufsiz = RC_BUFSIZ;
		if ((buf = malloc(bufsiz)) == NULL)
			return NULL;
	}

	if (fgets(buf, (int)bufsiz, fp) == NULL)
		return NULL;
	*len = 0;

	while ((ptr = strchr(&buf[*len], '\n')) == NULL) {
		size_t nbufsiz = bufsiz + RC_BUFSIZ;
		char *nbuf = realloc(buf, nbufsiz);

		if (nbuf == NULL) {
			int oerrno = errno;
			free(buf);
			errno = oerrno;
			buf = NULL;
			return NULL;
		} else
			buf = nbuf;

		*len = bufsiz;
		if (fgets(&buf[bufsiz], RC_BUFSIZ, fp) == NULL)
			return buf;

		bufsiz = nbufsiz;
	}

	*len = (ptr - buf) + 1;
	return buf;
}

/*
 * Function: rc_getctime
 *
 * Purpose: Get current time (seconds since epoch) expressed as
 * double-precision floating point number.
 *
 */

double
rc_getctime(void)
{
    struct timeval timev;

    if (gettimeofday(&timev, NULL) == -1)
        return -1;

    return timev.tv_sec + ((double)timev.tv_usec) / 1000000.0;
}

#ifndef HAVE_STRLCAT
/* 
 * Replacement for a missing strlcat.
 *
 * Provides the same functionality as the *BSD function strlcat, originally
 * developed by Todd Miller and Theo de Raadt.  strlcat works similarly to
 * strncat, except simpler.  The result is always nul-terminated even if the
 * source string is longer than the space remaining in the destination string,
 * and the total space required is returned.  The third argument is the total
 * space available in the destination buffer, not just the amount of space
 * remaining.
 *
 * The canonical version of this file is maintained in the rra-c-util package,
 * which can be found at <http://www.eyrie.org/~eagle/software/rra-c-util/>.
 *
 * Written by Russ Allbery <eagle@eyrie.org>
 *
 * The authors hereby relinquish any claim to any copyright that they may have
 * in this work, whether granted under contract or by operation of law or
 * international treaty, and hereby commit to the public, at large, that they
 * shall not, at any time in the future, seek to enforce any copyright in this
 * work against any person or entity, or prevent any person or entity from
 * copying, publishing, distributing or creating derivative works of this
 * work.
 */

size_t
rc_strlcat(char *dst, const char *src, size_t size)
{
    size_t used, length, copy;

    used = strlen(dst);
    length = strlen(src);
    if (size > 0 && used < size - 1) {
        copy = (length >= size - used) ? size - used - 1 : length;
        memcpy(dst + used, src, copy);
        dst[used + copy] = '\0';
    }
    return used + length;
}
#endif

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

