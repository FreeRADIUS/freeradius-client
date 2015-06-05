/*
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

#define	RC_BUFSIZ	1024

/** Reads in a string from the user (with or witout echo)
 *
 * @param rh a handle to parsed configuration.
 * @param prompt the prompt to print.
 * @param do_echo whether to echo characters.
 * @return the data user typed or NULL.
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

/** Get next line from the stream.
 *
 * @param fp a %FILE pointer.
 * @param len output length.
 * @return the next line in an allocated buffer.
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
