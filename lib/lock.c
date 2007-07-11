/*
 * $Id: lock.c,v 1.4 2007/07/11 16:37:35 cparker Exp $
 *
 * Copyright (C) 1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include "config.h"
#include "includes.h"

#if defined(HAVE_FLOCK)

int do_lock_exclusive(FILE * fd)
{
	return flock(fileno(fd), LOCK_EX|LOCK_NB);
}

int do_unlock(FILE * fd)
{
	return flock(fileno(fd), LOCK_UN);
}

#elif defined(WIN32)

int do_lock_exclusive(FILE * fd)
{
	_lock_file(fd);
	return 1;
}

int do_unlock(FILE * fd)
{
	_unlock_file(fd);
	return 1;
}

#elif defined(HAVE_FCNTL)

int do_lock_exclusive(FILE * fd)
{
	flock_t fl;
	int res;

	memset((void *)&fl, 0, sizeof(fl));

	fl.l_type = F_WRLCK;
	fl.l_whence = fl.l_start = 0;
	fl.l_len = 0; /* 0 means "to end of file" */

	res = fcntl(fileno(fd), F_SETLK, &fl);

	if ((res == -1) && (errno == EAGAIN))
		errno = EWOULDBLOCK;

	return res;
}

int do_unlock(FILE * fd)
{
	flock_t fl;

	memset((void *)&fl, 0, sizeof(fl));

	fl.l_type = F_UNLCK;
	fl.l_whence = fl.l_start = 0;
	fl.l_len = 0; /* 0 means "to end of file" */

	return fcntl(fileno(fd), F_SETLK, &fl);
}

#else
#error YOU_LOSE "need either flock(2) or fcntl(2)"
#endif

