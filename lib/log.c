/*
 * $Id: log.c,v 1.5 2007/06/21 18:07:23 cparker Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>

/**
 * rc_openlog:
 * @ident: the name of the program
 *
 * Opens system log.
 *
 **/

void rc_openlog(char const *ident)
{
#ifndef _MSC_VER /* TODO: Fix me */
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
#endif
}

/**
 * rc_log:
 * @prio: the syslog priority
 * @format: the format of the data to print
 *
 * Logs information on system log.
 *
 **/

void rc_log(int prio, char const *format, ...)
{
	char buff[1024];
	va_list ap;

	va_start(ap,format);
	vsnprintf(buff, sizeof(buff), format, ap);
	va_end(ap);

#ifndef _MSC_VER /* TODO: Fix me */
	syslog(prio, "%s", buff);
#endif
}
