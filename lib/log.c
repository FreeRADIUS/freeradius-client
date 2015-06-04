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
#include <radcli.h>

/** Opens system log
 *
 * @param ident the name of the program.
 */
void rc_openlog(char const *ident)
{
#ifndef _MSC_VER /* TODO: Fix me */
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
#endif
}

/** Logs information on system log
 *
 * @param prio the syslog priority.
 * @param format the format of the data to print.
 */
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
