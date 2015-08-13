/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>

unsigned int radcli_debug = 0;

void rc_setdebug(int debug)
{
  radcli_debug = debug;
}

/**
 * @defgroup misc-api Miscellaneous API
 * @brief Miscellaneous functions
 *
 * @{
 */

/** Opens system log
 *
 * This function is a wrapper over openlog() in
 * systems which support it. Don't call it if you already
 * call openlog().
 *
 * @param ident the name of the program.
 */
void rc_openlog(char const *ident)
{
#ifndef _MSC_VER /* TODO: Fix me */
	openlog(ident, LOG_PID, RC_LOG_FACILITY);
#endif
}

/** @} */
