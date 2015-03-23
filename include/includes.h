/*
 * $Id: includes.h,v 1.6 2007/06/21 18:07:22 cparker Exp $
 *
 * Copyright (C) 1997 Lars Fenneberg
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

#ifndef RC_INCLUDES_H
# define RC_INCLUDES_H

#include "config.h"

/* AIX requires this to be the first thing in the file.  */
#ifndef __GNUC__
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
#   pragma alloca
#  else
#   ifndef alloca /* predefined by HP cc +Olibcalls */
     char *alloca ();
#   endif
#  endif
# endif
#endif

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <errno.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <string.h>
# include <stdarg.h>
#else
# include <stdarg.h>
# ifndef HAVE_STRCHR
#  define strchr index
#  define strrchr rindex
# endif
#endif

/* I realize that this is ugly and unsafe.. :( */
#ifndef HAVE_SNPRINTF
# define snprintf(buf, len, format, ...) sprintf(buf, format, __VA_ARGS__)
#endif
#ifndef HAVE_VSNPRINTF
# define vsnprintf(buf, len, format, ap) vsprintf(buf, format, ap)
#endif

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif

#ifdef HAVE_SYS_FCNTL_H
# include <sys/fcntl.h>
#endif

#ifdef HAVE_SYS_FILE_H
# include <sys/file.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#ifdef HAVE_LIMITS_H
# include <limits.h>
#endif

#ifdef HAVE_TERMIOS_H
# include <termios.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX        1024
#endif

#ifndef UCHAR_MAX
# ifdef  __STDC__
#  define UCHAR_MAX       255U
# else
#  define UCHAR_MAX       255
# endif
#endif

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if defined(HAVE_SIGNAL_H)
# include <signal.h>
#endif
#if defined(HAVE_SYS_SIGNAL_H)
# include <sys/signal.h>
#endif

#ifdef NEED_SIG_PROTOTYPES
int sigemptyset(sigset_t *);
int sigaddset(sigset_t *, int);
int sigprocmask (int, sigset_t *, sigset_t *);
#endif

#if HAVE_GETOPT_H
# include <getopt.h>
#endif

#if defined(HAVE_SHADOW_H) && defined(HAVE_SHADOW_PASSWORDS)
# include <shadow.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/*
 * prefer srandom/random over srand/rand as there generator has a
 * better distribution of the numbers on certain systems.
 * on Linux both generators are identical.
 */
#ifndef HAVE_RANDOM
# ifdef HAVE_RAND
# define srandom        srand
# define random         rand
# endif
#endif

/* rlib/lock.c */
int do_lock_exclusive(FILE *);
int do_unlock(FILE *);

#endif
