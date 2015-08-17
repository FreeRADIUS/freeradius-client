/*
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

#include <radcli/radcli.h>

#define GETSTR_LENGTH		128	//!< must be bigger than AUTH_PASS_LEN.

typedef struct pw_auth_hdr
{
	uint8_t		code;
	uint8_t		id;
	uint16_t	length;
	uint8_t		vector[AUTH_VECTOR_LEN];
	uint8_t		data[2];
}
#ifdef __GNUC__
__attribute__((packed))
#endif
AUTH_HDR;

typedef struct rc_sockets_override {
	void *ptr;
	const char *static_secret;
	int (*get_fd)(void *ptr, struct sockaddr* our_sockaddr);
	void (*close_fd)(int fd);
	ssize_t (*sendto)(void *ptr, int sockfd, const void *buf, size_t len, int flags,
	                  const struct sockaddr *dest_addr, socklen_t addrlen);
	ssize_t (*recvfrom)(void *ptr, int sockfd, void *buf, size_t len, int flags,
	                    struct sockaddr *src_addr, socklen_t *addrlen);
	int (*lock)(void *ptr);
	int (*unlock)(void *ptr);
} rc_sockets_override;

struct rc_conf
{
	struct _option		*config_options;
	struct sockaddr_storage	own_bind_addr;
	unsigned		own_bind_addr_set;

	 /* we keep a copy of the filename to avoid re-reading a dictionary,
	  * for applications relying on the old API which required explicit
	  * load of it. */
	char			*first_dict_read;
	struct dict_attr	*dictionary_attributes;
	struct dict_value	*dictionary_values;
	struct dict_vendor	*dictionary_vendors;

	rc_sockets_override	so;
	unsigned		so_type; /* rc_socket_type */
};

/* older compilers don't like seeing this typedef along with the one in radcli.h */
struct rc_aaa_ctx_st
{
	char	secret[MAX_SECRET_LENGTH + 1]; //!< The secret used for this request
	uint8_t	request_vector[AUTH_VECTOR_LEN]; //< The auth vector used in this request
};

int rc_send_server_ctx (rc_handle *rh, RC_AAA_CTX **ctx, SEND_DATA *data,
                        char *msg, rc_type type);

#endif
