/*
 * util.h        Utility structures and prototypes.
 *
 * License:	BSD
 *
 */

#ifndef UTIL_H
# define UTIL_H

#include <string.h>

#ifndef HAVE_STRLCPY
size_t rc_strlcpy(char *dst, char const *src, size_t siz);
# define strlcpy rc_strlcpy
#endif

#include <includes.h>

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))

#define SS_LEN(sa) \
  (((sa)->ss_family == AF_INET) ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif

#define SA_GET_INADDR(sa) \
  (((sa)->sa_family == AF_INET) ? \
    ((void*)&(((struct sockaddr_in*)(sa))->sin_addr)) : ((void*)&(((struct sockaddr_in6*)(sa))->sin6_addr)))

#define SA_GET_INLEN(sa) \
  ((sa)->sa_family == AF_INET) ? \
    sizeof(struct in_addr) : sizeof(struct in6_addr)

int rc_find_server_addr(rc_handle const *, char const *, struct addrinfo **, char *, unsigned flags);

/* flags to rc_getaddrinfo() */
#define PW_AI_PASSIVE		1
#define PW_AI_AUTH		(1<<1)
#define PW_AI_ACCT		(1<<2)

struct addrinfo *rc_getaddrinfo (char const *host, unsigned flags);
void rc_own_bind_addr(rc_handle *rh, struct sockaddr_storage *lia);

#endif /* UTIL_H */

