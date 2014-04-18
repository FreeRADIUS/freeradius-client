/*
 * $Id: ip_util.c,v 1.14 2010/03/17 18:57:01 aland Exp $
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

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>

#define HOSTBUF_SIZE 1024

#if !defined(SA_LEN)
#define SA_LEN(sa) \
  (((sa)->sa_family == AF_INET) ? \
    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6))
#endif


static __thread size_t	hostbuflen=HOSTBUF_SIZE;
static __thread	char	*tmphostbuf=NULL;

/*
 * Function: rc_gethostbyname
 *
 * Purpose: threadsafe replacement for gethostbyname.
 *
 * Returns: NULL on failure, hostent pointer on success
 */

struct hostent *rc_gethostbyname(char const *hostname)
{
	struct 	hostent *hp;
#ifdef GETHOSTBYNAME_R
#if defined (GETHOSTBYNAMERSTYLE_SYSV) || defined (GETHOSTBYNAMERSTYLE_GNU)
	struct 	hostent hostbuf;
	int	res;
	int	herr;
	
	if(!tmphostbuf) tmphostbuf = malloc(hostbuflen);
#endif
#endif

#ifdef GETHOSTBYNAME_R
#if defined (GETHOSTBYNAMERSTYLE_GNU)
	while ((res = gethostbyname_r(hostname, &hostbuf, tmphostbuf, hostbuflen, &hp, &herr)) == ERANGE)
	{
		/* Enlarge the buffer */
		hostbuflen *= 2;
		tmphostbuf = realloc(tmphostbuf, hostbuflen);
	}
	if(res) return NULL;
#elif defined (GETHOSTBYNAMERSTYLE_SYSV)
	hp = gethostbyname_r(hostname, &hostbuf, tmphostbuf, hostbuflen, &herr);
#else
	hp = gethostbyname(hostname);
#endif
#else
	hp = gethostbyname(hostname);
#endif

	if (hp == NULL) {
		return NULL;
	}
	return hp;
} 

/*
 * Function: rc_gethostbyname
 *
 * Purpose: threadsafe replacement for gethostbyname.
 *
 * Returns: NULL on failure, hostent pointer on success
 */

struct hostent *rc_gethostbyaddr(char const *addr, size_t length, int format)
{
	struct 	hostent *hp;
#ifdef GETHOSTBYADDR_R
#if defined (GETHOSTBYADDRRSTYLE_SYSV) || defined (GETHOSTBYADDRRSTYLE_GNU)
	struct	hostent hostbuf;
	int	res;
	int	herr;
	
	if(!tmphostbuf) tmphostbuf = malloc(hostbuflen);
#endif
#endif

#ifdef GETHOSTBYADDR_R
#if defined (GETHOSTBYADDRRSTYLE_GNU)
	while ((res = gethostbyaddr_r(addr, length, format, &hostbuf, tmphostbuf, hostbuflen, 
					&hp, &herr)) == ERANGE)
	{
		/* Enlarge the buffer */
		hostbuflen *= 2;
		tmphostbuf = realloc(tmphostbuf, hostbuflen);
	}
	if(res) return NULL;
#elif GETHOSTBYADDRSTYLE_SYSV
	hp = gethostbyaddr_r(addr, length, format, &hostbuf, tmphostbuf, hostbuflen, &herr);
#else
	hp = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);
#endif
#else
	hp = gethostbyaddr((char *)&addr, sizeof(struct in_addr), AF_INET);
#endif

	if (hp == NULL) {
		return NULL;
	}
	return hp;
} 

/*
 * Function: rc_get_ipaddr
 *
 * Purpose: return an IP address in host long notation from a host
 *          name or address in dot notation.
 *
 * Returns: 0 on failure
 */

uint32_t rc_get_ipaddr (char const *host)
{
	struct 	hostent *hp;

	if (rc_good_ipaddr (host) == 0)
	{
		return ntohl(inet_addr (host));
	}
	else if ((hp = rc_gethostbyname(host)) == NULL)
	{
		rc_log(LOG_ERR,"rc_get_ipaddr: couldn't resolve hostname: %s", host);
		return (uint32_t)0;
	}
	return ntohl((*(uint32_t *) hp->h_addr));
}

/*
 * Function: rc_good_ipaddr
 *
 * Purpose: check for valid IP address in standard dot notation.
 *
 * Returns: 0 on success, -1 when failure
 *
 */

int rc_good_ipaddr (char const *addr)
{
	int             dot_count;
	int             digit_count;

	if (addr == NULL)
		return -1;

	dot_count = 0;
	digit_count = 0;
	while (*addr != '\0' && *addr != ' ')
	{
		if (*addr == '.')
		{
			dot_count++;
			digit_count = 0;
		}
		else if (!isdigit (*addr))
		{
			dot_count = 5;
		}
		else
		{
			digit_count++;
			if (digit_count > 3)
			{
				dot_count = 5;
			}
		}
		addr++;
	}
	if (dot_count != 3)
	{
		return -1;
	}
	else
	{
		return 0;
	}
}

/*
 * Function: rc_ip_hostname
 *
 * Purpose: Return a printable host name (or IP address in dot notation)
 *	    for the supplied IP address.
 *
 */

char const *rc_ip_hostname (uint32_t h_ipaddr)
{
	struct hostent  *hp;
	uint32_t           n_ipaddr = htonl (h_ipaddr);

	if ((hp = rc_gethostbyaddr ((char *) &n_ipaddr, sizeof (struct in_addr),
			    AF_INET)) == NULL) {
		rc_log(LOG_ERR,"rc_ip_hostname: couldn't look up host by addr: %08lX", h_ipaddr);
	}

	return (hp == NULL) ? "unknown" : hp->h_name;
}

/*
 * Function: rc_getport
 *
 * Purpose: get the port number for the supplied request type
 *
 */

unsigned short rc_getport(int type)
{
	struct servent *svp;

	if ((svp = getservbyname ((type==AUTH)?"radius":"radacct", "udp")) == NULL)
	{
		return (type==AUTH) ? PW_AUTH_UDP_PORT : PW_ACCT_UDP_PORT;
	} else {
		return ntohs ((unsigned short) svp->s_port);
	}
}

/*
 * Function: rc_own_hostname
 *
 * Purpose: get the hostname of this machine
 *
 * Returns  -1 on failure, 0 on success
 *
 */

int
rc_own_hostname(char *hostname, int len)
{
#ifdef HAVE_UNAME
	struct	utsname uts;
#endif

#if defined(HAVE_UNAME)
	if (uname(&uts) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
	strncpy(hostname, uts.nodename, len);
#elif defined(HAVE_GETHOSTNAME)
	if (gethostname(hostname, len) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#elif defined(HAVE_SYSINFO)
	if (sysinfo(SI_HOSTNAME, hostname, len) < 0)
	{
		rc_log(LOG_ERR,"rc_own_hostname: couldn't get own hostname");
		return -1;
	}
#else
	return -1;
#endif

	return 0;
}

/*
 * Function: rc_own_ipaddress
 *
 * Purpose: get the IP address of this host in host order
 *
 * Returns: IP address on success, 0 on failure
 *
 */

uint32_t rc_own_ipaddress(rc_handle *rh)
{
	char hostname[256];

	if (!rh->this_host_ipaddr) {
		if (rc_conf_str(rh, "bindaddr") == NULL ||
		    strcmp(rc_conf_str(rh, "bindaddr"), "*") == 0) {
			if (rc_own_hostname(hostname, sizeof(hostname)) < 0)
				return 0;
		} else {
			strncpy(hostname, rc_conf_str(rh, "bindaddr"), sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
		}
		if ((rh->this_host_ipaddr = rc_get_ipaddr (hostname)) == 0) {
			rc_log(LOG_ERR, "rc_own_ipaddress: couldn't get own IP address");
			return 0;
		}
	}

	return rh->this_host_ipaddr;
}

/*
 * Function: rc_own_bind_ipaddress
 *
 * Purpose: get the IP address to be used as a source address
 *          for sending requests in host order
 *
 * Returns: IP address
 *
 */

uint32_t rc_own_bind_ipaddress(rc_handle *rh)
{
	char hostname[256];
	uint32_t rval;

	if (rh->this_host_bind_ipaddr != NULL)
		return *rh->this_host_bind_ipaddr;

	rh->this_host_bind_ipaddr = malloc(sizeof(*rh->this_host_bind_ipaddr));
	if (rh->this_host_bind_ipaddr == NULL)
		rc_log(LOG_CRIT, "rc_own_bind_ipaddress: out of memory");
	if (rc_conf_str(rh, "bindaddr") == NULL ||
	    strcmp(rc_conf_str(rh, "bindaddr"), "*") == 0) {
		rval = INADDR_ANY;
	} else {
		strncpy(hostname, rc_conf_str(rh, "bindaddr"), sizeof(hostname));
		hostname[sizeof(hostname) - 1] = '\0';
		if ((rval = rc_get_ipaddr (hostname)) == 0) {
			rc_log(LOG_ERR, "rc_own_ipaddress: couldn't get IP address from bindaddr");
			rval = INADDR_ANY;
		}
	}
	if (rh->this_host_bind_ipaddr != NULL)
		*rh->this_host_bind_ipaddr = rval;

	return rval;
}

/*
 * Function: rc_get_srcaddr
 *
 * Purpose: given remote address find local address which the
 *          system will use as a source address for sending
 *          datagrams to that remote address
 *
 * Returns: 0 in success, -1 on failure, address is filled into
 *          the first argument.
 *
 */
int
rc_get_srcaddr(struct sockaddr *lia, struct sockaddr *ria)
{
	int temp_sock;
	socklen_t namelen;

	temp_sock = socket(ria->sa_family, SOCK_DGRAM, 0);
	if (temp_sock == -1) {
		rc_log(LOG_ERR, "rc_get_srcaddr: socket: %s", strerror(errno));
		return -1;
	}

	if (connect(temp_sock, ria, SA_LEN(ria)) != 0) {
		rc_log(LOG_ERR, "rc_get_srcaddr: connect: %s",
		    strerror(errno));
		close(temp_sock);
		return -1;
	}

	namelen = SA_LEN(ria);
	if (getsockname(temp_sock, lia, &namelen) != 0) {
		rc_log(LOG_ERR, "rc_get_srcaddr: getsockname: %s",
		    strerror(errno));
		close(temp_sock);
		return -1;
	}

	close(temp_sock);
	return 0;
}
