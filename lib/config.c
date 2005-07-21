/*
 * $Id: config.c,v 1.12 2005/07/21 07:55:56 sobomax Exp $
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
#include <radiusclient-ng.h>
#include <options.h>

static int test_config(rc_handle *, char *);

/*
 * Function: find_option
 *
 * Purpose: find an option in the option list
 *
 * Returns: pointer to option on success, NULL otherwise
 */

static OPTION *find_option(rc_handle *rh, char *optname, unsigned int type)
{
	int i;

	/* there're so few options that a binary search seems not necessary */
	for (i = 0; i < NUM_OPTIONS; i++) {
		if (!strcmp(rh->config_options[i].name, optname) &&
		    (rh->config_options[i].type & type))
		    	return &rh->config_options[i];
	}

	return NULL;
}

/*
 * Function: set_option_...
 *
 * Purpose: set a specific option doing type conversions
 *
 * Returns: 0 on success, -1 on failure
 */

static int set_option_str(char *filename, int line, OPTION *option, char *p)
{
	if (p) {
		option->val = (void *) strdup(p);
		if (option->val == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			return -1;
		}
	} else {
		option->val = NULL;
	}

	return 0;
}

static int set_option_int(char *filename, int line, OPTION *option, char *p)
{
	int *iptr;

	if (p == NULL) {
		rc_log(LOG_ERR, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	if ((iptr = malloc(sizeof(*iptr))) == NULL) {
		rc_log(LOG_CRIT, "read_config: out of memory");
		return -1;
	}

	*iptr = atoi(p);
	option->val = (void *) iptr;

	return 0;
}

static int set_option_srv(char *filename, int line, OPTION *option, char *p)
{
	SERVER *serv;
	char *q;
	struct servent *svp;

	if (p == NULL) {
		rc_log(LOG_ERR, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	serv = (SERVER *) option->val;
	if (serv == NULL) {
		serv = malloc(sizeof(*serv));
		if (serv == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			return -1;
		}
		serv->max = 0;
	}

	while ((p = strtok(p, ", \t")) != NULL) {

		if ((q = strchr(p,':')) != NULL) {
			*q = '\0';
			q++;
			serv->port[serv->max] = atoi(q);
		} else {
			if (!strcmp(option->name,"authserver"))
				if ((svp = getservbyname ("radius", "udp")) == NULL)
					serv->port[serv->max] = PW_AUTH_UDP_PORT;
				else
					serv->port[serv->max] = ntohs ((unsigned int) svp->s_port);
			else if (!strcmp(option->name, "acctserver"))
				if ((svp = getservbyname ("radacct", "udp")) == NULL)
					serv->port[serv->max] = PW_ACCT_UDP_PORT;
				else
					serv->port[serv->max] = ntohs ((unsigned int) svp->s_port);
			else {
				rc_log(LOG_ERR, "%s: line %d: no default port for %s", filename, line, option->name);
				if (option->val == NULL)
					free(serv);
				return -1;
			}
		}

		serv->name[serv->max] = strdup(p);
		if (serv->name[serv->max] == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			if (option->val == NULL)
				free(serv);
			return -1;
		}
		serv->max++;

		p = NULL;
	}
	if (option->val == NULL)
		option->val = (void *)serv;

	return 0;
}

static int set_option_auo(char *filename, int line, OPTION *option, char *p)
{
	int *iptr;

	if (p == NULL) {
		rc_log(LOG_WARNING, "%s: line %d: bogus option value", filename, line);
		return -1;
	}

	if ((iptr = malloc(sizeof(iptr))) == NULL) {
			rc_log(LOG_CRIT, "read_config: out of memory");
			return -1;
	}

	*iptr = 0;
	p = strtok(p, ", \t");

	if (!strncmp(p, "local", 5))
			*iptr = AUTH_LOCAL_FST;
	else if (!strncmp(p, "radius", 6))
			*iptr = AUTH_RADIUS_FST;
	else {
		rc_log(LOG_ERR,"%s: auth_order: unknown keyword: %s", filename, p);
		return -1;
	}

	p = strtok(NULL, ", \t");

	if (p && (*p != '\0')) {
		if ((*iptr & AUTH_RADIUS_FST) && !strcmp(p, "local"))
			*iptr = (*iptr) | AUTH_LOCAL_SND;
		else if ((*iptr & AUTH_LOCAL_FST) && !strcmp(p, "radius"))
			*iptr = (*iptr) | AUTH_RADIUS_SND;
		else {
			rc_log(LOG_ERR,"%s: auth_order: unknown or unexpected keyword: %s", filename, p);
			return -1;
		}
	}

	option->val = (void *) iptr;

	return 0;
}


/*
 * Function: rc_read_config
 *
 * Purpose: read the global config file
 *
 * Returns: new rc_handle on success, NULL when failure
 */

rc_handle *
rc_read_config(char *filename)
{
	FILE *configfd;
	char buffer[512], *p;
	OPTION *option;
	int line, pos;
	rc_handle *rh;

	rh = rc_new();
	if (rh == NULL)
		return NULL;

        rh->config_options = malloc(sizeof(config_options_default));
        if (rh->config_options == NULL) {
                rc_log(LOG_CRIT, "rc_read_config: out of memory");
		rc_destroy(rh);
                return NULL;
        }
        memcpy(rh->config_options, &config_options_default, sizeof(config_options_default));

	if ((configfd = fopen(filename,"r")) == NULL)
	{
		rc_log(LOG_ERR,"rc_read_config: can't open %s: %s", filename, strerror(errno));
		rc_destroy(rh);
		return NULL;
	}

	line = 0;
	while ((fgets(buffer, sizeof(buffer), configfd) != NULL))
	{
		line++;
		p = buffer;

		if ((*p == '\n') || (*p == '#') || (*p == '\0'))
			continue;

		p[strlen(p)-1] = '\0';


		if ((pos = strcspn(p, "\t ")) == 0) {
			rc_log(LOG_ERR, "%s: line %d: bogus format: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		p[pos] = '\0';

		if ((option = find_option(rh, p, OT_ANY)) == NULL) {
			rc_log(LOG_ERR, "%s: line %d: unrecognized keyword: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		if (option->status != ST_UNDEF) {
			rc_log(LOG_ERR, "%s: line %d: duplicate option line: %s", filename, line, p);
			fclose(configfd);
			rc_destroy(rh);
			return NULL;
		}

		p += pos+1;
		while (isspace(*p))
			p++;
		pos = strlen(p) - 1;
		while(pos >= 0 && isspace(p[pos]))
			pos--;
		p[pos + 1] = '\0';

		switch (option->type) {
			case OT_STR:
				if (set_option_str(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_INT:
				if (set_option_int(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_SRV:
				if (set_option_srv(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			case OT_AUO:
				if (set_option_auo(filename, line, option, p) < 0) {
					fclose(configfd);
					rc_destroy(rh);
				 	return NULL;
				}
				break;
			default:
				rc_log(LOG_CRIT, "rc_read_config: impossible case branch!");
				abort();
		}
	}
	fclose(configfd);

	if (test_config(rh, filename) == -1) {
		rc_destroy(rh);
		return NULL;
	}
	return rh;
}

/*
 * Function: rc_conf_str, rc_conf_int, rc_conf_src
 *
 * Purpose: get the value of a config option
 *
 * Returns: config option value
 */

char *rc_conf_str(rc_handle *rh, char *optname)
{
	OPTION *option;

	option = find_option(rh, optname, OT_STR);

	if (option != NULL) {
		return (char *)option->val;
	} else {
		rc_log(LOG_CRIT, "rc_conf_str: unkown config option requested: %s", optname);
		abort();
	}
}

int rc_conf_int(rc_handle *rh, char *optname)
{
	OPTION *option;

	option = find_option(rh, optname, OT_INT|OT_AUO);

	if (option != NULL) {
		return *((int *)option->val);
	} else {
		rc_log(LOG_CRIT, "rc_conf_int: unkown config option requested: %s", optname);
		abort();
	}
}

SERVER *rc_conf_srv(rc_handle *rh, char *optname)
{
	OPTION *option;

	option = find_option(rh, optname, OT_SRV);

	if (option != NULL) {
		return (SERVER *)option->val;
	} else {
		rc_log(LOG_CRIT, "rc_conf_srv: unkown config option requested: %s", optname);
		abort();
	}
}

/*
 * Function: test_config
 *
 * Purpose: test the configuration the user supplied
 *
 * Returns: 0 on success, -1 when failure
 */

static int test_config(rc_handle *rh, char *filename)
{
#if 0
	struct stat st;
	char	    *file;
#endif

	if (!(rc_conf_srv(rh, "authserver")->max))
	{
		rc_log(LOG_ERR,"%s: no authserver specified", filename);
		return -1;
	}
	if (!(rc_conf_srv(rh, "acctserver")->max))
	{
		rc_log(LOG_ERR,"%s: no acctserver specified", filename);
		return -1;
	}
	if (!rc_conf_str(rh, "servers"))
	{
		rc_log(LOG_ERR,"%s: no servers file specified", filename);
		return -1;
	}
	if (!rc_conf_str(rh, "dictionary"))
	{
		rc_log(LOG_ERR,"%s: no dictionary specified", filename);
		return -1;
	}

	if (rc_conf_int(rh, "radius_timeout") <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_timeout <= 0 is illegal", filename);
		return -1;
	}
	if (rc_conf_int(rh, "radius_retries") <= 0)
	{
		rc_log(LOG_ERR,"%s: radius_retries <= 0 is illegal", filename);
		return -1;
	}

#if 0
	file = rc_conf_str(rh, "login_local");
	if (stat(file, &st) == 0)
	{
		if (!S_ISREG(st.st_mode)) {
			rc_log(LOG_ERR,"%s: not a regular file: %s", filename, file);
			return -1;
		}
	} else {
		rc_log(LOG_ERR,"%s: file not found: %s", filename, file);
		return -1;
	}
	file = rc_conf_str(rh, "login_radius");
	if (stat(file, &st) == 0)
	{
		if (!S_ISREG(st.st_mode)) {
			rc_log(LOG_ERR,"%s: not a regular file: %s", filename, file);
			return -1;
		}
	} else {
		rc_log(LOG_ERR,"%s: file not found: %s", filename, file);
		return -1;
	}
#endif

	if (rc_conf_int(rh, "login_tries") <= 0)
	{
		rc_log(LOG_ERR,"%s: login_tries <= 0 is illegal", filename);
		return -1;
	}
	if (rc_conf_str(rh, "seqfile") == NULL)
	{
		rc_log(LOG_ERR,"%s: seqfile not specified", filename);
		return -1;
	}
	if (rc_conf_int(rh, "login_timeout") <= 0)
	{
		rc_log(LOG_ERR,"%s: login_timeout <= 0 is illegal", filename);
		return -1;
	}
	if (rc_conf_str(rh, "mapfile") == NULL)
	{
		rc_log(LOG_ERR,"%s: mapfile not specified", filename);
		return -1;
	}
	if (rc_conf_str(rh, "nologin") == NULL)
	{
		rc_log(LOG_ERR,"%s: nologin not specified", filename);
		return -1;
	}

	return 0;
}

/*
 * Function: rc_find_match
 *
 * Purpose: see if ip_addr is one of the ip addresses of hostname
 *
 * Returns: 0 on success, -1 when failure
 *
 */

static int find_match (UINT4 *ip_addr, char *hostname)
{
	UINT4           addr;
	char          **paddr;
	struct hostent *hp;

	if (rc_good_ipaddr (hostname) == 0)
	{
		if (*ip_addr == ntohl(inet_addr (hostname)))
		{
			return 0;
		}
	}
	else
	{
		if ((hp = gethostbyname (hostname)) == NULL)
		{
			return -1;
		}
		for (paddr = hp->h_addr_list; *paddr; paddr++)
		{
			addr = ** (UINT4 **) paddr;
			if (ntohl(addr) == *ip_addr)
			{
				return 0;
			}
		}
	}
	return -1;
}

/*
 * Function: rc_ipaddr_local
 *
 * Purpose: checks if provided address is local address
 *
 * Returns: 0 if local, 1 if not local, -1 on failure
 *
 */

static int
rc_ipaddr_local(UINT4 ip_addr)
{
	int temp_sock, res, serrno;
	struct sockaddr_in sin;

	temp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (temp_sock == -1)
		return -1;
	memset(&sin, '\0', sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(ip_addr);
	sin.sin_port = htons(0);
	res = bind(temp_sock, (struct sockaddr *)&sin, sizeof(sin));
	serrno = errno;
	close(temp_sock);
	if (res == 0)
		return 0;
	if (serrno == EADDRNOTAVAIL)
		return 1;
	return -1;
}

/*
 * Function: rc_is_myname
 *
 * Purpose: check if provided name refers to ourselves
 *
 * Returns: 0 if yes, 1 if no and -1 on failure
 *
 */

static int
rc_is_myname(char *hostname)
{
	UINT4 addr;
	char **paddr;
	struct hostent *hp;
	int res;

	if (rc_good_ipaddr(hostname) == 0)
		return rc_ipaddr_local(ntohl(inet_addr(hostname)));

	if ((hp = gethostbyname (hostname)) == NULL)
		return -1;
	for (paddr = hp->h_addr_list; *paddr; paddr++) {
		addr = **(UINT4 **)paddr;
		res = rc_ipaddr_local(ntohl(addr));
		if (res == 0 || res == -1)
			return res;
	}
	return 1;
}

/*
 * Function: rc_find_server
 *
 * Purpose: search a server in the servers file
 *
 * Returns: 0 on success, -1 on failure
 *
 */

int rc_find_server (rc_handle *rh, char *server_name, UINT4 *ip_addr, char *secret)
{
	int             len;
	int             result;
	FILE           *clientfd;
	char           *h;
	char           *s;
	char           *host2;
	char            buffer[128];
	char            hostnm[AUTH_ID_LEN + 1];

	/* Get the IP address of the authentication server */
	if ((*ip_addr = rc_get_ipaddr (server_name)) == (UINT4) 0)
		return -1;

	if ((clientfd = fopen (rc_conf_str(rh, "servers"), "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_find_server: couldn't open file: %s: %s", strerror(errno), rc_conf_str(rh, "servers"));
		return -1;
	}

	result = 0;
	while (fgets (buffer, sizeof (buffer), clientfd) != NULL)
	{
		if (*buffer == '#')
			continue;

		if ((h = strtok (buffer, " \t\n")) == NULL) /* first hostname */
			continue;

		memset (hostnm, '\0', AUTH_ID_LEN);
		len = strlen (h);
		if (len > AUTH_ID_LEN)
		{
			len = AUTH_ID_LEN;
		}
		strncpy (hostnm, h, (size_t) len);
		hostnm[AUTH_ID_LEN] = '\0';

		if ((s = strtok (NULL, " \t\n")) == NULL) /* and secret field */
			continue;

		memset (secret, '\0', MAX_SECRET_LENGTH);
		len = strlen (s);
		if (len > MAX_SECRET_LENGTH)
		{
			len = MAX_SECRET_LENGTH;
		}
		strncpy (secret, s, (size_t) len);
		secret[MAX_SECRET_LENGTH] = '\0';

		if (!strchr (hostnm, '/')) /* If single name form */
		{
			if (find_match (ip_addr, hostnm) == 0)
			{
				result++;
				break;
			}
		}
		else /* <name1>/<name2> "paired" form */
		{
			strtok (hostnm, "/");
			if (rc_is_myname(hostnm) == 0)
			{	     /* If we're the 1st name, target is 2nd */
				host2 = strtok (NULL, " ");
				if (find_match (ip_addr, host2) == 0)
				{
					result++;
					break;
				}
			}
			else	/* If we were 2nd name, target is 1st name */
			{
				if (find_match (ip_addr, hostnm) == 0)
				{
					result++;
					break;
				}
			}
		}
	}
	fclose (clientfd);
	if (result == 0)
	{
		memset (buffer, '\0', sizeof (buffer));
		memset (secret, '\0', sizeof (secret));
		rc_log(LOG_ERR, "rc_find_server: couldn't find RADIUS server %s in %s",
			 server_name, rc_conf_str(rh, "servers"));
		return -1;
	}
	return 0;
}

/*
 * Function: rc_config_free
 *
 * Purpose: Free allocated config values
 *
 * Arguments: Radius Client handle
 */

void
rc_config_free(rc_handle *rh)
{
	int i, j;
	SERVER *serv;

	if (rh->config_options == NULL)
		return;

	for (i = 0; i < NUM_OPTIONS; i++) {
		if (rh->config_options[i].val == NULL)
			continue;
		if (rh->config_options[i].type == OT_SRV) {
		        serv = (SERVER *)rh->config_options[i].val;
			for (j = 0; j < serv->max; j++)
				free(serv->name[j]);
			free(serv);
		} else {
			free(rh->config_options[i].val);
		}
	}
	free(rh->config_options);
	rh->config_options = NULL;
}
