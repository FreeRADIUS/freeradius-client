/*
 * $Id: radexample.c,v 1.8 2007/07/11 17:29:30 cparker Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */


static char	rcsid[] =
		"$Id: radexample.c,v 1.8 2007/07/11 17:29:30 cparker Exp $";

#include	<config.h>
#include	<includes.h>
#include	<freeradius-client.h>
#include	<pathnames.h>

static char *pname = NULL;

int
main (int argc, char **argv)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR 	*send, *received;
	uint32_t		service;
	char 		msg[4096], username_realm[256];
	char		*default_realm;
	rc_handle	*rh;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);

	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0)
		return ERROR_RC;

	default_realm = rc_conf_str(rh, "default_realm");

	strncpy(username, rc_getstr (rh, "login: ",1), sizeof(username));
	strncpy (passwd, rc_getstr(rh, "Password: ",0), sizeof (passwd));

	send = NULL;

	/*
	 * Fill in User-Name
	 */

	strncpy(username_realm, username, sizeof(username_realm));

	/* Append default realm */
	if ((strchr(username_realm, '@') == NULL) && default_realm &&
	    (*default_realm != '\0'))
	{
		strncat(username_realm, "@", sizeof(username_realm)-strlen(username_realm)-1);
		strncat(username_realm, default_realm, sizeof(username_realm)-strlen(username_realm)-1);
	}

	if (rc_avpair_add(rh, &send, PW_USER_NAME, username_realm, -1, 0) == NULL)
		return ERROR_RC;

	/*
	 * Fill in User-Password
	 */

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, passwd, -1, 0) == NULL)
		return ERROR_RC;

	/*
	 * Fill in Service-Type
	 */

	service = PW_AUTHENTICATE_ONLY;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
		return ERROR_RC;

	result = rc_auth(rh, 0, send, &received, msg);

	if (result == OK_RC)
	{
		fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);
	}
	else
	{
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
	}

	return result;
}
