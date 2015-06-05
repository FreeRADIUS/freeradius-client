/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

#include	<config.h>
#include	<includes.h>
#include	<radcli.h>
#include	<pathnames.h>
#include	"common.h"

static char *pname = NULL;

int
main (int argc, char **argv)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR 	*send, *received;
	uint32_t		service;
	char 		msg[PW_MAX_MSG_SIZE], username_realm[256];
	char		*default_realm;
	rc_handle	*rh;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);

	if ((rh = rc_read_config2(RC_CONFIG_FILE, RC_CONFIG_LOAD_ALL)) == NULL)
		return ERROR_RC;

	default_realm = rc_conf_str(rh, "default_realm");

	strcpy(username, "my-username");
	strcpy(passwd, "my-password");

	send = NULL;

	/*
	 * Fill in User-Name
	 */
	strncpy(username_realm, username, sizeof(username_realm));

	/* Append default realm */
	if (default_realm && default_realm[0] != 0)
		snprintf(username_realm, sizeof(username_realm), "%s@%s", username, default_realm);
	else
		strcpy(username_realm, username);

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

	if (result == OK_RC) {
		fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);
	} else {
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
	}

	return result;
}
