/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

#include	<config.h>
#include	<stdio.h>
#include	<radcli/radcli.h>

int
main (int argc, char **argv)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR 	*send, *received;
	uint32_t	service;
	char 		username_realm[256];
	char		*default_realm;
	rc_handle	*rh;

	/* Not needed if you already used openlog() */
	rc_openlog("my-prog-name");

	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;

	default_realm = rc_conf_str(rh, "default_realm");

	strcpy(username, "my-username");
	strcpy(passwd, "my-password");

	send = NULL;

	/*
	 * Fill in User-Name
	 */
	if (default_realm && default_realm[0] != 0)
		snprintf(username_realm, sizeof(username_realm), "%s@%s", username, default_realm);
	else
		snprintf(username_realm, sizeof(username_realm), "%s", username);

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

	result = rc_auth(rh, 0, send, &received, NULL);

	if (result == OK_RC) {
		VALUE_PAIR *vp = received;
		char name[128];
		char value[128];

		fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);

		/* print the known attributes in the reply */
		while(vp != NULL) {
			if (rc_avpair_tostr(rh, vp, name, sizeof(name), value, sizeof(value)) == 0) {
				fprintf(stderr, "%s:\t%s\n", name, value);
			}
			vp = vp->next;
		}
	} else {
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
	}

	return result;
}
