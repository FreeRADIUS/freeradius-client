/*
 * $Id: radius.c,v 1.9 2007/07/11 17:29:30 cparker Exp $
 *
 * Copyright (C) 1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>
#include <messages.h>
#include <radlogin.h>

extern ENV *env;

LFUNC auth_radius(rc_handle *rh, uint32_t client_port, char const *username, char const *passwd)
{

	VALUE_PAIR 	*send, *received, *vp, *service_vp;
	uint32_t		service, ftype, ctype;
	char 		msg[4096], *p, username_realm[256];
	char            name[2048], value[2048]; /* more than enough */
	int		result;
	char		*default_realm, *service_str, *ftype_str;
	DICT_VALUE	*dval;

	send = received = NULL;

	/*
	 * Determine and fill in Service-Type
	 */

#ifdef SCP
	/* determine based on the username what kind of service is requested.
	   this allows you to use one password for all accounts, but the
	   Merit radiusd supplies you just with the right information you
	   need for the specified service type	-lf, 03/15/96 */

	switch (*username)
	{
		case 'S':
				service = PW_FRAMED;
				ftype = PW_SLIP;
				ctype = 0;
				username++;
				break;
		case 'C':
				service = PW_FRAMED;
				ftype = PW_SLIP;
				ctype = PW_VAN_JACOBSON_TCP_IP;
				username++;
				break;
		case 'P':
				service = PW_FRAMED;
				ftype = PW_PPP;
				ctype = 0;
				username++;
				break;
		default:
				service = PW_LOGIN;
				ftype = 0;
				ctype = 0;
				break;
	}
#else
	service = PW_LOGIN;
	ftype = 0;
	ctype = 0;
#endif

	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
		return NULL;

	/* Fill in Framed-Protocol, if neccessary */

	if (ftype != 0)
	{
		if (rc_avpair_add(rh, &send, PW_FRAMED_PROTOCOL, &ftype, -1, 0) == NULL)
			return NULL;
	}

	/* Fill in Framed-Compression, if neccessary */

	if (ctype != 0)
	{
		if (rc_avpair_add(rh, &send, PW_FRAMED_COMPRESSION, &ctype, -1, 0) == NULL)
			return NULL;
	}

	/*
	 * Fill in User-Name
	 */

	 strncpy(username_realm, username, sizeof(username_realm));

	 /* Append default realm */
	 default_realm = rc_conf_str(rh, "default_realm");

	 if ((strchr(username_realm, '@') == NULL) && default_realm &&
	     ((*default_realm) != '\0'))
	 {
		strncat(username_realm, "@", sizeof(username_realm)-strlen(username_realm)-1);
		strncat(username_realm, default_realm, sizeof(username_realm)-strlen(username_realm)-1);
	 }

	if (rc_avpair_add(rh, &send, PW_USER_NAME, username_realm, -1, 0) == NULL)
		return NULL;

	/*
	 * Fill in User-Password
	 */

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, passwd, -1, 0) == NULL)
		return NULL;

	result = rc_auth(rh, client_port, send, &received, msg, NULL);

	if (result == OK_RC)
	{
		/* Set up a running count of attributes saved. */
		int acount[256], attr;

		memset(acount, 0, sizeof(acount));

		rc_add_env(env, "RADIUS_USER_NAME", username);

		vp = received;

		/* map-- keep track of the attributes so that we know
		   when to add the delimiters. Note that we can only
		   handle attributes < 256, which is the standard anyway. */

		while (vp)
		{
			strcpy(name, "RADIUS_");
			if (rc_avpair_tostr(rh, vp, name+7, sizeof(name)-7, value, sizeof(value)) < 0) {
				rc_avpair_free(send);
				rc_avpair_free(received);
				return NULL;
			}

			/* Translate "-" => "_" and uppercase*/
			for(p = name; *p; p++) {
				*p = toupper(*p);
				if (*p == '-') *p = '_';
			}

			/* Add to the attribute count and append the var
			   if necessary. */
			if ((attr = vp->attribute) < 256)
			{
				int count;
				if ((count = acount[attr]++) > 0) {
					char buf[10];
					snprintf(buf, sizeof(buf), "_%d", count);
					strcat(name,buf);
				}
			}

			if (rc_add_env(env, name, value) < 0)
			{
				rc_avpair_free(send);
				rc_avpair_free(received);
				return NULL;
			}

			vp = vp->next;
		}

		service_str = "(unknown)";
		ftype_str = NULL;

		if ((service_vp = rc_avpair_get(received, PW_SERVICE_TYPE, 0)) != NULL)
				if ((dval = rc_dict_getval(rh, service_vp->lvalue, service_vp->name)) != NULL) {
					service_str = dval->name;
				}

		if (service_vp && (service_vp->lvalue == PW_FRAMED) &&
			((vp = rc_avpair_get(received, PW_FRAMED_PROTOCOL, 0)) != NULL))
				if ((dval = rc_dict_getval(rh, vp->lvalue, vp->name)) != NULL) {
					ftype_str = dval->name;
				}

		rc_log(LOG_NOTICE, "authentication OK, username %s, service %s%s%s",
				username, service_str,(ftype_str)?"/":"", (ftype_str)?ftype_str:"");

		if (msg && (*msg != '\0'))
			printf(SC_SERVER_REPLY, msg);
		else
			printf(SC_RADIUS_OK);

		rc_avpair_free(send);
		rc_avpair_free(received);

		return radius_login;
	}
	else
	{
		rc_log(LOG_NOTICE, "authentication FAILED, type RADIUS, username %s",
			   username_realm);
		if (msg && (*msg != '\0'))
			printf(SC_SERVER_REPLY, msg);
		else
			printf(SC_RADIUS_FAILED);
	}

	rc_avpair_free(send);
	if (received)
		rc_avpair_free(received);

	return NULL;
}

void
radius_login(rc_handle *rh, char const *username)
{
	char *login_radius = rc_conf_str(rh, "login_radius");

	execle(login_radius, login_radius, NULL, env->env);

	rc_log(LOG_ERR, "couldn't execute %s: %s", login_radius, strerror(errno));
	fprintf(stderr, "couldn't execute %s: %s", login_radius, strerror(errno));

	sleep(1);	/* give the user time to read */
	exit(ERROR_RC);
}
