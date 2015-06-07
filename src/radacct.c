/*
 * Copyright (C) 1995,1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#include <config.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <radcli/radcli.h>
#include <radcli/version.h>
#include <messages.h>
#include <pathnames.h>

static char *pname;

void usage(void)
{
	fprintf(stderr,"Usage: %s [-Vh] [-f <config_file>] [-i <client_port>]\n\n", pname);
	fprintf(stderr,"  -V            output version information\n");
	fprintf(stderr,"  -h            output this text\n");
	fprintf(stderr,"  -f		filename of alternate config file\n");
	exit(ERROR_RC);
}

void version(void)
{
	fprintf(stderr,"%s: %s\n", pname, RADCLI_VERSION);
	exit(ERROR_RC);
}

static
VALUE_PAIR *rc_avpair_readin(rc_handle const *rh, FILE *input)
{
       VALUE_PAIR *vp = NULL;
       char buffer[1024], *q;

       while (fgets(buffer, sizeof(buffer), input) != NULL)
       {
               q = buffer;

               while(*q && isspace(*q)) q++;

               if ((*q == '\n') || (*q == '#') || (*q == '\0'))
                       continue;

               if (rc_avpair_parse(rh, q, &vp) < 0) {
                       rc_log(LOG_ERR, "rc_avpair_readin: malformed attribute: %s", buffer);
                       rc_avpair_free(vp);
                       return NULL;
               }
       }

       return vp;
}

int
main (int argc, char **argv)
{
	int			result = ERROR_RC;
	VALUE_PAIR	*send = NULL;
   	uint32_t		client_port;
   	int			c;
	VALUE_PAIR	*vp;
	DICT_VALUE  *dval;
	char *username, *service, *fproto, *type;
	char *path_radiusclient_conf = RC_CONFIG_FILE;
	rc_handle *rh;

	extern char *optarg;

	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);

	while ((c = getopt(argc,argv,"f:hV")) > 0)
	{
		switch(c)
		{
			case 'f':
				path_radiusclient_conf = optarg;
				break;
			case 'V':
				version();
				break;
			case 'h':
				usage();
				break;
			default:
				exit(ERROR_RC);
				break;
		}
	}

	if ((rh = rc_read_config(path_radiusclient_conf)) == NULL)
		exit(ERROR_RC);

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0)
		exit (ERROR_RC);

	client_port = 0;
	if ((send = rc_avpair_readin(rh, stdin))) {

		username = service = type = "(unknown)";
		fproto = NULL;

		if ((vp = rc_avpair_get(send, PW_ACCT_STATUS_TYPE, 0)) != NULL)
				if ((dval = rc_dict_getval(rh, vp->lvalue, vp->name)) != NULL) {
					type = dval->name;
				}

		if ((vp = rc_avpair_get(send, PW_USER_NAME, 0)) != NULL)
				username = vp->strvalue;

		if ((vp = rc_avpair_get(send, PW_SERVICE_TYPE, 0)) != NULL)
				if ((dval = rc_dict_getval(rh, vp->lvalue, vp->name)) != NULL) {
					service = dval->name;
				}

		if (vp && (vp->lvalue == PW_FRAMED) &&
			((vp = rc_avpair_get(send, PW_FRAMED_PROTOCOL, 0)) != NULL))
				if ((dval = rc_dict_getval(rh, vp->lvalue, vp->name)) != NULL) {
					fproto = dval->name;
				}

		result = rc_acct(rh, client_port, send);
		if (result == OK_RC)
		{
			fprintf(stdout, SC_ACCT_OK);
			fprintf(stderr, "accounting OK, type %s, username %s, service %s%s%s",
				   type, username, service,(fproto)?"/":"", (fproto)?fproto:"");
		}
		else
		{
			fprintf(stdout, SC_ACCT_FAILED, result);
			fprintf(stderr, "accounting FAILED, type %s, username %s, service %s%s%s",
				   type, username, service,(fproto)?"/":"", (fproto)?fproto:"");
		}
		rc_avpair_free(send);
	}

	exit (result);
}
