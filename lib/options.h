/*
 * Copyright (C) 1996 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */

#define OPTION_LEN	64

/* ids for different option types */
#define OT_STR		(1<<0)			//!< string.
#define OT_INT		(1<<1)			//!< integer.
#define OT_SRV		(1<<2)			//!< server list.
#define OT_AUO		(1<<3)			//!< authentication order.

#define OT_ANY		((unsigned int)~0)	//!< Used internally.

/* status types */
#define ST_UNDEF	(1<<0)			//!< option is undefined.

typedef struct _option {
	char name[OPTION_LEN];			//!< name of the option.
	int type, status;			//!< type and status.
	void *val;				//!< pointer to option value.
} OPTION;

static OPTION config_options_default[] = {
/* internally used options */
{"config_file",		OT_STR, ST_UNDEF, NULL},
/* RADIUS specific options */
{"serv-auth-type",	OT_STR, ST_UNDEF, NULL},
{"tls-verify-hostname",	OT_STR, ST_UNDEF, NULL},
{"tls-ca-file",		OT_STR, ST_UNDEF, NULL},
{"tls-cert-file",	OT_STR, ST_UNDEF, NULL},
{"tls-key-file",	OT_STR, ST_UNDEF, NULL},
{"nas-identifier",	OT_STR, ST_UNDEF, NULL},
{"authserver",		OT_SRV, ST_UNDEF, NULL},
{"acctserver",		OT_SRV, ST_UNDEF, NULL},
{"servers",		OT_STR, ST_UNDEF, NULL},
{"dictionary",		OT_STR, ST_UNDEF, NULL},
{"default_realm",	OT_STR, ST_UNDEF, NULL},
{"radius_timeout",	OT_INT, ST_UNDEF, NULL},
{"radius_retries",	OT_INT,	ST_UNDEF, NULL},
{"radius_deadtime",	OT_INT, ST_UNDEF, NULL},
{"bindaddr",		OT_STR, ST_UNDEF, NULL},
{"clientdebug",		OT_INT, ST_UNDEF, NULL},
/* Deprecated options */
{"login_radius",	OT_STR, ST_UNDEF, NULL},
{"seqfile",		OT_STR, ST_UNDEF, NULL},
{"mapfile",		OT_STR, ST_UNDEF, NULL},
{"auth_order",	 	OT_AUO, ST_UNDEF, NULL},
{"login_tries",	 	OT_INT, ST_UNDEF, NULL},
{"login_timeout",	OT_INT, ST_UNDEF, NULL},
{"nologin",		OT_STR, ST_UNDEF, NULL},
{"issue",		OT_STR, ST_UNDEF, NULL},
{"login_local",		OT_STR, ST_UNDEF, NULL},
};

#define	NUM_OPTIONS	((sizeof(config_options_default))/(sizeof(config_options_default[0])))
