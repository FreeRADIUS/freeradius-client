/*
 * $Id: freeradius-client.h,v 1.18 2010/06/15 09:22:51 aland Exp $
 *
 * Copyright (C) 1995,1996,1997,1998 Lars Fenneberg
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

#ifndef FREERADIUS_CLIENT_H
#define FREERADIUS_CLIENT_H

#ifdef CP_DEBUG
#define		DEBUG(args...)	rc_log(## args)
#else
#define		DEBUG(args...)	;
#endif

#include	<sys/types.h>
/*
 * Include for C99 uintX_t defines is stdint.h on most systems.  Solaris uses
 * inttypes.h instead.  Comment out the stdint include if you get an error,
 * and uncomment the inttypes.h include.
 */
#include	<stdint.h> 
/* #include	<inttypes.h> */
#include	<stdio.h>
#include	<time.h>

#undef __BEGIN_DECLS
#undef __END_DECLS
#ifdef __cplusplus
# define __BEGIN_DECLS extern "C" {
# define __END_DECLS }
#else
# define __BEGIN_DECLS /* empty */
# define __END_DECLS /* empty */
#endif

#define AUTH_VECTOR_LEN		16
#define AUTH_PASS_LEN		(3 * 16) /* multiple of 16 */
#define AUTH_ID_LEN		64
#define AUTH_STRING_LEN		253	 /* maximum of 253 */

#define	BUFFER_LEN		8192

#define NAME_LENGTH		32
#define	GETSTR_LENGTH		128	/* must be bigger than AUTH_PASS_LEN */

#define	MAX_SECRET_LENGTH	(3 * 16) /* MUST be multiple of 16 */

#define MAX_STRING_LEN                 254 /* RFC2138: string 0-253 octets */

#define	VENDOR(x)		(((x) >> 16) & 0xffff)
#define	ATTRID(x)		((x) & 0xffff)

/* codes for radius_buildreq, radius_getport, etc. */
#define AUTH			0
#define ACCT			1

/* defines for config.c */

#define SERVER_MAX 8

#define AUTH_LOCAL_FST	(1<<0)
#define AUTH_RADIUS_FST (1<<1)
#define AUTH_LOCAL_SND  (1<<2)
#define AUTH_RADIUS_SND (1<<3)

typedef struct server {
	int max;
	char *name[SERVER_MAX];
	uint16_t port[SERVER_MAX];
	char *secret[SERVER_MAX];
	double deadtime_ends[SERVER_MAX];
} SERVER;

typedef struct pw_auth_hdr
{
	uint8_t          code;
	uint8_t          id;
	uint16_t         length;
	uint8_t          vector[AUTH_VECTOR_LEN];
	uint8_t          data[2];
} AUTH_HDR;

struct rc_conf
{
	struct _option		*config_options;
	uint32_t 			this_host_ipaddr;
	uint32_t			*this_host_bind_ipaddr;
	struct map2id_s		*map2id_list;
	struct dict_attr	*dictionary_attributes;
	struct dict_value	*dictionary_values;
	struct dict_vendor	*dictionary_vendors;
	char			buf[GETSTR_LENGTH];
	char			buf1[14];
	char			ifname[512];
};

typedef struct rc_conf rc_handle;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1645
#define PW_ACCT_UDP_PORT		1646

#define PW_TYPE_STRING			0
#define PW_TYPE_INTEGER			1
#define PW_TYPE_IPADDR			2
#define PW_TYPE_DATE			3

/* standard RADIUS codes */

#define	PW_ACCESS_REQUEST		1
#define	PW_ACCESS_ACCEPT		2
#define	PW_ACCESS_REJECT		3
#define	PW_ACCOUNTING_REQUEST		4
#define	PW_ACCOUNTING_RESPONSE		5
#define	PW_ACCOUNTING_STATUS		6
#define	PW_PASSWORD_REQUEST		7
#define	PW_PASSWORD_ACK			8
#define	PW_PASSWORD_REJECT		9
#define	PW_ACCOUNTING_MESSAGE		10
#define	PW_ACCESS_CHALLENGE		11
#define	PW_STATUS_SERVER		12
#define	PW_STATUS_CLIENT		13


/* standard RADIUS attribute-value pairs */

#define	PW_USER_NAME			1	/* string */
#define	PW_USER_PASSWORD		2	/* string */
#define	PW_CHAP_PASSWORD		3	/* string */
#define	PW_NAS_IP_ADDRESS		4	/* ipaddr */
#define	PW_NAS_PORT			5	/* integer */
#define	PW_SERVICE_TYPE			6	/* integer */
#define	PW_FRAMED_PROTOCOL		7	/* integer */
#define	PW_FRAMED_IP_ADDRESS		8	/* ipaddr */
#define	PW_FRAMED_IP_NETMASK		9	/* ipaddr */
#define	PW_FRAMED_ROUTING		10	/* integer */
#define	PW_FILTER_ID		        11	/* string */
#define	PW_FRAMED_MTU			12	/* integer */
#define	PW_FRAMED_COMPRESSION		13	/* integer */
#define	PW_LOGIN_IP_HOST		14	/* ipaddr */
#define	PW_LOGIN_SERVICE		15	/* integer */
#define	PW_LOGIN_PORT			16	/* integer */
#define	PW_OLD_PASSWORD			17	/* string */ /* deprecated */
#define	PW_REPLY_MESSAGE		18	/* string */
#define	PW_LOGIN_CALLBACK_NUMBER	19	/* string */
#define	PW_FRAMED_CALLBACK_ID		20	/* string */
#define	PW_EXPIRATION			21	/* date */ /* deprecated */
#define	PW_FRAMED_ROUTE			22	/* string */
#define	PW_FRAMED_IPX_NETWORK		23	/* integer */
#define	PW_STATE			24	/* string */
#define	PW_CLASS			25	/* string */
#define	PW_VENDOR_SPECIFIC		26	/* string */
#define	PW_SESSION_TIMEOUT		27	/* integer */
#define	PW_IDLE_TIMEOUT			28	/* integer */
#define	PW_TERMINATION_ACTION		29	/* integer */
#define	PW_CALLED_STATION_ID            30      /* string */
#define	PW_CALLING_STATION_ID           31      /* string */
#define	PW_NAS_IDENTIFIER		32	/* string */
#define	PW_PROXY_STATE			33	/* string */
#define	PW_LOGIN_LAT_SERVICE		34	/* string */
#define	PW_LOGIN_LAT_NODE		35	/* string */
#define	PW_LOGIN_LAT_GROUP		36	/* string */
#define	PW_FRAMED_APPLETALK_LINK	37	/* integer */
#define	PW_FRAMED_APPLETALK_NETWORK	38	/* integer */
#define	PW_FRAMED_APPLETALK_ZONE	39	/* string */
#define	PW_EVENT_TIMESTAMP		55	/* integer */
#define	PW_CHAP_CHALLENGE               60      /* string */
#define	PW_NAS_PORT_TYPE                61      /* integer */
#define	PW_PORT_LIMIT                   62      /* integer */
#define PW_LOGIN_LAT_PORT               63      /* string */
#define PW_CONNECT_INFO                 77      /* string */
#define PW_MESSAGE_AUTHENTICATOR        80      /* string */

/* RFC3162 IPv6 attributes */

#define PW_NAS_IPV6_ADDRESS             95      /* string */
#define PW_FRAMED_INTERFACE_ID          96      /* string */
#define PW_FRAMED_IPV6_PREFIX           97      /* string */
#define PW_LOGIN_IPV6_HOST              98      /* string */
#define PW_FRAMED_IPV6_ROUTE            99      /* string */
#define PW_FRAMED_IPV6_POOL             100     /* string */

/*	Accounting */

#define	PW_ACCT_STATUS_TYPE		40	/* integer */
#define	PW_ACCT_DELAY_TIME		41	/* integer */
#define	PW_ACCT_INPUT_OCTETS		42	/* integer */
#define	PW_ACCT_OUTPUT_OCTETS		43	/* integer */
#define	PW_ACCT_SESSION_ID		44	/* string */
#define	PW_ACCT_AUTHENTIC		45	/* integer */
#define	PW_ACCT_SESSION_TIME		46	/* integer */
#define	PW_ACCT_INPUT_PACKETS		47	/* integer */
#define	PW_ACCT_OUTPUT_PACKETS		48	/* integer */
#define PW_ACCT_TERMINATE_CAUSE		49	/* integer */
#define PW_ACCT_MULTI_SESSION_ID	50	/* string */
#define PW_ACCT_LINK_COUNT		51	/* integer */

/* 	Experimental SIP-specific attributes (draft-sterman-aaa-sip-00.txt etc) */

#define	PW_DIGEST_RESPONSE		206	/* string */
#define	PW_DIGEST_ATTRIBUTES		207	/* string */
#define	PW_DIGEST_REALM			1063	/* string */
#define	PW_DIGEST_NONCE			1064	/* string */
#define	PW_DIGEST_METHOD		1065	/* string */
#define	PW_DIGEST_URI			1066	/* string */
#define	PW_DIGEST_QOP			1067	/* string */
#define	PW_DIGEST_ALGORITHM		1068	/* string */
#define	PW_DIGEST_BODY_DIGEST		1069	/* string */
#define	PW_DIGEST_CNONCE		1070	/* string */
#define	PW_DIGEST_NONCE_COUNT		1071	/* string */
#define	PW_DIGEST_USER_NAME		1072	/* string */

/*	Merit Experimental Extensions */

#define PW_USER_ID                      222     /* string */
#define PW_USER_REALM                   223     /* string */

/*	Integer Translations */

/*	SERVICE TYPES	*/

#define	PW_LOGIN			1
#define	PW_FRAMED			2
#define	PW_CALLBACK_LOGIN		3
#define	PW_CALLBACK_FRAMED		4
#define	PW_OUTBOUND			5
#define	PW_ADMINISTRATIVE		6
#define PW_NAS_PROMPT                   7
#define PW_AUTHENTICATE_ONLY		8
#define PW_CALLBACK_NAS_PROMPT          9

/*	FRAMED PROTOCOLS	*/

#define	PW_PPP				1
#define	PW_SLIP				2
#define PW_ARA                          3
#define PW_GANDALF                      4
#define PW_XYLOGICS                     5

/*	FRAMED ROUTING VALUES	*/

#define	PW_NONE				0
#define	PW_BROADCAST			1
#define	PW_LISTEN			2
#define	PW_BROADCAST_LISTEN		3

/*	FRAMED COMPRESSION TYPES	*/

#define	PW_VAN_JACOBSON_TCP_IP		1
#define	PW_IPX_HEADER_COMPRESSION	2

/*	LOGIN SERVICES	*/

#define PW_TELNET                       0
#define PW_RLOGIN                       1
#define PW_TCP_CLEAR                    2
#define PW_PORTMASTER                   3
#define PW_LAT                          4
#define PW_X25_PAD                      5
#define PW_X25_T3POS                    6

/*	TERMINATION ACTIONS	*/

#define	PW_DEFAULT			0
#define	PW_RADIUS_REQUEST		1

/*	PROHIBIT PROTOCOL  */

#define PW_DUMB		0	/* 1 and 2 are defined in FRAMED PROTOCOLS */
#define PW_AUTH_ONLY	3
#define PW_ALL		255

/*	ACCOUNTING STATUS TYPES    */

#define PW_STATUS_START		1
#define PW_STATUS_STOP		2
#define PW_STATUS_ALIVE		3
#define PW_STATUS_MODEM_START	4
#define PW_STATUS_MODEM_STOP	5
#define PW_STATUS_CANCEL	6
#define PW_ACCOUNTING_ON	7
#define PW_ACCOUNTING_OFF	8

/*      ACCOUNTING TERMINATION CAUSES   */

#define PW_USER_REQUEST         1
#define PW_LOST_CARRIER         2
#define PW_LOST_SERVICE         3
#define PW_ACCT_IDLE_TIMEOUT    4
#define PW_ACCT_SESSION_TIMEOUT 5
#define PW_ADMIN_RESET          6
#define PW_ADMIN_REBOOT         7
#define PW_PORT_ERROR           8
#define PW_NAS_ERROR            9
#define PW_NAS_REQUEST          10
#define PW_NAS_REBOOT           11
#define PW_PORT_UNNEEDED        12
#define PW_PORT_PREEMPTED       13
#define PW_PORT_SUSPENDED       14
#define PW_SERVICE_UNAVAILABLE  15
#define PW_CALLBACK             16
#define PW_USER_ERROR           17
#define PW_HOST_REQUEST         18

/*     NAS PORT TYPES    */

#define PW_ASYNC		0
#define PW_SYNC			1
#define PW_ISDN_SYNC		2
#define PW_ISDN_SYNC_V120	3
#define PW_ISDN_SYNC_V110	4
#define PW_VIRTUAL		5

/*	   AUTHENTIC TYPES */
#define PW_RADIUS	1
#define PW_LOCAL	2
#define PW_REMOTE	3

/* Server data structures */


typedef struct attr_flags 
{
	char         has_tag;     /* attribute allows tags */
	signed char  tag;
	uint8_t      encrypt;     /* encryption method */
} ATTR_FLAGS;

/*
 *     Values of the encryption flags.
 */
#define FLAG_ENCRYPT_NONE               (0)
#define FLAG_ENCRYPT_USER_PASSWORD      (1)
#define FLAG_ENCRYPT_TUNNEL_PASSWORD    (2)
#define FLAG_ENCRYPT_ASCEND_SECRET      (3)

typedef struct dict_attr
{
	char              name[NAME_LENGTH + 1];	/* attribute name */
	int               value;			/* attribute index */
	int               type;				/* string, int, etc. */
	ATTR_FLAGS        flags;
	struct dict_attr *next;
} DICT_ATTR;

typedef struct dict_value
{
	char               attrname[NAME_LENGTH +1];
	char               name[NAME_LENGTH + 1];
	int                value;
	struct dict_value *next;
} DICT_VALUE;

typedef struct dict_vendor
{
	char		   vendorname[NAME_LENGTH +1];
	int		   vendorpec;
	struct dict_vendor *next;
} DICT_VENDOR;

typedef struct value_pair
{
	char               name[NAME_LENGTH + 1];
	int                attribute;
	int                type;
	uint32_t           lvalue;
	char               strvalue[AUTH_STRING_LEN + 1];
	ATTR_FLAGS         flags;
	struct value_pair *next;
} VALUE_PAIR;

/* don't change this, as it has to be the same as in the Merit radiusd code */
#define MGMT_POLL_SECRET	"Hardlyasecret"

/* 	Define return codes from "SendServer" utility */

#define BADRESP_RC	-2
#define ERROR_RC	-1
#define OK_RC		0
#define TIMEOUT_RC	1
#define REJECT_RC	2

typedef struct send_data /* Used to pass information to sendserver() function */
{
	uint8_t        code;		/* RADIUS packet code */
	uint8_t        seq_nbr;		/* Packet sequence number */
	char           *server;		/* Name/addrress of RADIUS server */
	int            svc_port;	/* RADIUS protocol destination port */
	char	       *secret;		/* Shared secret of RADIUS server */	
	int            timeout;		/* Session timeout in seconds */
	int	       retries;
	VALUE_PAIR     *send_pairs;     /* More a/v pairs to send */
	VALUE_PAIR     *receive_pairs;  /* Where to place received a/v pairs */
} SEND_DATA;

#ifndef MIN
#define MIN(a, b)     ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#endif

#ifndef PATH_MAX
#define PATH_MAX	1024
#endif

typedef struct env
{
	int maxsize, size;
	char **env;
} ENV;

#define ENV_SIZE	128

__BEGIN_DECLS

/*	Function prototypes	*/

/*	avpair.c		*/

int rc_tunnel_pwdecode(uint8_t *, int *, const char *, const char *);
VALUE_PAIR *rc_avpair_add(const rc_handle *, VALUE_PAIR **, int, void *, int, int);
int rc_avpair_assign(VALUE_PAIR *, void *, int);
VALUE_PAIR *rc_avpair_new(const rc_handle *, int, void *, int, int);
VALUE_PAIR *rc_avpair_gen(const rc_handle *, VALUE_PAIR *, unsigned char *, int, int);
VALUE_PAIR *rc_avpair_get(VALUE_PAIR *, int, int);
void rc_avpair_insert(VALUE_PAIR **, VALUE_PAIR *, VALUE_PAIR *);
void rc_avpair_free(VALUE_PAIR *);
int rc_avpair_parse(const rc_handle *, char *, VALUE_PAIR **);
int rc_avpair_tostr(const rc_handle *, VALUE_PAIR *, char *, int, char *, int);
char *rc_avpair_log(rc_handle *, VALUE_PAIR *, char *buf, size_t buf_len);
VALUE_PAIR *rc_avpair_readin(const rc_handle *, FILE *);

/*	buildreq.c		*/

void rc_buildreq(rc_handle *, SEND_DATA *, int, char *, unsigned short, char *, int, int);
unsigned char rc_get_id();
int rc_auth(rc_handle *, uint32_t, VALUE_PAIR *, VALUE_PAIR **, char *);
int rc_auth_proxy(rc_handle *, VALUE_PAIR *, VALUE_PAIR **, char *);
int rc_acct(rc_handle *, uint32_t, VALUE_PAIR *);
int rc_acct_proxy(rc_handle *, VALUE_PAIR *);
int rc_check(rc_handle *, char *, char *, unsigned short, char *);

/*	clientid.c		*/

int rc_read_mapfile(rc_handle *, char *);
uint32_t rc_map2id(rc_handle *, char *);
void rc_map2id_free(rc_handle *);

/*	config.c		*/

rc_handle *rc_read_config(char *);
char *rc_conf_str(rc_handle *, char *);
int rc_conf_int(rc_handle *, char *);
SERVER *rc_conf_srv(rc_handle *, char *);
int rc_find_server(rc_handle *, char *, uint32_t *, char *);
void rc_config_free(rc_handle *);
int rc_add_config(rc_handle *, const char *, const char *, const char *, const int);
rc_handle *rc_config_init(rc_handle *);
int test_config(rc_handle *, char *);

/*	dict.c			*/

int rc_read_dictionary(rc_handle *, const char *);
DICT_ATTR *rc_dict_getattr(const rc_handle *, int);
DICT_ATTR *rc_dict_findattr(const rc_handle *, const char *);
DICT_VALUE *rc_dict_findval(const rc_handle *, const char *);
DICT_VENDOR *rc_dict_findvend(const rc_handle *, const char *);
DICT_VENDOR *rc_dict_getvend(const rc_handle *, int);
DICT_VALUE * rc_dict_getval(const rc_handle *, uint32_t, const char *);
void rc_dict_free(rc_handle *);

/*	ip_util.c		*/

struct hostent *rc_gethostbyname(const char *);
struct hostent *rc_gethostbyaddr(const char *, size_t, int);
uint32_t rc_get_ipaddr(char *);
int rc_good_ipaddr(char *);
const char *rc_ip_hostname(uint32_t);
unsigned short rc_getport(int);
int rc_own_hostname(char *, int);
uint32_t rc_own_ipaddress(rc_handle *);
uint32_t rc_own_bind_ipaddress(rc_handle *);
struct sockaddr;
int rc_get_srcaddr(struct sockaddr *, struct sockaddr *);


/*	log.c			*/

void rc_openlog(char *);
void rc_log(int, const char *, ...);

/*	sendserver.c		*/

int rc_send_server(rc_handle *, SEND_DATA *, char *);

/*	util.c			*/

void rc_str2tm(char *, struct tm *);
char *rc_getifname(rc_handle *, char *);
char *rc_getstr(rc_handle *, char *, int);
void rc_mdelay(int);
char *rc_mksid(rc_handle *);
rc_handle *rc_new(void);
void rc_destroy(rc_handle *);
char *rc_fgetln(FILE *, size_t *);
double rc_getctime(void);

/*	env.c			*/

struct env *rc_new_env(int);
void rc_free_env(struct env *);
int rc_add_env(struct env *, char *, char *);
int rc_import_env(struct env *, char **);

/* md5.c			*/

void rc_md5_calc(unsigned char *, unsigned char *, unsigned int);

__END_DECLS

#endif /* FREERADIUS_CLIENT_H */
