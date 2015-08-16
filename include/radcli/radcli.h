/*
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

#ifndef RADCLI_H
#define RADCLI_H

#undef CP_DEBUG
extern unsigned int radcli_debug;
extern void rc_setdebug(int debug);
#ifdef CP_DEBUG
#define		DEBUG(args...)	if(radcli_debug) syslog(args)
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


/* for struct addrinfo and sockaddr_storage */
#include <sys/socket.h>
#include <netdb.h>

/* *INDENT-OFF* */
#ifdef __cplusplus
extern "C" {
#endif
/* *INDENT-ON* */

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

#define AUTH_PASS_LEN		(3 * 16) /* multiple of 16 */
#define AUTH_ID_LEN		64

#define BUFFER_LEN		8192

#define NAME_LENGTH		32

#define MAX_SECRET_LENGTH	(6 * 16) /* MUST be multiple of 16 */

#define VENDOR(x)		(((x) >> 16) & 0xffff)
#define ATTRID(x)		((x) & 0xffff)

#define PW_MAX_MSG_SIZE		4096

/** \enum rc_type Codes to indicate the type of server
 */
typedef enum rc_type {
	AUTH = 0, //!< Request for authentication server
	ACCT = 1  //!< Request for accounting server
} rc_type;

/* defines for config.c */

#define SERVER_MAX 8

#define AUTH_LOCAL_FST	(1<<0)
#define AUTH_RADIUS_FST	(1<<1)
#define AUTH_LOCAL_SND	(1<<2)
#define AUTH_RADIUS_SND	(1<<3)

struct rc_conf;
typedef struct rc_conf rc_handle;

/** \struct server Avoid using this structure directly, it is included for backwards compatibility only.
 * Several of its fields have been deprecated.
 */
typedef struct server {
	int   max;
	char *name[SERVER_MAX];
	uint16_t port[SERVER_MAX];
	char *secret[SERVER_MAX];
	double deadtime_ends[SERVER_MAX]; //!< unused
} SERVER;

/** \enum rc_socket_type Indicate the type of the socket
 */
typedef enum rc_socket_type {
	RC_SOCKET_UDP = 0,	//!< Plain UDP socket
	RC_SOCKET_TLS = 1,	//!< TLS socket
	RC_SOCKET_DTLS = 2	//!< DTLS socket
} rc_socket_type;

#define AUTH_HDR_LEN			20
#define CHAP_VALUE_LENGTH		16

#define PW_AUTH_UDP_PORT		1812
#define PW_ACCT_UDP_PORT		1813

/** \enum rc_attr_type Attribute types
 */
typedef enum rc_attr_type {
	PW_TYPE_STRING=0,	//!< The attribute is a printable string.
	PW_TYPE_INTEGER=1,	//!< The attribute is a 32-bit integer.
	PW_TYPE_IPADDR=2,	//!< The attribute is an IPv4 address in host-byte order.
	PW_TYPE_DATE=3,		//!< The attribute contains a 32-bit number indicating the seconds since epoch.
	PW_TYPE_IPV6ADDR=4,	//!< The attribute is an 128-bit IPv6 address.
	PW_TYPE_IPV6PREFIX=5    //!< The attribute is an IPv6 prefix; the lvalue will indicate its size.
} rc_attr_type;

/** \enum rc_standard_codes Standard RADIUS request codes
 */
typedef enum rc_standard_codes {
	PW_ACCESS_REQUEST=1,
	PW_ACCESS_ACCEPT=2,
	PW_ACCESS_REJECT=3,
	PW_ACCOUNTING_REQUEST=4,
	PW_ACCOUNTING_RESPONSE=5,
	PW_ACCOUNTING_STATUS=6,
	PW_PASSWORD_REQUEST=7,
	PW_PASSWORD_ACK=8,
	PW_PASSWORD_REJECT=9,
	PW_ACCOUNTING_MESSAGE=10,
	PW_ACCESS_CHALLENGE=11,
	PW_STATUS_SERVER=12,
	PW_STATUS_CLIENT=13
} rc_standard_codes;

/** \enum rc_attr_id Standard RADIUS attribute-value pair identifiers
 */
typedef enum rc_attr_id {
	PW_USER_NAME=1,		//!< Its type is string.
	PW_USER_PASSWORD=2,	//!< Its type is string.
	PW_CHAP_PASSWORD=3,	//!< Its type is string.
	PW_NAS_IP_ADDRESS=4,	//!< Its type is ipaddr.
	PW_NAS_PORT=5,		//!< Its type is integer.
	PW_SERVICE_TYPE=6,	//!< Its type is integer.
	PW_FRAMED_PROTOCOL=7,	//!< Its type is integer.
	PW_FRAMED_IP_ADDRESS=8,	//!< Its type is ipaddr.
	PW_FRAMED_IP_NETMASK=9,	//!< Its type is ipaddr.
	PW_FRAMED_ROUTING=10,	//!< Its type is integer.
	PW_FILTER_ID=11,	//!< Its type is string.
	PW_FRAMED_MTU=12,	//!< Its type is integer.
	PW_FRAMED_COMPRESSION=13,	//!< Its type is integer.
	PW_LOGIN_IP_HOST=14,	//!< Its type is ipaddr.
	PW_LOGIN_SERVICE=15,	//!< Its type is integer.
	PW_LOGIN_PORT=16,	//!< Its type is integer.
	PW_OLD_PASSWORD=17,	//!< Its type is string - deprecated.
	PW_REPLY_MESSAGE=18,	//!< Its type is string.
	PW_LOGIN_CALLBACK_NUMBER=19,	//!< Its type is string.
	PW_FRAMED_CALLBACK_ID=20,	//!< Its type is string.
	PW_EXPIRATION=21,		//!< Its type is date - deprecated.
	PW_FRAMED_ROUTE=22,		//!< Its type is string.
	PW_FRAMED_IPX_NETWORK=23,	//!< Its type is integer.
	PW_STATE=24,		//!< Its type is string.
	PW_CLASS=25,		//!< Its type is string.
	PW_VENDOR_SPECIFIC=26,	//!< Its type is string.
	PW_SESSION_TIMEOUT=27,	//!< Its type is integer.
	PW_IDLE_TIMEOUT=28,	//!< Its type is integer.
	PW_TERMINATION_ACTION=29,	//!< Its type is integer.
	PW_CALLED_STATION_ID=30,	//!< Its type is string.
	PW_CALLING_STATION_ID=31,	//!< Its type is string.
	PW_NAS_IDENTIFIER=32,	//!< Its type is string.
	PW_PROXY_STATE=33,	//!< Its type is string.
	PW_LOGIN_LAT_SERVICE=34,//!< Its type is string.
	PW_LOGIN_LAT_NODE=35,	//!< Its type is string.
	PW_LOGIN_LAT_GROUP=36,	//!< Its type is string.
	PW_FRAMED_APPLETALK_LINK=37,	//!< Its type is integer.
	PW_FRAMED_APPLETALK_NETWORK=38,	//!< Its type is integer.
	PW_FRAMED_APPLETALK_ZONE=39,	//!< Its type is string.
	PW_ACCT_STATUS_TYPE=40,		//!< Its type is integer.
	PW_ACCT_DELAY_TIME=41,		//!< Its type is integer.
	PW_ACCT_INPUT_OCTETS=42,	//!< Its type is integer.
	PW_ACCT_OUTPUT_OCTETS=43,	//!< Its type is integer.
	PW_ACCT_SESSION_ID=44,		//!< Its type is string.
	PW_ACCT_AUTHENTIC=45,		//!< Its type is integer.
	PW_ACCT_SESSION_TIME=46,	//!< Its type is integer.
	PW_ACCT_INPUT_PACKETS=47,	//!< Its type is integer.
	PW_ACCT_OUTPUT_PACKETS=48,	//!< Its type is integer.
	PW_ACCT_TERMINATE_CAUSE=49,	//!< Its type is integer.
	PW_ACCT_MULTI_SESSION_ID=50,	//!< Its type is string.
	PW_ACCT_LINK_COUNT=51,		//!< Its type is integer.
	PW_ACCT_INPUT_GIGAWORDS=52,	//!< Its type is integer.
	PW_ACCT_OUTPUT_GIGAWORDS=53,	//!< Its type is integer.
	PW_EVENT_TIMESTAMP=55,		//!< Its type is integer.
	PW_EGRESS_VLANID=56,		//!< Its type is string.
	PW_INGRESS_FILTERS=57,		//!< Its type is integer.
	PW_EGRESS_VLAN_NAME=58,		//!< Its type is string.
	PW_USER_PRIORITY_TABLE=59,	//!< Its type is string.
	PW_CHAP_CHALLENGE=60,		//!< Its type is string.
	PW_NAS_PORT_TYPE=61,		//!< Its type is integer.
	PW_PORT_LIMIT=62,		//!< Its type is integer.
	PW_LOGIN_LAT_PORT=63,		//!< Its type is string.
	PW_TUNNEL_TYPE=64,		//!< Its type is string.
	PW_TUNNEL_MEDIUM_TYPE=65,	//!< Its type is integer.
	PW_TUNNEL_CLIENT_ENDPOINT=66,	//!< Its type is string.
	PW_TUNNEL_SERVER_ENDPOINT=67,	//!< Its type is string.
	PW_ACCT_TUNNEL_CONNECTION=68,	//!< Its type is string.
	PW_TUNNEL_PASSWORD=69,		//!< Its type is string.
	PW_ARAP_PASSWORD=70,		//!< Its type is string.
	PW_ARAP_FEATURES=71,		//!< Its type is string.
	PW_ARAP_ZONE_ACCESS=72,		//!< Its type is integer.
	PW_ARAP_SECURITY=73,		//!< Its type is integer.
	PW_ARAP_SECURITY_DATA=74,	//!< Its type is string.
	PW_PASSWORD_RETRY=75,		//!< Its type is integer.
	PW_PROMPT=76,			//!< Its type is integer.
	PW_CONNECT_INFO=77,		//!< Its type is string.
	PW_CONFIGURATION_TOKEN=78,	//!< Its type is string.
	PW_EAP_MESSAGE=79,		//!< Its type is string.
	PW_MESSAGE_AUTHENTICATOR=80,	//!< Its type is string.
	PW_TUNNEL_PRIVATE_GROUP_ID=81,	//!< Its type is string.
	PW_TUNNEL_ASSIGNMENT_ID=82,	//!< Its type is string.
	PW_TUNNEL_PREFERENCE=83,	//!< Its type is string.
	PW_ARAP_CHALLENGE_RESPONSE=84,	//!< Its type is string.
	PW_ACCT_INTERIM_INTERVAL=85,	//!< Its type is integer.
	PW_ACCT_TUNNEL_PACKETS_LOST=86,	//!< Its type is integer.
	PW_NAS_PORT_ID_STRING=87,	//!< Its type is string.
	PW_FRAMED_POOL=88,		//!< Its type is string.
	PW_CHARGEABLE_USER_IDENTITY=89,	//!< Its type is string.
	PW_CUI=89,			//!< Its type is string.
	PW_TUNNEL_CLIENT_AUTH_ID=90,	//!< Its type is string.
	PW_TUNNEL_SERVER_AUTH_ID=91,	//!< Its type is string.
	PW_NAS_FILTER_RULE=92,		//!< Its type is string.
	PW_ORIGINATING_LINE_INFO=94,	//!< Its type is string.
	PW_NAS_IPV6_ADDRESS=95,		//!< Its type is string.
	PW_FRAMED_INTERFACE_ID=96,	//!< Its type is string.
	PW_FRAMED_IPV6_PREFIX=97,	//!< Its type is string.
	PW_LOGIN_IPV6_HOST=98,		//!< Its type is string.
	PW_FRAMED_IPV6_ROUTE=99,	//!< Its type is string.
	PW_FRAMED_IPV6_POOL=100,	//!< Its type is string.
	PW_ERROR_CAUSE=101,		//!< Its type is integer.
	PW_EAP_KEY_NAME=102,		//!< Its type is string.
	PW_DELEGATED_IPV6_PREFIX=123,	//!< Its type is ipv6prefix.

	PW_FRAMED_IPV6_ADDRESS=168,	//!< Its type is ipaddr6.
	PW_DNS_SERVER_IPV6_ADDRESS=169,	//!< Its type is ipaddr6.
	PW_ROUTE_IPV6_INFORMATION=170,	//!< Its type is ipv6prefix.

	//!< Experimental SIP-specific attributes (draft-sterman-aaa-sip-00.txt etc)

	PW_DIGEST_RESPONSE=206,		//!< Its type is string.
	PW_DIGEST_ATTRIBUTES=207,	//!< Its type is string.
	PW_DIGEST_REALM=1063,		//!< Its type is string.
	PW_DIGEST_NONCE=1064,		//!< Its type is string.
	PW_DIGEST_METHOD=1065,		//!< Its type is string.
	PW_DIGEST_URI=1066,		//!< Its type is string.
	PW_DIGEST_QOP=1067,		//!< Its type is string.
	PW_DIGEST_ALGORITHM=1068,	//!< Its type is string.
	PW_DIGEST_BODY_DIGEST=1069,	//!< Its type is string.
	PW_DIGEST_CNONCE=1070,		//!< Its type is string.
	PW_DIGEST_NONCE_COUNT=1071,	//!< Its type is string.
	PW_DIGEST_USER_NAME=1072,	//!< Its type is string.

	//!< Merit Experimental Extensions
	PW_USER_ID=222,			//!< Its type is string.
	PW_USER_REALM=223		//!< Its type is string.
} rc_attr_id;

/* Integer Translations */

/** \enum rc_service_type RFC2865 Service-Type values
 */
typedef enum rc_service_type {
	PW_LOGIN=1,
	PW_FRAMED=2,
	PW_CALLBACK_LOGIN=3,
	PW_CALLBACK_FRAMED=4,
	PW_OUTBOUND=5,
	PW_ADMINISTRATIVE=6,
	PW_NAS_PROMPT=7,
	PW_AUTHENTICATE_ONLY=8,
	PW_CALLBACK_NAS_PROMPT=9
} rc_service_type;

/** \enum rc_framed_protocol RFC2865 Framed-Protocol values
 */
typedef enum rc_framed_protocol {
	PW_PPP=1,
	PW_SLIP=2,
	PW_ARA=	3,
	PW_GANDALF=4,
	PW_XYLOGICS=5
} rc_framed_protocol;

/** \enum rc_framed_routing_type RFC2865 Framed-Routing values
 */
typedef enum rc_framed_routing_type {
	PW_NONE=0,
	PW_BROADCAST=1,
	PW_LISTEN=2,
	PW_BROADCAST_LISTEN=3
} rc_framed_routing_type;

/** FRAMED COMPRESSION TYPES */

/** \enum rc_framed_comp RFC2865 Framed-Compression values
 */
typedef enum rc_framed_comp {
	PW_COMP_NONE=0,
	PW_VAN_JACOBSON_TCP_IP=1,
	PW_IPX_HEADER_COMPRESSION=2,
	PW_COMP_LZS=3
} rc_framed_comp;

/** \enum rc_login_service_type RFC2865 Login-Service values
 */
typedef enum rc_login_service_type {
	PW_TELNET=0,
	PW_RLOGIN=1,
	PW_TCP_CLEAR=2,
	PW_PORTMASTER=3,
	PW_LAT=4,
	PW_X25_PAD=5,
	PW_X25_T3POS=6
} rc_login_service_type;

/** \enum rc_termination_action RFC2865 Termination-Action values
 */
typedef enum rc_termination_action {
	PW_DEFAULT=0,
	PW_RADIUS_REQUEST=1
} rc_termination_action;


/** \enum rc_acct_status_type RFC2866 Acct-Status-Type values
 */
typedef enum rc_acct_status_type {
	PW_STATUS_START=1,
	PW_STATUS_STOP=2,
	PW_STATUS_ALIVE=3,
	PW_STATUS_MODEM_START=4,
	PW_STATUS_MODEM_STOP=5,
	PW_STATUS_CANCEL=6,
	PW_ACCOUNTING_ON=7,
	PW_ACCOUNTING_OFF=8
} rc_acct_status_type;

/** \enum rc_acct_terminate_cause RFC2866 Acct-Terminate-Cause values
 */
typedef enum rc_acct_terminate_cause {
	PW_USER_REQUEST=1,
	PW_LOST_CARRIER=2,
	PW_LOST_SERVICE=3,
	PW_ACCT_IDLE_TIMEOUT=4,
	PW_ACCT_SESSION_TIMEOUT=5,
	PW_ADMIN_RESET=6,
	PW_ADMIN_REBOOT=7,
	PW_PORT_ERROR=8,
	PW_NAS_ERROR=9,
	PW_NAS_REQUEST=10,
	PW_NAS_REBOOT=11,
	PW_PORT_UNNEEDED=12,
	PW_PORT_PREEMPTED=13,
	PW_PORT_SUSPENDED=14,
	PW_SERVICE_UNAVAILABLE=15,
	PW_CALLBACK=16,
	PW_USER_ERROR=17,
	PW_HOST_REQUEST=18
} rc_acct_terminate_cause;

/** \enum rc_nas_port_type RFC2866 NAS-Port-Type values
 */
typedef enum rc_nas_port_type {
	PW_ASYNC=0,
	PW_SYNC=1,
	PW_ISDN_SYNC=2,
	PW_ISDN_SYNC_V120=3,
	PW_ISDN_SYNC_V110=4,
	PW_VIRTUAL=5
} rc_nas_port_type;

/** \enum rc_acct_auth_type RFC2866 Acct-Authentic values
 */
typedef enum rc_acct_auth_type {
	PW_RADIUS=1,
	PW_LOCAL=2,
	PW_REMOTE=3
} rc_acct_auth_type;

/** \enum rc_vendor_pec --- http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
 */
typedef enum rc_vendor_pec {
  VENDOR_NONE=0,
  VENDOR_MICROSOFT	     = 311,
  VENDOR_ROARING_PENGUIN     = 10055
} rc_vendor_type;

/* Vendor RADIUS attribute-value pairs for MICROSOFT */
enum rc_vendor_attr_microsoft {
  PW_MS_CHAP_CHALLENGE	=	11,	/* string */
  PW_MS_CHAP_RESPONSE	=	1,	/* string */
  PW_MS_CHAP2_RESPONSE	=	25,	/* string */
  PW_MS_CHAP2_SUCCESS	=	26,	/* string */
  PW_MS_MPPE_ENCRYPTION_POLICY=	7,	/* string */
  PW_MS_MPPE_ENCRYPTION_TYPE=	8,	/* string */
  PW_MS_MPPE_ENCRYPTION_TYPES=PW_MS_MPPE_ENCRYPTION_TYPE,
  PW_MS_CHAP_MPPE_KEYS	=	12,	/* string */
  PW_MS_MPPE_SEND_KEY	=	16,	/* string */
  PW_MS_MPPE_RECV_KEY	=	17,	/* string */
  PW_MS_PRIMARY_DNS_SERVER=	28,	/* ipaddr */
  PW_MS_SECONDARY_DNS_SERVER=	29,	/* ipaddr */
  PW_MS_PRIMARY_NBNS_SERVER=	30,	/* ipaddr */
  PW_MS_SECONDARY_NBNS_SERVER=	31,	/* ipaddr */
};

/* Vendor RADIUS attribute-value pairs for Roaring Penguin: Bandwidth bit rate limits */
enum rc_vendor_attr_roaringpenguin {
  PW_RP_UPSTREAM_LIMIT        =1,  /* integer */
  PW_RP_DOWNSTREAM_LIMIT      =2,  /* integer */
};

/* PROHIBIT PROTOCOL */
#define PW_DUMB			0	//!< 1 and 2 are defined in FRAMED PROTOCOLS.
#define PW_AUTH_ONLY		3
#define PW_ALL			255

/* Server data structures */

typedef struct dict_attr
{
	char              name[NAME_LENGTH + 1];	//!< attribute name.
	int               value;			//!< attribute index.
	rc_attr_type      type;				//!< string, int, etc..
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
	char               vendorname[NAME_LENGTH +1];
	int                vendorpec;
	struct dict_vendor *next;
} DICT_VENDOR;

/* don't change this, as it has to be the same as in the Merit radiusd code */
#define MGMT_POLL_SECRET	"Hardlyasecret" //!< Default for Merit radiusd

/** \enum rc_send_status Return codes for rc_send_server()
 */
typedef enum rc_send_status {
	BADRESPID_RC=-3,
	BADRESP_RC=-2,
	ERROR_RC=-1,
	OK_RC=0,
	TIMEOUT_RC=1,
	REJECT_RC=2
} rc_send_status;


# define AUTH_STRING_LEN		253	 /* maximum of 253 */

/** \struct rc_value_pair Avoid using this structure directly. Use the rc_avpair_get_ functions.
 */
typedef struct rc_value_pair
{
	char               name[NAME_LENGTH + 1];	//!< attribute name if known.
	unsigned           attribute;			//!< attribute numeric value of type rc_attr_id.
	rc_attr_type	   type;			//!< attribute type.
	uint32_t           lvalue;			//!< attribute value if type is PW_TYPE_INTEGER, PW_TYPE_DATE or PW_TYPE_IPADDR.
	char               strvalue[AUTH_STRING_LEN + 1]; //!< contains attribute value in other cases.
	struct rc_value_pair *next;
	char		   pad[32];			//!< unused pad
} VALUE_PAIR;

typedef struct send_data /* Used to pass information to sendserver() function */
{
	uint8_t        code;		//!< RADIUS packet code.
	uint8_t        seq_nbr;		//!< Packet sequence number.
	char           *server;		//!< Name/addrress of RADIUS server.
	int            svc_port;	//!< RADIUS protocol destination port.
	char           *secret;		//!< Shared secret of RADIUS server.
	int            timeout;		//!< Session timeout in seconds.
	int            retries;
	VALUE_PAIR     *send_pairs;     //!< More a/v pairs to send.
	VALUE_PAIR     *receive_pairs;  //!< Where to place received a/v pairs.
} SEND_DATA;

#define AUTH_VECTOR_LEN		16

struct rc_aaa_ctx_st;
typedef struct rc_aaa_ctx_st RC_AAA_CTX;

#ifndef MIN
#define MIN(a, b)     ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)     ((a) > (b) ? (a) : (b))
#endif

#ifndef PATH_MAX
#define PATH_MAX	1024
#endif

#define ENV_SIZE	128

/** @} */

/*!\mainpage
 * \section Introduction
 *
 * RADIUS stands for Remote Authentication Dial In User Service
 * and is a protocol for carrying authentication, authorization,
 * and configuration information between a Network Access Server
 * (NAS) which desires to authenticate its links and a shared
 * Authentication Server.  The protocol originally was designed
 * by the terminal server manufacturer Livingston for use with
 * their Portmaster series of terminal servers.  Since then it
 * has been implemented by a lot of other vendors and it is also
 * on it's way to become a Internet Standard.
 *
 * This library implements the needed standards for the client side
 * of the protocol, in a way the minimum configuration and modification
 * is needed for the clients. The approach is to rely on a small
 * external radius configuration file, read using rc_read_config(),
 * and then using rc_auth() or rc_acct() to communicate with the server.
 * Configuration options (like using TLS or so) are then set when
 * parsing the file, simplifying application configuration and administration.
 *
 * Alternative operation without a configuration file is also possible, see
 * rc_add_config().
 *
 * Check radexample.c for a functional example.
 *
 */

/** \example radexample.c
 * This is an example of how to use the radcli API.
 */

/** \example radiusclient-tls.conf
 * This is an configuration file with TLS.
 */

/** \example radiusclient.conf
 * This is an example configuration file listing the available options.
 */

/** \example servers
 * This is an example servers configuration file.
 */

/** \example servers-tls
 * This is an example servers configuration file with TLS PSK.
 */

/* avpair.c */

  VALUE_PAIR *rc_avpair_add (rc_handle const *rh, VALUE_PAIR **list, int attrid, void const *pval, int len, int vendorpec);
  int rc_avpair_assign (VALUE_PAIR *vp, void const *pval, int len);
  VALUE_PAIR *rc_avpair_new (rc_handle const *rh, int attrid, void const *pval, int len, int vendorpec);
  VALUE_PAIR *rc_avpair_gen(rc_handle const *rh, VALUE_PAIR *pair, unsigned char const *ptr,
			  int length, int vendorpec);
VALUE_PAIR *rc_avpair_get (VALUE_PAIR *vp, int attrid, int vendorpec);
VALUE_PAIR *rc_avpair_copy(VALUE_PAIR *p);
void rc_avpair_insert(VALUE_PAIR **a, VALUE_PAIR *p, VALUE_PAIR *b);
void rc_avpair_free (VALUE_PAIR *pair);
int rc_avpair_parse (rc_handle const *rh, char const *buffer, VALUE_PAIR **first_pair);
int rc_avpair_tostr (rc_handle const *rh, VALUE_PAIR *pair, char *name, int ln, char *value, int lv);
char *rc_avpair_log(rc_handle const *rh, VALUE_PAIR *pair, char *buf, size_t buf_len);
VALUE_PAIR *rc_avpair_next(VALUE_PAIR *t);

int rc_avpair_get_uint32 (VALUE_PAIR *vp, uint32_t *res);
int rc_avpair_get_in6 (VALUE_PAIR *vp, struct in6_addr *res, unsigned *prefix);
int rc_avpair_get_raw (VALUE_PAIR *vp, char **res, unsigned *res_size);
void rc_avpair_get_attr (VALUE_PAIR *vp, unsigned *type, unsigned *id);

/* buildreq.c */

void rc_buildreq(rc_handle const *rh, SEND_DATA *data, int code, char *server, unsigned short port,
		 char *secret, int timeout, int retries);
int rc_auth(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send,
            VALUE_PAIR **received, char *msg);
int rc_auth_proxy(rc_handle *rh, VALUE_PAIR *send, VALUE_PAIR **received, char *msg);
int rc_acct(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send);
int rc_acct_proxy(rc_handle *rh, VALUE_PAIR *send);
int rc_check(rc_handle *rh, char *host, char *secret, unsigned short port, char *msg);

int rc_aaa(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   char *msg, int add_nas_port, rc_standard_codes request_type);
int rc_aaa_ctx(rc_handle *rh, RC_AAA_CTX **ctx, uint32_t client_port, VALUE_PAIR *send,
               VALUE_PAIR **received,
               char *msg, int add_nas_port, rc_standard_codes request_type);
int rc_aaa_ctx_server(rc_handle *rh, RC_AAA_CTX **ctx, SERVER *aaaserver,
                      rc_type type, uint32_t client_port,
                      VALUE_PAIR *send, VALUE_PAIR **received,
                      char *msg, int add_nas_port, rc_standard_codes request_type);

/* config.c */

int rc_add_config(rc_handle *rh, char const *option_name, char const *option_val, char const *source, int line);
rc_handle *rc_config_init(rc_handle *rh);
rc_handle *rc_read_config(char const *filename);
char *rc_conf_str(rc_handle const *rh, char const *optname);
int rc_conf_int(rc_handle const *rh, char const *optname);
SERVER *rc_conf_srv(rc_handle const *rh, char const *optname);
int rc_test_config(rc_handle *rh, char const *filename);
int rc_find_server_addr (rc_handle const *rh, char const *server_name,
                         struct addrinfo** info, char *secret, rc_type type);
void rc_config_free(rc_handle *rh);
rc_handle *rc_new(void);
void rc_destroy(rc_handle *rh);
rc_socket_type rc_get_socket_type(rc_handle * rh);

#define test_config rc_test_config

/* dict.c */

int rc_read_dictionary (rc_handle *rh, char const *filename);
DICT_ATTR *rc_dict_getattr(rc_handle const *rh, int attribute);
DICT_ATTR *rc_dict_findattr(rc_handle const *rh, char const *attrname);
DICT_VALUE *rc_dict_findval(rc_handle const *rh, char const *valname);
DICT_VENDOR *rc_dict_findvend(rc_handle const *rh, char const *vendorname);
DICT_VENDOR *rc_dict_getvend (rc_handle const *rh, int vendorpec);
DICT_VALUE *rc_dict_getval(rc_handle const *rh, uint32_t value, char const *attrname);
void rc_dict_free(rc_handle *rh);

/*	tls.c			*/

int rc_tls_fd(rc_handle * rh);
int rc_check_tls(rc_handle * rh);

/* util.c */
char *rc_mksid __P((void));

/* ip_util.c */

unsigned short rc_getport(int type);
int rc_own_hostname(char *hostname, int len);
struct sockaddr;
int rc_get_srcaddr(struct sockaddr *lia, const struct sockaddr *ria);

/* log.c */

void rc_openlog(char const *ident);
/* to provide compatibility with any old applications that may have
 * been using rc_log() */
#define rc_log syslog

/* sendserver.c */

int rc_send_server (rc_handle *rh, SEND_DATA *data, char *msg,
                    rc_type type);

/* aaa_ctx.c */
void rc_aaa_ctx_free(RC_AAA_CTX *ctx);
const char *rc_aaa_ctx_get_secret(RC_AAA_CTX *ctx);
const void *rc_aaa_ctx_get_vector(RC_AAA_CTX *ctx);

/* *INDENT-OFF* */
#ifdef __cplusplus
}
#endif
/* *INDENT-ON* */

#endif /* RADCLI_H */
