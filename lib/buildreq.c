/*
 * Copyright (C) 1995,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */
#include <config.h>
#include <includes.h>
#include <radcli/radcli.h>
#include "util.h"

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions 
 *
 * @{
 */

/** Generates a random ID
 *
 * @return the random ID.
 */
static unsigned char rc_get_id()
{
	return (unsigned char)(random() & UCHAR_MAX);
}

/** Build a skeleton RADIUS request using information from the config file
 *
 * @param rh a handle to parsed configuration.
 * @param data a pointer to a SEND_DATA structure.
 * @param code one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @param server the name of the server.
 * @param port the server's port number.
 * @param secret the secret used by the server.
 * @param timeout the timeout in seconds of a message.
 * @param retries the number of retries.
 */
void rc_buildreq(rc_handle const *rh, SEND_DATA *data, int code, char *server, unsigned short port,
		 char *secret, int timeout, int retries)
{
	data->server = server;
	data->secret = secret;
	data->svc_port = port;
	data->seq_nbr = rc_get_id();
	data->timeout = timeout;
	data->retries = retries;
	data->code = code;
}

/** Builds an authentication/accounting request for port id client_port with the value_pairs send and submits it to a server.
 * This function keeps its state in ctx after a successful operation. It can be deallocated using
 * rc_aaa_ctx_free().
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL it will contain the context of the request; Its initial value should be NULL and it must be released using rc_aaa_ctx_free().
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @param add_nas_port if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return received value_pairs in received, messages from the server in msg and OK_RC (0) on success, negative
 *	on failure as return value.
 */
int rc_aaa_ctx(rc_handle *rh, RC_AAA_CTX **ctx, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   	char *msg, int add_nas_port, rc_standard_codes request_type)
{
	SERVER		*aaaserver;
	rc_type		type;

	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS ||
	    request_type != PW_ACCOUNTING_REQUEST) {
		aaaserver = rc_conf_srv(rh, "authserver");
		type = AUTH;
	} else {
		aaaserver = rc_conf_srv(rh, "acctserver");
		type = ACCT;
	}
	if (aaaserver == NULL)
		return ERROR_RC;

        return rc_aaa_ctx_server(rh, ctx, aaaserver, type,
                                 client_port, send, received, msg,
                                 add_nas_port, request_type);
}

/** Builds an authentication/accounting request for port id client_port with the value_pairs send and submits it to a specified server.
 * This function keeps its state in ctx after a successful operation. It can be deallocated using
 * rc_aaa_ctx_free().
 *
 * @param rh a handle to parsed configuration.
 * @param ctx if non-NULL it will contain the context of the request; Its initial value should be NULL and it must be released using rc_aaa_ctx_free().
 * @param aaaserver a non-NULL SERVER to send the message to.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @param add_nas_port if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return received value_pairs in received, messages from the server in msg and OK_RC (0) on success, negative
 *	on failure as return value.
 */
int rc_aaa_ctx_server(rc_handle *rh, RC_AAA_CTX **ctx, SERVER *aaaserver,
                      rc_type type,
                      uint32_t client_port,
                      VALUE_PAIR *send, VALUE_PAIR **received,
                      char *msg, int add_nas_port, rc_standard_codes request_type)
{
	SEND_DATA       data;
	VALUE_PAIR	*adt_vp = NULL;
	int		result;
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");
	double		start_time = 0;
	double		now = 0;
	time_t		dtime;
        int             servernum;

	data.send_pairs = send;
	data.receive_pairs = NULL;

        /*
         * if there is more than zero servers, then divide waiting time
         * among all the servers.
         */
        if(aaaserver->max > 0) {
          if(timeout > 0) {
            timeout = (timeout+1) / aaaserver->max;
          }
          if(retries > 0) {
            retries = (retries+1) / aaaserver->max;
          }
        }

	if (add_nas_port != 0 && rc_avpair_get(data.send_pairs, PW_NAS_PORT, 0) == NULL) {
		/*
		 * Fill in NAS-Port
		 */
		if (rc_avpair_add(rh, &(data.send_pairs), PW_NAS_PORT,
		    &client_port, 0, 0) == NULL)
			return ERROR_RC;
	}

	if (request_type == PW_ACCOUNTING_REQUEST) {
		/*
		 * Fill in Acct-Delay-Time
		 */
		dtime = 0;
		now = rc_getctime();
		adt_vp = rc_avpair_get(data.send_pairs, PW_ACCT_DELAY_TIME, 0);
		if (adt_vp == NULL) {
			adt_vp = rc_avpair_add(rh, &(data.send_pairs),
			    PW_ACCT_DELAY_TIME, &dtime, 0, 0);
			if (adt_vp == NULL)
				return ERROR_RC;
			start_time = now;
		} else {
			start_time = now - adt_vp->lvalue;
		}
	}

	if (data.receive_pairs != NULL) {
		rc_avpair_free(data.receive_pairs);
		data.receive_pairs = NULL;
	}

        servernum=0;
        do {
          rc_buildreq(rh, &data, request_type, aaaserver->name[servernum],
                      aaaserver->port[servernum],
                      aaaserver->secret[servernum], timeout, retries);

          if (request_type == PW_ACCOUNTING_REQUEST) {
            dtime = rc_getctime() - start_time;
            rc_avpair_assign(adt_vp, &dtime, 0);
          }

          result = rc_send_server_ctx (rh, ctx, &data, msg, type);

          if (request_type != PW_ACCOUNTING_REQUEST) {
            *received = data.receive_pairs;
          } else {
            rc_avpair_free(data.receive_pairs);
          }

          if(result == OK_RC) {
            DEBUG(LOG_INFO,
                  "servernum %u returned success", servernum);
            return result;
          }

          //rc_log(LOG_ERR,
          //       "servernum %u returned error: %d", servernum, result);
          servernum++;
        } while(servernum < aaaserver->max && result == TIMEOUT_RC);

	return result;
}

/** Builds an authentication/accounting request for port id client_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @param add_nas_port if non-zero it will include PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., PW_ACCESS_REQUEST).
 * @return received value_pairs in received, messages from the server in msg and OK_RC (0) on success, negative
 *	on failure as return value.
 */
int rc_aaa(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   char *msg, int add_nas_port, rc_standard_codes request_type)
{
	return rc_aaa_ctx(rh, NULL, client_port, send, received, msg, add_nas_port, request_type);
}

/** Builds an authentication request for port id client_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @return received value_pairs in received, messages from the server in msg (if non-NULL),
 *	and OK_RC (0) on success, negative on failure as return value.
 */
int rc_auth(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
    char *msg)
{

	return rc_aaa(rh, client_port, send, received, msg, 1, PW_ACCESS_REQUEST);
}

/** Builds an authentication request for proxying
 *
 * Builds an authentication request with the value_pairs send and submits it to a server.
 * Works for a proxy; does not add IP address, and does does not rely on config file.
 *
 * @param rh a handle to parsed configuration.
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of
 *	any PW_REPLY_MESSAGE received.
 * @return received value_pairs in received, messages from the server in msg (if non-NULL)
 *	and OK_RC (0) on success, negative on failure as return value.
 */
int rc_auth_proxy(rc_handle *rh, VALUE_PAIR *send, VALUE_PAIR **received, char *msg)
{
	return rc_aaa(rh, 0, send, received, msg, 0, PW_ACCESS_REQUEST);
}

/** Builds an accounting request for port id client_port with the value_pairs at send
 *
 * @note NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled in by this function, the rest has to be supplied.
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return received value_pairs in received, and OK_RC (0) on success, negative on failure as return value.
 */
int rc_acct(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send)
{
	return rc_aaa(rh, client_port, send, NULL, NULL, 1, PW_ACCOUNTING_REQUEST);
}

/** Builds an accounting request with the value_pairs at send
 *
 * @param rh a handle to parsed configuration.
 * @param send a VALUE_PAIR array of values (e.g., PW_USER_NAME).
 * @return OK_RC (0) on success, negative on failure as return value.
 */
int rc_acct_proxy(rc_handle *rh, VALUE_PAIR *send)
{

	return rc_aaa(rh, 0, send, NULL, NULL, 0, PW_ACCOUNTING_REQUEST);
}

/** Asks the server hostname on the specified port for a status message
 *
 * @param rh a handle to parsed configuration.
 * @param host the name of the server.
 * @param secret the secret used by the server.
 * @param port the server's port number.
 * @param msg must be an array of PW_MAX_MSG_SIZE or NULL; will contain the concatenation of any
 *	PW_REPLY_MESSAGE received.
 * @return OK_RC (0) on success, negative on failure as return value.
 */
int rc_check(rc_handle *rh, char *host, char *secret, unsigned short port, char *msg)
{
	SEND_DATA       data;
	int		result;
	uint32_t	service_type;
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");
	rc_type		type;

	data.send_pairs = data.receive_pairs = NULL;

	if (rh->so_type == RC_SOCKET_TLS || rh->so_type == RC_SOCKET_DTLS)
		type = AUTH;
	else
		type = ACCT;

	/*
	 * Fill in Service-Type
	 */

	service_type = PW_ADMINISTRATIVE;
	rc_avpair_add(rh, &(data.send_pairs), PW_SERVICE_TYPE, &service_type, 0, 0);

	rc_buildreq(rh, &data, PW_STATUS_SERVER, host, port, secret, timeout, retries);
	result = rc_send_server (rh, &data, msg, type);

	rc_avpair_free(data.receive_pairs);

	return result;
}
/** @} */
