/*
 * $Id: buildreq.c,v 1.17 2010/02/04 10:27:09 aland Exp $
 *
 * Copyright (C) 1995,1997 Lars Fenneberg
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 * If the file is missing contact me at lf@elemental.net
 * and I'll send you a copy.
 *
 */
#include <config.h>
#include <includes.h>
#include <freeradius-client.h>
#include "util.h"

/** Build a skeleton RADIUS request using information from the config file
 *
 * @param rh a handle to parsed configuration.
 * @param data a pointer to a #SEND_DATA structure.
 * @param code one of standard RADIUS codes (e.g., %PW_ACCESS_REQUEST).
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

/** Generates a random ID
 *
 * @return the random ID.
 */
unsigned char rc_get_id()
{
	return (unsigned char)(random() & UCHAR_MAX);
}

/** Builds an authentication/accounting request for port id client_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of any
 *	%PW_REPLY_MESSAGE received.
 * @param add_nas_port if non-zero it will include %PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., %PW_ACCESS_REQUEST).
 * @return received value_pairs in received, messages from the server in msg and %OK_RC (0) on success, negative
 *	on failure as return value.
 */
int rc_aaa(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   char *msg, int add_nas_port, int request_type)
{
	SEND_DATA       data;
	VALUE_PAIR	*adt_vp = NULL;
	int		result;
	int		i, skip_count;
	SERVER		*aaaserver;
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");
	int		radius_deadtime = rc_conf_int(rh, "radius_deadtime");
	double		start_time = 0;
	double		now = 0;
	time_t		dtime;
	unsigned	type;

	if (request_type != PW_ACCOUNTING_REQUEST) {
		aaaserver = rc_conf_srv(rh, "authserver");
		type = AUTH;
	} else {
		aaaserver = rc_conf_srv(rh, "acctserver");
		type = ACCT;
	}
	if (aaaserver == NULL)
		return ERROR_RC;

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (add_nas_port != 0) {
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

	skip_count = 0;
	result = ERROR_RC;
	for (i=0; (i < aaaserver->max) && (result != OK_RC) && (result != REJECT_RC)
	    ; i++, now = rc_getctime())
	{
		if (aaaserver->deadtime_ends[i] != -1 &&
		    aaaserver->deadtime_ends[i] > start_time) {
			skip_count++;
			continue;
		}
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}
		rc_buildreq(rh, &data, request_type, aaaserver->name[i],
		    aaaserver->port[i], aaaserver->secret[i], timeout, retries);

		if (request_type == PW_ACCOUNTING_REQUEST) {
			dtime = now - start_time;
			rc_avpair_assign(adt_vp, &dtime, 0);
		}

		result = rc_send_server (rh, &data, msg, type);
		if (result == TIMEOUT_RC && radius_deadtime > 0)
			aaaserver->deadtime_ends[i] = start_time + (double)radius_deadtime;
	}
	if (result == OK_RC || result == REJECT_RC || skip_count == 0)
		goto exit;

	result = ERROR_RC;
	for (i=0; (i < aaaserver->max) && (result != OK_RC) && (result != REJECT_RC)
	    ; i++)
	{
		if (aaaserver->deadtime_ends[i] == -1 ||
		    aaaserver->deadtime_ends[i] <= start_time) {
			continue;
		}
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}
		rc_buildreq(rh, &data, request_type, aaaserver->name[i],
		    aaaserver->port[i], aaaserver->secret[i], timeout, retries);

		if (request_type == PW_ACCOUNTING_REQUEST) {
			dtime = rc_getctime() - start_time;
			rc_avpair_assign(adt_vp, &dtime, 0);
		}

		result = rc_send_server (rh, &data, msg, type);
		if (result != TIMEOUT_RC)
			aaaserver->deadtime_ends[i] = -1;
	}

exit:
	if (request_type != PW_ACCOUNTING_REQUEST) {
		*received = data.receive_pairs;
	} else {
		rc_avpair_free(data.receive_pairs);
	}

	return result;
}

/** Builds an authentication/accounting request for port id client_port with the value_pairs send and submits it to a server;
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of any
 *	%PW_REPLY_MESSAGE received.
 * @param add_nas_port if non-zero it will include %PW_NAS_PORT in sent pairs.
 * @param request_type one of standard RADIUS codes (e.g., %PW_ACCESS_REQUEST).
 * @param ctx the context which shall be passed to the asynchronous receive function;
 * @return OK_RC on send success and populated @ctx and socket in @ctx->sockfd;
 *	resume shall be called
 *		   ERROR_RC on failure
 * if upper layer application detects timeout on sockfd it shall call this function
 * again with the same @ctx
 */

int rc_aaa_async (rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	   char *msg, int add_nas_port, int request_type, SEND_CONTEXT **ctx)
{
	SEND_DATA       data;
	VALUE_PAIR	*adt_vp = NULL;
	int		result;
	int		i, skip_count;
	int		resume_send = 0;
	SERVER		*aaaserver;
	int		radius_deadtime = rc_conf_int(rh, "radius_deadtime");
	double		start_time = 0;
	double		now = 0;
	time_t		dtime;
	unsigned	type;

	if (*ctx != NULL) {
		/* if here it means another destination is tried */
		aaaserver = (*ctx)->aaaserver;
		data = *((*ctx)->data);
		skip_count = (*ctx)->skip_count;

		/* resume from the next destination */
		(*ctx)->idx++;

		if (!(*ctx)->again) {
			if (radius_deadtime > 0)
				aaaserver->deadtime_ends[(*ctx)->idx] =
					(*ctx)->start_time + radius_deadtime;
		}
	} else {
		if (request_type != PW_ACCOUNTING_REQUEST) {
			aaaserver = rc_conf_srv(rh, "authserver");
			type = AUTH;
		} else {
			aaaserver = rc_conf_srv(rh, "acctserver");
			type = ACCT;
		}
		if (aaaserver == NULL)
			return ERROR_RC;

		data.send_pairs = send;
		data.receive_pairs = NULL;

		if (add_nas_port != 0) {
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

		if ((*ctx = malloc(sizeof(SEND_CONTEXT) + sizeof(SEND_DATA))) == NULL) {
			rc_log(LOG_ERR, "rc_aaa_async: out of memory\n");
			return -1;
		}
		memset(*ctx, '\0', sizeof(SEND_CONTEXT) + sizeof(SEND_DATA));

		(*ctx)->rh				= rh;
		(*ctx)->data			= (SEND_DATA *)(*ctx + 1);
		(*ctx)->msg				= msg;
		(*ctx)->idx				= 0;

		skip_count = 0;
	}

	if ((*ctx)->again != 1) {
		result = ERROR_RC;
		for (i = (*ctx)->idx; (i < aaaserver->max) && (result != OK_RC);
				i++, now = rc_getctime()) {
			if (aaaserver->deadtime_ends[i] != -1 &&
			    aaaserver->deadtime_ends[i] > start_time) {
				skip_count++;
				continue;
			}

			if (data.receive_pairs != NULL) {
				rc_avpair_free(data.receive_pairs);
				data.receive_pairs = NULL;
			}

			rc_buildreq(rh, &data, request_type, aaaserver->name[i],
				aaaserver->port[i], aaaserver->secret[i], 0, 0);
			(*(*ctx)->data)			= data;

			if (request_type == PW_ACCOUNTING_REQUEST) {
				dtime = now - start_time;
				rc_avpair_assign(adt_vp, &dtime, 0);
			}

			result = rc_send_server_async (rh, &data, msg, type, ctx);
			if (result == OK_RC) {
				(*ctx)->idx = i;
				(*ctx)->skip_count = skip_count;
			}
		}

		if (result == OK_RC) {
			(*ctx)->type			= type;
			(*ctx)->start_time		= start_time;
			(*ctx)->adt_vp			= adt_vp;
			(*ctx)->aaaserver		= aaaserver;

			return result;
		}

		if (skip_count == 0) {
			goto out_err;
		}

		(*ctx)->again = 1;
		(*ctx)->idx = 0;
	}

	result = ERROR_RC;
	for (i = (*ctx)->idx; (i < aaaserver->max) && (result != OK_RC); i++) {
		if (aaaserver->deadtime_ends[i] != -1 ||
			aaaserver->deadtime_ends[i] <= start_time) {
			continue;
		}

		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}

		rc_buildreq(rh, &data, request_type, aaaserver->name[i],
			aaaserver->port[i], aaaserver->secret[i], 0, 0);
		(*(*ctx)->data)			= data;

		if (request_type == PW_ACCOUNTING_REQUEST) {
			dtime = now - start_time;
			rc_avpair_assign(adt_vp, &dtime, 0);
		}

		result = rc_send_server_async (rh, &data, msg, type, ctx);
		if (result == OK_RC)
			(*ctx)->idx = i;

		if (result != OK_RC)
			aaaserver->deadtime_ends[i] = -1;

	}

	if (result == OK_RC) {
		(*ctx)->type			= type;
		(*ctx)->start_time		= start_time;
		(*ctx)->adt_vp			= adt_vp;
		(*ctx)->aaaserver		= aaaserver;

		return result;
	}

out_err:
	/* got through all entries; none OK; free ctx and exit*/
	free(*ctx);
	*ctx = NULL;

	return result;
}

/* Receives the reply from the server
 * @param ctx the context that was set by rc_aaa_async function
 * @param received an allocated array of received values.
 * @return NULL @ctx and OK_RC(0) on success
 * BLOCK_RC(3) and not NULL @ctx on EWOULDBLOCK/EAGAIN
 * NULL @ctx on any other failure return code
 */
/*rc_receive async name*/
int rc_aaa_receive_async(SEND_CONTEXT **ctx, VALUE_PAIR **received, int request_type)
{
	int i;
	int		result;

	if (*ctx == NULL) {
		rc_log(LOG_ERR, "rc_aaa_async: context is null");
		return ERROR_RC;
	}

	result = rc_receive_async(ctx);

	if (result != READBLOCK_RC) {
		i = (*ctx)->idx;
		(*ctx)->aaaserver->deadtime_ends[i] = -1;
		if (request_type != PW_ACCOUNTING_REQUEST) {
			*received = (*ctx)->data->receive_pairs;
		} else {
			rc_avpair_free((*ctx)->data->receive_pairs);
		}
	} else {
		free(*ctx);
		*ctx = NULL;
	}

	return result;
}

/** Builds an authentication request for port id client_port with the value_pairs send and submits it to a server
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of any
 *	%PW_REPLY_MESSAGE received.
 * @return received value_pairs in @received, messages from the server in msg (if non-NULL),
 *	and %OK_RC (0) on success, negative on failure as return value.
 */
int rc_auth(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
    char *msg)
{

	return rc_aaa(rh, client_port, send, received, msg, 1, PW_ACCESS_REQUEST);
}

/* Builds an authentication request for port id client_port with the value_pairs send and submits it to a server
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of any
 *	%PW_REPLY_MESSAGE received.
 * @param ctx the context which shall be passed to the asynchronous receive function.
 * @return received value_pairs in @received, messages from the server in msg (if non-NULL),
 * context for resume function in @ctx, sockfd in @ctx->sockfd and %OK_RC (0) on success
 * negative on failure as return value.
 * on failure an error code is called; function shall not be called again
 * if upper layer application detects timeout on socket it shall call this function
 * again with same context
 */
int rc_auth_async(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
    char *msg, SEND_CONTEXT **ctx)
{

	return rc_aaa_async(rh, client_port, send, received, msg, 1, PW_ACCESS_REQUEST, ctx);
}

/* Asynchronously receives the authentification reply from the server
 * @param ctx the context that was set by rc_auth_async function
 * @param received an allocated array of received values.
 * @return received value_pairs in @received OK_RC(0) on success;
 *			BLOCK_RC and not null @ctx on EWOULDBLOCK/EAGAIN
 *			any other rc means failure or rejection
 */
int rc_auth_resume(SEND_CONTEXT **ctx, VALUE_PAIR ** received) {
	return rc_aaa_receive_async(ctx, received, PW_ACCESS_REQUEST);
}

/** Builds an authentication request for proxying
 *
 * Builds an authentication request with the value_pairs send and submits it to a server.
 * Works for a proxy; does not add IP address, and does does not rely on config file.
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param received an allocated array of received values.
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of
 *	any %PW_REPLY_MESSAGE received.
 * @return received value_pairs in @received, messages from the server in msg (if non-NULL)
 *	and %OK_RC (0) on success, negative on failure as return value.
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
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @return received value_pairs in @received, and %OK_RC (0) on success, negative on failure as return value.
 */
int rc_acct(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send)
{
	return rc_aaa(rh, client_port, send, NULL, NULL, 1, PW_ACCOUNTING_REQUEST);
}

/** Builds an accounting request for port id client_port with the value_pairs at send
 *
 * @note NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled in by this function, the rest has to be supplied.
 *
 * @param rh a handle to parsed configuration.
 * @param client_port the client port number to use (may be zero to use any available).
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @param ctx the context which shall be passed to the asynchronous receive function;
 *@return received value_pairs in @received, messages from the server in msg (if non-NULL),
 * context for resume function in @ctx, sockfd in @ctx->sockfd and %OK_RC (0) on success
 * negative on failure as return value.
 * on failure an error code is called; function shall not be called again
 * if upper layer application detects timeout on socket it shall call this function
 * again with same context

 */
int rc_acct_async(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, SEND_CONTEXT **ctx) {
	return rc_aaa_async(rh, client_port, send, NULL, NULL, 1, PW_ACCOUNTING_REQUEST, ctx);
}

/* Asynchronously receives the accounting reply from the server
 * @param ctx the context that was set by rc_acct_resume function
 * @return NULL @ctx and OK_RC(0) on success;
 *		   BLOCK_RC and not NULL @ctx on EWOULDBLOCK/EAGAIN
 *		   any other rc means failure
 *
 */
int rc_acct_resume(SEND_CONTEXT **ctx) {
	return rc_aaa_receive_async(ctx, NULL, PW_ACCOUNTING_REQUEST);
}

/** Builds an accounting request with the value_pairs at send
 *
 * @param rh a handle to parsed configuration.
 * @param send a #VALUE_PAIR array of values (e.g., %PW_USER_NAME).
 * @return %OK_RC (0) on success, negative on failure as return value.
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
 * @param msg must be an array of %PW_MAX_MSG_SIZE or %NULL; will contain the concatenation of any
 *	%PW_REPLY_MESSAGE received.
 * @return %OK_RC (0) on success, negative on failure as return value.
 */
int rc_check(rc_handle *rh, char *host, char *secret, unsigned short port, char *msg)
{
	SEND_DATA       data;
	int		result;
	uint32_t		service_type;
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");

	data.send_pairs = data.receive_pairs = NULL;

	/*
	 * Fill in Service-Type
	 */

	service_type = PW_ADMINISTRATIVE;
	rc_avpair_add(rh, &(data.send_pairs), PW_SERVICE_TYPE, &service_type, 0, 0);

	rc_buildreq(rh, &data, PW_STATUS_SERVER, host, port, secret, timeout, retries);
	result = rc_send_server (rh, &data, msg, ACCT);

	rc_avpair_free(data.receive_pairs);

	return result;
}
