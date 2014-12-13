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

unsigned char rc_get_id();

/*
 * Function: rc_buildreq
 *
 * Purpose: builds a skeleton RADIUS request using information from the
 * 	    config file.
 *
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

/*
 * Function: rc_get_id
 *
 * Purpose: generate random id
 *
 */

unsigned char rc_get_id()
{
	return (unsigned char)(random() & UCHAR_MAX);
}

/*
 * Function: rc_aaa
 *
 * Purpose: Builds an authentication/accounting request for port id client_port
 *	    with the value_pairs send and submits it to a server
 *
 * Returns: received value_pairs in received, messages from the server in msg
 *	    and 0 on success, negative on failure as return value
 *
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

	if (request_type != PW_ACCOUNTING_REQUEST) {
		aaaserver = rc_conf_srv(rh, "authserver");
	} else {
		aaaserver = rc_conf_srv(rh, "acctserver");
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
	for (i=0; (i < aaaserver->max) && (result != OK_RC) && (result != BADRESP_RC)
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

		result = rc_send_server (rh, &data, msg);
		if (result == TIMEOUT_RC && radius_deadtime > 0)
			aaaserver->deadtime_ends[i] = start_time + (double)radius_deadtime;
	}
	if (result == OK_RC || result == BADRESP_RC || skip_count == 0)
		goto exit;

	result = ERROR_RC;
	for (i=0; (i < aaaserver->max) && (result != OK_RC) && (result != BADRESP_RC)
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

		result = rc_send_server (rh, &data, msg);
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

/*
 * Function: rc_auth
 *
 * Purpose: Builds an authentication request for port id client_port
 *          with the value_pairs send and submits it to a server
 *
 * Returns: received value_pairs in received, messages from the server in msg (if non-NULL),
 *          and 0 on success, negative on failure as return value
 *
 */

int rc_auth(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send, VALUE_PAIR **received,
    char *msg)
{

	return rc_aaa(rh, client_port, send, received, msg, 1, PW_ACCESS_REQUEST);
}

/*
 * Function: rc_auth_proxy
 *
 * Purpose: Builds an authentication request
 *	    with the value_pairs send and submits it to a server.
 *	    Works for a proxy; does not add IP address, and does
 *	    does not rely on config file.
 *
 * Returns: received value_pairs in received, messages from the server in msg (if non-NULL)
 *	    and 0 on success, negative on failure as return value
 *
 */

int rc_auth_proxy(rc_handle *rh, VALUE_PAIR *send, VALUE_PAIR **received, char *msg)
{

	return rc_aaa(rh, 0, send, received, msg, 0, PW_ACCESS_REQUEST);
}


/*
 * Function: rc_acct
 *
 * Purpose: Builds an accounting request for port id client_port
 *	    with the value_pairs send
 *
 * Remarks: NAS-IP-Address, NAS-Port and Acct-Delay-Time get filled
 *	    in by this function, the rest has to be supplied.
 */

int rc_acct(rc_handle *rh, uint32_t client_port, VALUE_PAIR *send)
{

	return rc_aaa(rh, client_port, send, NULL, NULL, 1, PW_ACCOUNTING_REQUEST);
}

/*
 * Function: rc_acct_proxy
 *
 * Purpose: Builds an accounting request with the value_pairs send
 *
 */

int rc_acct_proxy(rc_handle *rh, VALUE_PAIR *send)
{

	return rc_aaa(rh, 0, send, NULL, NULL, 0, PW_ACCOUNTING_REQUEST);
}

/*
 * Function: rc_check
 *
 * Purpose: ask the server hostname on the specified port for a
 *	    status message
 *
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
	result = rc_send_server (rh, &data, msg);

	rc_avpair_free(data.receive_pairs);

	return result;
}
