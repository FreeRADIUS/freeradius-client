/*
 * $Id: buildreq.c,v 1.11 2007/02/19 22:14:11 cparker Exp $
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

unsigned char rc_get_seqnbr(rc_handle *);

/*
 * Function: rc_buildreq
 *
 * Purpose: builds a skeleton RADIUS request using information from the
 * 	    config file.
 *
 */

void rc_buildreq(rc_handle *rh, SEND_DATA *data, int code, char *server, unsigned short port, 
		 char *secret, int timeout, int retries)
{
	data->server = server;
	data->secret = secret;
	data->svc_port = port;
	data->seq_nbr = rc_get_seqnbr(rh);
	data->timeout = timeout;
	data->retries = retries;
	data->code = code;
}

/*
 * Function: rc_guess_seqnbr
 *
 * Purpose: return a random sequence number
 *
 */

static unsigned char rc_guess_seqnbr(void)
{
	srandom((unsigned int)(time(NULL)+getpid()));
	return (unsigned char)(random() & UCHAR_MAX);
}

/*
 * Function: rc_get_seqnbr
 *
 * Purpose: generate a sequence number
 *
 */

unsigned char rc_get_seqnbr(rc_handle *rh)
{
	FILE *sf;
	int tries = 1;
	int seq_nbr;
	char *seqfile = rc_conf_str(rh, "seqfile");

	if ((sf = fopen(seqfile, "a+")) == NULL)
	{
		rc_log(LOG_ERR,"rc_get_seqnbr: couldn't open sequence file %s: %s", seqfile, strerror(errno));
		/* well, so guess a sequence number */
		return rc_guess_seqnbr();
	}

	while (do_lock_exclusive(fileno(sf))!= 0)
	{
		if (errno != EWOULDBLOCK) {
			rc_log(LOG_ERR, "rc_get_seqnbr: flock failure: %s: %s", seqfile, strerror(errno));
			fclose(sf);
			return rc_guess_seqnbr();
		}
		tries++;
		if (tries <= 10)
			rc_mdelay(500);
		else
			break;
	}

	if (tries > 10) {
		rc_log(LOG_ERR,"rc_get_seqnbr: couldn't get lock after %d tries: %s", tries-1, seqfile);
 		fclose(sf);
		return rc_guess_seqnbr();
	}

	rewind(sf);
	if (fscanf(sf, "%d", &seq_nbr) != 1) {
		rc_log(LOG_ERR,"rc_get_seqnbr: fscanf failure: %s", seqfile);
		seq_nbr = rc_guess_seqnbr();
	}

	rewind(sf);
	ftruncate(fileno(sf),0);
	fprintf(sf,"%d\n", (seq_nbr+1) & UCHAR_MAX);

	fflush(sf); /* fflush because a process may read it between the do_unlock and fclose */

	if (do_unlock(fileno(sf)) != 0)
		rc_log(LOG_ERR, "rc_get_seqnbr: couldn't release lock on %s: %s", seqfile, strerror(errno));

	fclose(sf);

	return (unsigned char)seq_nbr;
}

/*
 * Function: rc_auth
 *
 * Purpose: Builds an authentication request for port id client_port
 *	    with the value_pairs send and submits it to a server
 *
 * Returns: received value_pairs in received, messages from the server in msg
 *	    and 0 on success, negative on failure as return value
 *
 */

int rc_auth(rc_handle *rh, UINT4 client_port, VALUE_PAIR *send, VALUE_PAIR **received,
	    char *msg)
{
	SEND_DATA       data;
	int		result;
	int		i;
	SERVER		*authserver = rc_conf_srv(rh, "authserver");
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (authserver == NULL)
		return ERROR_RC;
	/*
	 * Fill in NAS-Port
	 */

	if (rc_avpair_add(rh, &(data.send_pairs), PW_NAS_PORT, &client_port, 0, 0) == NULL)
		return ERROR_RC;

	result = ERROR_RC;
	for(i=0; (i<authserver->max) && (result != OK_RC) && (result != BADRESP_RC)
		; i++)
	{
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}
		rc_buildreq(rh, &data, PW_ACCESS_REQUEST, authserver->name[i],
			    authserver->port[i], authserver->secret[i], timeout, retries);

		result = rc_send_server (rh, &data, msg);
	}

	*received = data.receive_pairs;

	return result;
}

/*
 * Function: rc_auth_proxy
 *
 * Purpose: Builds an authentication request
 *	    with the value_pairs send and submits it to a server.
 *	    Works for a proxy; does not add IP address, and does
 *	    does not rely on config file.
 *
 * Returns: received value_pairs in received, messages from the server in msg
 *	    and 0 on success, negative on failure as return value
 *
 */

int rc_auth_proxy(rc_handle *rh, VALUE_PAIR *send, VALUE_PAIR **received, char *msg)
{
	SEND_DATA       data;
	int		result;
	int		i;
	SERVER		*authserver = rc_conf_srv(rh, "authserver");
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if(authserver == NULL) 
		return ERROR_RC;

	result = ERROR_RC;
	for(i=0; (i<authserver->max) && (result != OK_RC) && (result != BADRESP_RC)
		; i++)
	{
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}
		rc_buildreq(rh, &data, PW_ACCESS_REQUEST, authserver->name[i],
			    authserver->port[i], authserver->secret[i], timeout, retries);

		result = rc_send_server (rh, &data, msg);
	}

	*received = data.receive_pairs;

	return result;
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

int rc_acct(rc_handle *rh, UINT4 client_port, VALUE_PAIR *send)
{
	SEND_DATA       data;
	VALUE_PAIR	*adt_vp;
	int		result;
	time_t		start_time, dtime;
	char		msg[4096];
	int		i;
	SERVER		*acctserver = rc_conf_srv(rh, "acctserver");
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if(acctserver == NULL)
		return ERROR_RC;

	/*
	 * Fill in NAS-Port
	 */

	if (rc_avpair_add(rh, &(data.send_pairs), PW_NAS_PORT, &client_port, 0, 0) == NULL)
		return ERROR_RC;

	/*
	 * Fill in Acct-Delay-Time
	 */

	dtime = 0;
	if ((adt_vp = rc_avpair_add(rh, &(data.send_pairs), PW_ACCT_DELAY_TIME, &dtime, 0, 0)) == NULL)
		return ERROR_RC;

	start_time = time(NULL);
	result = ERROR_RC;
	for(i=0; (i<acctserver->max) && (result != OK_RC) && (result != BADRESP_RC)
		; i++)
	{
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}

		rc_buildreq(rh, &data, PW_ACCOUNTING_REQUEST, acctserver->name[i],
			    acctserver->port[i], acctserver->secret[i], timeout, retries);

		dtime = time(NULL) - start_time;
		rc_avpair_assign(adt_vp, &dtime, 0);

		result = rc_send_server (rh, &data, msg);
	}

	rc_avpair_free(data.receive_pairs);

	return result;
}

/*
 * Function: rc_acct_proxy
 *
 * Purpose: Builds an accounting request with the value_pairs send
 *
 */

int rc_acct_proxy(rc_handle *rh, VALUE_PAIR *send)
{
	SEND_DATA       data;
	int		result;
	char		msg[4096];
	int		i;
	SERVER		*acctserver = rc_conf_srv(rh, "acctserver");
	int		timeout = rc_conf_int(rh, "radius_timeout");
	int		retries = rc_conf_int(rh, "radius_retries");

	data.send_pairs = send;
	data.receive_pairs = NULL;

	if (acctserver == NULL)
		return ERROR_RC;

	result = ERROR_RC;
	for(i=0; (i<acctserver->max) && (result != OK_RC) && (result != BADRESP_RC)
		; i++)
	{
		if (data.receive_pairs != NULL) {
			rc_avpair_free(data.receive_pairs);
			data.receive_pairs = NULL;
		}
		rc_buildreq(rh, &data, PW_ACCOUNTING_REQUEST, acctserver->name[i],
			    acctserver->port[i], acctserver->secret[i], timeout, retries);

		result = rc_send_server (rh, &data, msg);
	}

	rc_avpair_free(data.receive_pairs);

	return result;
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
	UINT4		service_type;
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
