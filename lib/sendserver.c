/*
 * $Id: sendserver.c,v 1.30 2010/06/15 09:22:52 aland Exp $
 *
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
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

#include <poll.h>

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>
#include <pathnames.h>

#define	SA(p)	((struct sockaddr *)(p))

static void rc_random_vector (unsigned char *);
static int rc_check_reply (AUTH_HDR *, int, char const *, unsigned char const *, unsigned char);

/*
 * Function: rc_pack_list
 *
 * Purpose: Packs an attribute value pair list into a buffer.
 *
 * Returns: Number of octets packed.
 *
 */

static int rc_pack_list (VALUE_PAIR *vp, char *secret, AUTH_HDR *auth)
{
	int             length, i, pc, padded_length;
	int             total_length = 0;
	size_t			secretlen;
	uint32_t           lvalue, vendor;
	unsigned char   passbuf[MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char   md5buf[256];
	unsigned char   *buf, *vector, *vsa_length_ptr;

	buf = auth->data;

	while (vp != NULL)
	{
		vsa_length_ptr = NULL;
		if (VENDOR(vp->attribute) != 0) {
			*buf++ = PW_VENDOR_SPECIFIC;
			vsa_length_ptr = buf;
			*buf++ = 6;
			vendor = htonl(VENDOR(vp->attribute));
			memcpy(buf, &vendor, sizeof(uint32_t));
			buf += 4;
			total_length += 6;
		}
		*buf++ = (vp->attribute & 0xff);

		switch (vp->attribute)
		{
		 case PW_USER_PASSWORD:

		  /* Encrypt the password */

		  /* Chop off password at AUTH_PASS_LEN */
		  length = vp->lvalue;
		  if (length > AUTH_PASS_LEN)
			length = AUTH_PASS_LEN;

		  /* Calculate the padded length */
		  padded_length = (length+(AUTH_VECTOR_LEN-1)) & ~(AUTH_VECTOR_LEN-1);

		  /* Record the attribute length */
		  *buf++ = padded_length + 2;
		  if (vsa_length_ptr != NULL) *vsa_length_ptr += padded_length + 2;

		  /* Pad the password with zeros */
		  memset ((char *) passbuf, '\0', AUTH_PASS_LEN);
		  memcpy ((char *) passbuf, vp->strvalue, (size_t) length);

		  secretlen = strlen (secret);
		  vector = (unsigned char *)auth->vector;
		  for(i = 0; i < padded_length; i += AUTH_VECTOR_LEN)
		  {
		  	/* Calculate the MD5 digest*/
		  	strcpy ((char *) md5buf, secret);
		  	memcpy ((char *) md5buf + secretlen, vector,
		  		  AUTH_VECTOR_LEN);
		  	rc_md5_calc (buf, md5buf, secretlen + AUTH_VECTOR_LEN);

		        /* Remeber the start of the digest */
		  	vector = buf;

			/* Xor the password into the MD5 digest */
			for (pc = i; pc < (i + AUTH_VECTOR_LEN); pc++)
		  	{
				*buf++ ^= passbuf[pc];
		  	}
		  }

		  total_length += padded_length + 2;

		  break;
#if 0
		 case PW_CHAP_PASSWORD:

		  *buf++ = CHAP_VALUE_LENGTH + 2;
		  if (vsa_length_ptr != NULL) *vsa_length_ptr += CHAP_VALUE_LENGTH + 2;

		  /* Encrypt the Password */
		  length = vp->lvalue;
		  if (length > CHAP_VALUE_LENGTH)
		  {
			length = CHAP_VALUE_LENGTH;
		  }
		  memset ((char *) passbuf, '\0', CHAP_VALUE_LENGTH);
		  memcpy ((char *) passbuf, vp->strvalue, (size_t) length);

		  /* Calculate the MD5 Digest */
		  secretlen = strlen (secret);
		  strcpy ((char *) md5buf, secret);
		  memcpy ((char *) md5buf + secretlen, (char *) auth->vector,
		  	  AUTH_VECTOR_LEN);
		  rc_md5_calc (buf, md5buf, secretlen + AUTH_VECTOR_LEN);

		  /* Xor the password into the MD5 digest */
		  for (i = 0; i < CHAP_VALUE_LENGTH; i++)
		  {
			*buf++ ^= passbuf[i];
		  }
		  total_length += CHAP_VALUE_LENGTH + 2;

		  break;
#endif
		 default:
		  switch (vp->type)
		  {
		    case PW_TYPE_STRING:
			length = vp->lvalue;
			*buf++ = length + 2;
			if (vsa_length_ptr != NULL) *vsa_length_ptr += length + 2;
			memcpy (buf, vp->strvalue, (size_t) length);
			buf += length;
			total_length += length + 2;
			break;

		    case PW_TYPE_IPV6ADDR:
			length = 16;
			if (vsa_length_ptr != NULL) *vsa_length_ptr += length + 2;
			memcpy (buf, vp->strvalue, (size_t) length);
			buf += length;
			total_length += length + 2;
			break;

		    case PW_TYPE_IPV6PREFIX:
			length = vp->lvalue;
			if (vsa_length_ptr != NULL) *vsa_length_ptr += length + 2;
			memcpy (buf, vp->strvalue, (size_t) length);
			buf += length;
			total_length += length + 2;
			break;

		    case PW_TYPE_INTEGER:
		    case PW_TYPE_IPADDR:
		    case PW_TYPE_DATE:
			*buf++ = sizeof (uint32_t) + 2;
			if (vsa_length_ptr != NULL) *vsa_length_ptr += sizeof(uint32_t) + 2;
			lvalue = htonl (vp->lvalue);
			memcpy (buf, (char *) &lvalue, sizeof (uint32_t));
			buf += sizeof (uint32_t);
			total_length += sizeof (uint32_t) + 2;
			break;

		    default:
			break;
		  }
		  break;
		}
		vp = vp->next;
	}
	return total_length;
}

/* Function strappend
 *
 * Purpose: appends a string to the provided buffer
 */
static void strappend(char *dest, unsigned max_size, int *pos, const char *src)
{
	unsigned len = strlen(src) + 1;

	if (*pos == -1)
		return;

	if (len + *pos > max_size) {
		*pos = -1;
		return;
	}

	memcpy(&dest[*pos], src, len);
	*pos += len-1;
	return;
}

/*
 * Function: rc_send_server
 *
 * Purpose: send a request to a RADIUS server and wait for the reply
 *
 */

int rc_send_server (rc_handle *rh, SEND_DATA *data, char *msg)
{
	int             sockfd;
	struct sockaddr_in sinlocal;
	struct sockaddr_in sinremote;
	AUTH_HDR       *auth, *recv_auth;
	uint32_t           auth_ipaddr, nas_ipaddr;
	char           *server_name;	/* Name of server to query */
	socklen_t       salen;
	int             result = 0;
	int             total_length;
	int             length, pos;
	int             retry_max;
	size_t			secretlen;
	char            secret[MAX_SECRET_LENGTH + 1];
	unsigned char   vector[AUTH_VECTOR_LEN];
	char            recv_buffer[BUFFER_LEN];
	char            send_buffer[BUFFER_LEN];
	int		retries;
	VALUE_PAIR 	*vp;
	struct pollfd	pfd;
	double		start_time, timeout;

	server_name = data->server;
	if (server_name == NULL || server_name[0] == '\0')
		return ERROR_RC;

	if ((vp = rc_avpair_get(data->send_pairs, PW_SERVICE_TYPE, 0)) && \
	    (vp->lvalue == PW_ADMINISTRATIVE))
	{
		strcpy(secret, MGMT_POLL_SECRET);
		if ((auth_ipaddr = rc_get_ipaddr(server_name)) == 0)
			return ERROR_RC;
	}
	else
	{
		if(data->secret != NULL)
		{
			strncpy(secret, data->secret, MAX_SECRET_LENGTH);
		}
		/*
		else
		{
		*/
		if (rc_find_server (rh, server_name, &auth_ipaddr, secret) != 0)
		{
			rc_log(LOG_ERR, "rc_send_server: unable to find server: %s", server_name);
			return ERROR_RC;
		}
		/*}*/
	}

	DEBUG(LOG_ERR, "DEBUG: rc_send_server: creating socket to: %s", server_name);

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		memset (secret, '\0', sizeof (secret));
		rc_log(LOG_ERR, "rc_send_server: socket: %s", strerror(errno));
		return ERROR_RC;
	}

	memset((char *)&sinlocal, '\0', sizeof(sinlocal));
	sinlocal.sin_family = AF_INET;
	sinlocal.sin_addr.s_addr = htonl(rc_own_bind_ipaddress(rh));
	sinlocal.sin_port = htons((unsigned short) 0);
	if (bind(sockfd, SA(&sinlocal), sizeof(sinlocal)) < 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		rc_log(LOG_ERR, "rc_send_server: bind: %s: %s", server_name, strerror(errno));
		return ERROR_RC;
	}

	retry_max = data->retries;	/* Max. numbers to try for reply */
	retries = 0;			/* Init retry cnt for blocking call */

	memset ((char *)&sinremote, '\0', sizeof(sinremote));
	sinremote.sin_family = AF_INET;
	sinremote.sin_addr.s_addr = htonl (auth_ipaddr);
	sinremote.sin_port = htons ((unsigned short) data->svc_port);

	/*
	 * Fill in NAS-IP-Address (if needed)
	 */
	if (rc_avpair_get(data->send_pairs, PW_NAS_IP_ADDRESS, 0) == NULL) {
		if (sinlocal.sin_addr.s_addr == htonl(INADDR_ANY)) {
			if (rc_get_srcaddr(SA(&sinlocal), SA(&sinremote)) != 0) {
				close (sockfd);
				memset (secret, '\0', sizeof (secret));
				return ERROR_RC;
			}
		}
		nas_ipaddr = ntohl(sinlocal.sin_addr.s_addr);
		rc_avpair_add(rh, &(data->send_pairs), PW_NAS_IP_ADDRESS,
		    &nas_ipaddr, 0, 0);
	}

	/* Build a request */
	auth = (AUTH_HDR *) send_buffer;
	auth->code = data->code;
	auth->id = data->seq_nbr;

	if (data->code == PW_ACCOUNTING_REQUEST)
	{
		total_length = rc_pack_list(data->send_pairs, secret, auth) + AUTH_HDR_LEN;

		auth->length = htons ((unsigned short) total_length);

		memset((char *) auth->vector, 0, AUTH_VECTOR_LEN);
		secretlen = strlen (secret);
		memcpy ((char *) auth + total_length, secret, secretlen);
		rc_md5_calc (vector, (unsigned char *) auth, total_length + secretlen);
		memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
	}
	else
	{
		rc_random_vector (vector);
		memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);

		total_length = rc_pack_list(data->send_pairs, secret, auth) + AUTH_HDR_LEN;

		auth->length = htons ((unsigned short) total_length);
	}

	DEBUG(LOG_ERR, "DEBUG: local %s : 0, remote %s : %u\n", 
		inet_ntoa(sinlocal.sin_addr),
		inet_ntoa(sinremote.sin_addr), data->svc_port);

	for (;;)
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			SA(&sinremote), sizeof (struct sockaddr_in));

		pfd.fd = sockfd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		start_time = rc_getctime();
		for (timeout = data->timeout; timeout > 0;
		    timeout -= rc_getctime() - start_time) {
			result = poll(&pfd, 1, timeout * 1000);
			if (result != -1 || errno != EINTR)
				break;
		}
		if (result == -1)
		{
			rc_log(LOG_ERR, "rc_send_server: poll: %s", strerror(errno));
			memset (secret, '\0', sizeof (secret));
			close (sockfd);
			return ERROR_RC;
		}
		if (result == 1 && (pfd.revents & POLLIN) != 0)
			break;

		/*
		 * Timed out waiting for response.  Retry "retry_max" times
		 * before giving up.  If retry_max = 0, don't retry at all.
		 */
		if (retries++ >= retry_max)
		{
			rc_log(LOG_ERR,
				"rc_send_server: no reply from RADIUS server %s:%u, %s",
				 rc_ip_hostname (auth_ipaddr), data->svc_port, inet_ntoa(sinremote.sin_addr));
			close (sockfd);
			memset (secret, '\0', sizeof (secret));
			return TIMEOUT_RC;
		}
	}
	salen = sizeof(sinremote);
	length = recvfrom (sockfd, (char *) recv_buffer,
			   (int) sizeof (recv_buffer),
			   (int) 0, SA(&sinremote), &salen);

	if (length <= 0)
	{
		rc_log(LOG_ERR, "rc_send_server: recvfrom: %s:%d: %s", server_name,\
			 data->svc_port, strerror(errno));
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		return ERROR_RC;
	}

	recv_auth = (AUTH_HDR *)recv_buffer;

	if (length < AUTH_HDR_LEN || length < ntohs(recv_auth->length)) {
		rc_log(LOG_ERR, "rc_send_server: recvfrom: %s:%d: reply is too short",
		    server_name, data->svc_port);
		close(sockfd);
		memset(secret, '\0', sizeof(secret));
		return ERROR_RC;
	}

	result = rc_check_reply (recv_auth, BUFFER_LEN, secret, vector, data->seq_nbr);

	length = ntohs(recv_auth->length)  - AUTH_HDR_LEN;
	if (length > 0) {
		data->receive_pairs = rc_avpair_gen(rh, NULL, recv_auth->data,
		    length, 0);
	} else {
		data->receive_pairs = NULL;
	}

	close (sockfd);
	memset (secret, '\0', sizeof (secret));

	if (result != OK_RC) return result;

	if (msg) {
		*msg = '\0';
		pos = 0;
		vp = data->receive_pairs;
		while (vp)
		{
			if ((vp = rc_avpair_get(vp, PW_REPLY_MESSAGE, 0)))
			{
				strappend(msg, PW_MAX_MSG_SIZE, &pos, vp->strvalue);
				strappend(msg, PW_MAX_MSG_SIZE, &pos, "\n");
				vp = vp->next;
			}
		}
	}

	if ((recv_auth->code == PW_ACCESS_ACCEPT) ||
		(recv_auth->code == PW_PASSWORD_ACK) ||
		(recv_auth->code == PW_ACCOUNTING_RESPONSE))
	{
		result = OK_RC;
	}
	else if ((recv_auth->code == PW_ACCESS_REJECT) ||
		(recv_auth->code == PW_PASSWORD_REJECT))
	{
		result = REJECT_RC;
	}
	else
	{
		result = BADRESP_RC;
	}

	return result;
}

/*
 * Function: rc_check_reply
 *
 * Purpose: verify items in returned packet.
 *
 * Returns:	OK_RC       -- upon success,
 *		BADRESP_RC  -- if anything looks funny.
 *
 */

static int rc_check_reply (AUTH_HDR *auth, int bufferlen, char const *secret, unsigned char const *vector, uint8_t seq_nbr)
{
	int             secretlen;
	int             totallen;
	unsigned char   calc_digest[AUTH_VECTOR_LEN];
	unsigned char   reply_digest[AUTH_VECTOR_LEN];
#ifdef DIGEST_DEBUG
	uint8_t		*ptr;
#endif

	totallen = ntohs (auth->length);
	secretlen = (int)strlen (secret);

	/* Do sanity checks on packet length */
	if ((totallen < 20) || (totallen > 4096))
	{
		rc_log(LOG_ERR, "rc_check_reply: received RADIUS server response with invalid length");
		return BADRESP_RC;
	}

	/* Verify buffer space, should never trigger with current buffer size and check above */
	if ((totallen + secretlen) > bufferlen)
	{
		rc_log(LOG_ERR, "rc_check_reply: not enough buffer space to verify RADIUS server response");
		return BADRESP_RC;
	}

	/* Verify that id (seq. number) matches what we sent */
	if (auth->id != seq_nbr)
	{
		rc_log(LOG_ERR, "rc_check_reply: received non-matching id in RADIUS server response");
		return BADRESP_RC;
	}

	/* Verify the reply digest */
	memcpy ((char *) reply_digest, (char *) auth->vector, AUTH_VECTOR_LEN);
	memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
	memcpy ((char *) auth + totallen, secret, secretlen);
#ifdef DIGEST_DEBUG
        rc_log(LOG_ERR, "Calculating digest on:");
        for (ptr = (u_char *)auth; ptr < ((u_char *)auth) + totallen + secretlen; ptr += 32) {
                char buf[65];
                int i;

                buf[0] = '\0';
                for (i = 0; i < 32; i++) {
                        if (ptr + i >= ((u_char *)auth) + totallen + secretlen)
                                break;
                        sprintf(buf + i * 2, "%.2X", ptr[i]);
                }
                rc_log(LOG_ERR, "  %s", buf);
        }
#endif
	rc_md5_calc (calc_digest, (unsigned char *) auth, totallen + secretlen);
#ifdef DIGEST_DEBUG
	rc_log(LOG_ERR, "Calculated digest is:");
        for (ptr = (u_char *)calc_digest; ptr < ((u_char *)calc_digest) + 16; ptr += 32) {
                char buf[65];
                int i;

                buf[0] = '\0';
                for (i = 0; i < 32; i++) {
                        if (ptr + i >= ((u_char *)calc_digest) + 16)
                                break;
                        sprintf(buf + i * 2, "%.2X", ptr[i]);
                }
                rc_log(LOG_ERR, "  %s", buf);
        }
	rc_log(LOG_ERR, "Reply digest is:");
        for (ptr = (u_char *)reply_digest; ptr < ((u_char *)reply_digest) + 16; ptr += 32) {
                char buf[65];
                int i;

                buf[0] = '\0';
                for (i = 0; i < 32; i++) {
                        if (ptr + i >= ((u_char *)reply_digest) + 16)
                                break;
                        sprintf(buf + i * 2, "%.2X", ptr[i]);
                }
                rc_log(LOG_ERR, "  %s", buf);
        }
#endif

	if (memcmp ((char *) reply_digest, (char *) calc_digest,
		    AUTH_VECTOR_LEN) != 0)
	{
#ifdef RADIUS_116
		/* the original Livingston radiusd v1.16 seems to have
		   a bug in digest calculation with accounting requests,
		   authentication request are ok. i looked at the code
		   but couldn't find any bugs. any help to get this
		   kludge out are welcome. preferably i want to
		   reproduce the calculation bug here to be compatible
		   to stock Livingston radiusd v1.16.	-lf, 03/14/96
		 */
		if (auth->code == PW_ACCOUNTING_RESPONSE)
			return OK_RC;
#endif
		rc_log(LOG_ERR, "rc_check_reply: received invalid reply digest from RADIUS server");
		return BADRESP_RC;
	}

	return OK_RC;

}

/*
 * Function: rc_random_vector
 *
 * Purpose: generates a random vector of AUTH_VECTOR_LEN octets.
 *
 * Returns: the vector (call by reference)
 *
 */

static void rc_random_vector (unsigned char *vector)
{
	int             randno;
	int             i;
#if defined(HAVE_GETENTROPY)
	if (getentropy(vector, AUTH_VECTOR_LEN) >= 0) {
		return;
	} /* else fall through */
#elif defined(HAVE_DEV_URANDOM)
	int		fd;

/* well, I added this to increase the security for user passwords.
   we use /dev/urandom here, as /dev/random might block and we don't
   need that much randomness. BTW, great idea, Ted!     -lf, 03/18/95	*/

	if ((fd = open(_PATH_DEV_URANDOM, O_RDONLY)) >= 0)
	{
		unsigned char *pos;
		int readcount;

		i = AUTH_VECTOR_LEN;
		pos = vector;
		while (i > 0)
		{
			readcount = read(fd, (char *)pos, i);
			if (readcount >= 0) {
				pos += readcount;
				i -= readcount;
			} else {
				if (errno != EINTR && errno != EAGAIN)
					goto fallback;
			}
		}

		close(fd);
		return;
	} /* else fall through */
#endif
 fallback:
	for (i = 0; i < AUTH_VECTOR_LEN;)
	{
		randno = random ();
		memcpy ((char *) vector, (char *) &randno, sizeof (int));
		vector += sizeof (int);
		i += sizeof (int);
	}

	return;
}
