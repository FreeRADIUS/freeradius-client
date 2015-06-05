/*
 * Copyright (c) 2014, 2015, Nikos Mavrogiannopoulos.  All rights reserved.
 * Copyright (c) 2015, Red Hat, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <config.h>
#include <includes.h>
#include <radcli.h>
#include "util.h"

#ifdef HAVE_GNUTLS

/**
 * @defgroup tls-api TLS/DTLS API
 * @brief TLS and DTLS related functions
 *
 * @{
 */

#include <gnutls/gnutls.h>
#include <gnutls/dtls.h>
#include <pthread.h>
#include <time.h>

#define DEFAULT_DTLS_SECRET "radius/dtls"
#define DEFAULT_TLS_SECRET "radsec"

typedef struct tls_int_st {
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */
	struct sockaddr_storage our_sockaddr;
	gnutls_session_t session;
	int sockfd;
	unsigned init;
	unsigned need_restart;
	unsigned skip_hostname_check; /* whether to verify hostname */
	pthread_mutex_t lock;
	time_t last_msg;
	time_t last_restart;
} tls_int_st;

typedef struct tls_st {
	gnutls_psk_client_credentials_t psk_cred;
	gnutls_certificate_credentials_t x509_cred;
	struct tls_int_st ctx;	/* one for ACCT and another for AUTH */
	unsigned flags; /* the flags set on init */
	rc_handle *rh; /* a pointer to our owner */
} tls_st;

static void restart_session(rc_handle *rh, tls_st *st);

static int tls_get_fd(void *ptr, struct sockaddr *our_sockaddr)
{
	tls_st *st = ptr;
	return st->ctx.sockfd;
}

static ssize_t tls_sendto(void *ptr, int sockfd,
			   const void *buf, size_t len,
			   int flags, const struct sockaddr *dest_addr,
			   socklen_t addrlen)
{
	tls_st *st = ptr;
	int ret;

	if (st->ctx.need_restart != 0) {
		restart_session(st->rh, st);
	}

	ret = gnutls_record_send(st->ctx.session, buf, len);
	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED) {
		errno = EINTR;
		return -1;
	}

	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in sending: %s", __func__,
		       gnutls_strerror(ret));
		errno = EIO;
		st->ctx.need_restart = 1;
		return -1;
	}

	st->ctx.last_msg = time(0);
	return ret;
}

static int tls_lock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_lock(&st->ctx.lock);
}

static int tls_unlock(void *ptr)
{
	tls_st *st = ptr;

	return pthread_mutex_unlock(&st->ctx.lock);
}

static ssize_t tls_recvfrom(void *ptr, int sockfd,
			     void *buf, size_t len,
			     int flags, struct sockaddr *src_addr,
			     socklen_t * addrlen)
{
	tls_st *st = ptr;
	int ret;

	ret = gnutls_record_recv(st->ctx.session, buf, len);
	if (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED ||
	    ret == GNUTLS_E_HEARTBEAT_PING_RECEIVED || ret == GNUTLS_E_HEARTBEAT_PONG_RECEIVED) {
		errno = EINTR;
		return -1;
	}

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED) {
		rc_log(LOG_ERR, "%s: received alert: %s", __func__,
		       gnutls_alert_get_name(gnutls_alert_get(st->ctx.session)));
		errno = EINTR;
		return -1;
	}

	/* RFC6614 says: "After the TLS session is established, RADIUS packet payloads are
	 * exchanged over the encrypted TLS tunnel.  In RADIUS/UDP, the
	 * packet size can be determined by evaluating the size of the
	 * datagram that arrived.  Due to the stream nature of TCP and TLS,
	 * this does not hold true for RADIUS/TLS packet exchange.",
	 *
	 * That is correct in principle but it fails to associate the length with 
	 * the TLS record boundaries. Here, when in TLS, we assume that a single TLS
	 * record holds a single radius packet. It wouldn't make sense anyway to send
	 * multiple TLS records for a single packet.
	 */

	if (ret <= 0) {
		rc_log(LOG_ERR, "%s: error in receiving: %s", __func__,
		       gnutls_strerror(ret));
		errno = EIO;
		st->ctx.need_restart = 1;
		return -1;
	}

	st->ctx.last_msg = time(0);
	return ret;
}

/* This function will verify the peer's certificate, and check
 * if the hostname matches.
 */
static int cert_verify_callback(gnutls_session_t session)
{
	unsigned int status;
	int ret;
	struct tls_int_st *ctx;
	gnutls_datum_t out;

	/* read hostname */
	ctx = gnutls_session_get_ptr(session);
	if (ctx == NULL)
		return GNUTLS_E_CERTIFICATE_ERROR;

	if (ctx->skip_hostname_check)
		ret = gnutls_certificate_verify_peers2(session, &status);
	else
		ret = gnutls_certificate_verify_peers3(session, ctx->hostname, &status);
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in certificate verification: %s",
		       __func__, gnutls_strerror(ret));
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	if (status != 0) {
		ret =
		    gnutls_certificate_verification_status_print(status,
								 gnutls_certificate_type_get
								 (session),
								 &out, 0);
		if (ret < 0) {
			return GNUTLS_E_CERTIFICATE_ERROR;
		}
		rc_log(LOG_INFO, "%s: certificate: %s", __func__, out.data);
		gnutls_free(out.data);
		return GNUTLS_E_CERTIFICATE_ERROR;
	}

	return 0;
}

static void deinit_session(tls_int_st *ses)
{
	if (ses->init != 0) {
		ses->init = 0;
		pthread_mutex_destroy(&ses->lock);
		if (ses->sockfd != -1)
			close(ses->sockfd);
		if (ses->session)
			gnutls_deinit(ses->session);
	}
}

static int init_session(rc_handle *rh, tls_int_st *ses,
			const char *hostname, unsigned port,
			struct sockaddr_storage *our_sockaddr,
			int timeout,
			unsigned secflags)
{
	int sockfd, ret, e;
	struct addrinfo *info;
	char *p;
	unsigned flags = 0;
	unsigned cred_set = 0;
	tls_st *st = rh->so.ptr;

	ses->sockfd = -1;
	ses->init = 1;

	pthread_mutex_init(&ses->lock, NULL);
	sockfd = socket(our_sockaddr->ss_family, (secflags&SEC_FLAG_DTLS)?SOCK_DGRAM:SOCK_STREAM, 0);
	if (sockfd < 0) {
		rc_log(LOG_ERR,
		       "%s: cannot open socket", __func__);
		ret = -1;
		goto cleanup;
	}

	if (our_sockaddr->ss_family == AF_INET)
		((struct sockaddr_in *)our_sockaddr)->sin_port = 0;
	else
		((struct sockaddr_in6 *)our_sockaddr)->sin6_port = 0;

	ses->sockfd = sockfd;

	/* Initialize DTLS */

	flags = GNUTLS_CLIENT;
	if (secflags&SEC_FLAG_DTLS)
		flags |= GNUTLS_DATAGRAM;
	ret = gnutls_init(&ses->session, flags);
	if (ret < 0) {
		rc_log(LOG_ERR,
		       "%s: error in gnutls_init(): %s", __func__, gnutls_strerror(ret));
		ret = -1;
		goto cleanup;
	}

	memcpy(&ses->our_sockaddr, our_sockaddr, sizeof(*our_sockaddr));
	if (!(secflags&SEC_FLAG_DTLS)) {
		if (timeout > 0) {
			gnutls_handshake_set_timeout(ses->session, timeout*1000);
		} else {
			gnutls_handshake_set_timeout(ses->session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
		}
	} else { /* DTLS */
		if (timeout > 0)
			gnutls_dtls_set_timeouts(ses->session, 1000, timeout*1000);
	}

	gnutls_transport_set_int(ses->session, sockfd);
	gnutls_session_set_ptr(ses->session, ses);
	/* we only initiate heartbeat messages */
	gnutls_heartbeat_enable(ses->session, GNUTLS_HB_LOCAL_ALLOWED_TO_SEND);

	p = rc_conf_str(rh, "tls-verify-hostname");
	if (p && (strcasecmp(p, "false") == 0 || strcasecmp(p, "no"))) {
		ses->skip_hostname_check = 1;
	}

	if (st && st->psk_cred) {
		cred_set = 1;
		gnutls_credentials_set(ses->session,
				       GNUTLS_CRD_PSK, st->psk_cred);

		ret = gnutls_priority_set_direct(ses->session, "NORMAL:-KX-ALL:+ECDHE-PSK:+DHE-PSK:+PSK:-VERS-TLS1.0", NULL);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK priorities: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;

			cred_set = 1;
		}
	} else if (st) {
		cred_set = 1;
		if (st->x509_cred) {
			gnutls_credentials_set(ses->session,
					       GNUTLS_CRD_CERTIFICATE,
					       st->x509_cred);
		}

		gnutls_set_default_priority(ses->session);
	}

	gnutls_server_name_set(ses->session, GNUTLS_NAME_DNS,
			       hostname, strlen(hostname));

	info =
	    rc_getaddrinfo(hostname, PW_AI_AUTH);
	if (info == NULL) {
		ret = -1;
		rc_log(LOG_ERR, "%s: cannot resolve %s", __func__,
		       hostname);
		goto cleanup;
	}

	if (port != 0) {
		if (info->ai_addr->sa_family == AF_INET)
			((struct sockaddr_in *)info->ai_addr)->sin_port =
			    htons(port);
		else
			((struct sockaddr_in6 *)info->ai_addr)->sin6_port =
			    htons(port);
	} else {
		rc_log(LOG_ERR, "%s: no port specified for server %s",
		       __func__, hostname);
		ret = -1;
		goto cleanup;
	}

	strlcpy(ses->hostname, hostname, sizeof(ses->hostname));
	ses->port = port;

	if (cred_set == 0) {
		rc_log(LOG_CRIT,
		       "%s: neither tls-ca-file or a PSK key are configured",
		       __func__);
		ret = -1;
		goto cleanup;
	}

	/* we connect since we are talking to a single server */
	ret = connect(sockfd, info->ai_addr, info->ai_addrlen);
	freeaddrinfo(info);
	if (ret == -1) {
		e = errno;
		ret = -1;
		rc_log(LOG_CRIT, "%s: cannot connect to %s: %s",
		       __func__, hostname, strerror(e));
		goto cleanup;
	}

	rc_log(LOG_DEBUG,
	       "%s: performing TLS/DTLS handshake with [%s]:%d",
	       __func__, hostname, port);
	do {
		ret = gnutls_handshake(ses->session);
		if (ret == GNUTLS_E_LARGE_PACKET)
			break;
	} while (ret < 0 && gnutls_error_is_fatal(ret) == 0);

	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in handshake: %s",
		       __func__, gnutls_strerror(ret));
		ret = -1;
		goto cleanup;
	}

	return 0;
 cleanup:
	deinit_session(ses);
	return ret;

}

/* The time after the last message was received, that
 * we will try heartbeats */
#define TIME_ALIVE 120

static void restart_session(rc_handle *rh, tls_st *st)
{
	struct tls_int_st tmps;
	time_t now = time(0);
	int ret;
	int timeout;

	if (now - st->ctx.last_restart < TIME_ALIVE)
		return;

	st->ctx.last_restart = now;

	timeout = rc_conf_int(rh, "radius_timeout");

	/* reinitialize this session */
	ret = init_session(rh, &tmps, st->ctx.hostname, st->ctx.port, &st->ctx.our_sockaddr, timeout, st->flags);
	if (ret < 0) {
		rc_log(LOG_ERR, "%s: error in re-initializing DTLS", __func__);
		return;
	}

	if (tmps.sockfd == st->ctx.sockfd)
		st->ctx.sockfd = -1;
	deinit_session(&st->ctx);
	memcpy(&st->ctx, &tmps, sizeof(tmps));
	st->ctx.need_restart = 0;

	return;
}

/** Returns the file descriptor of the TLS/DTLS session
 *
 * @param rh a handle to parsed configuration
 * @return the file descriptor used by the TLS session
 */
int rc_tls_fd(rc_handle * rh)
{
	tls_st *st;

	if (rh->so_set != SOCKETS_TLS && rh->so_set != SOCKETS_DTLS)
		return -1;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		return st->ctx.sockfd;
	}
	return -1;
}

/** Check established TLS/DTLS channels for operation
 *
 * This function will check whether the channel(s) established
 * for TLS or DTLS are operational, and will re-establish the channel
 * if necessary. If this function fails then  the TLS or DTLS state 
 * should be considered as disconnected.
 * It must be called at a time when the sessions are not in usage
 * (e.g., in a different thread).
 *
 * @param: rh a handle to parsed configuration
 * @return 0 on success, -1 on error
 */
int rc_check_tls(rc_handle * rh)
{
	tls_st *st;
	time_t now = time(0);
	int ret;

	if (rh->so_set != SOCKETS_TLS && rh->so_set != SOCKETS_DTLS)
		return 0;

	st = rh->so.ptr;

	if (st->ctx.init != 0) {
		if (st->ctx.need_restart != 0) {
			restart_session(rh, st);
		} else if (now - st->ctx.last_msg > TIME_ALIVE) {
			ret = gnutls_heartbeat_ping(st->ctx.session, 64, 4, GNUTLS_HEARTBEAT_WAIT);
			if (ret < 0) {
				restart_session(rh, st);
			}
			st->ctx.last_msg = now;
		}
	}
	return 0;
}

/** This function will deinitialize a previously initialed DTLS or TLS session.
 *
 * @param rh the configuration handle.
 */
void rc_deinit_tls(rc_handle * rh)
{
	tls_st *st = rh->so.ptr;
	if (st) {
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
		if (st->x509_cred)
			gnutls_certificate_free_credentials(st->x509_cred);
		if (st->psk_cred)
			gnutls_psk_free_client_credentials(st->psk_cred);
	}
	free(st);
}

/** Initialize a configuration for TLS or DTLS
 *
 * This function will initialize the handle for TLS or DTLS.
 *
 * @param rh a handle to parsed configuration
 * @param flags must be zero or SEC_FLAG_DTLS
 * @return 0 on success, -1 on failure.
 */
int rc_init_tls(rc_handle * rh, unsigned flags)
{
	int ret;
	tls_st *st = NULL;
	struct sockaddr_storage our_sockaddr;
	const char *ca_file = rc_conf_str(rh, "tls-ca-file");
	const char *cert_file = rc_conf_str(rh, "tls-cert-file");
	const char *key_file = rc_conf_str(rh, "tls-key-file");
	const char *pskkey = NULL;
	SERVER *authservers;
	char hostname[256];	/* server's hostname */
	unsigned port;		/* server's port */

	memset(&rh->so, 0, sizeof(rh->so));

	if (flags & SEC_FLAG_DTLS) {
		rh->so_set = SOCKETS_DTLS;
		rh->so.static_secret = DEFAULT_DTLS_SECRET;
	} else {
		rh->so_set = SOCKETS_TLS;
		rh->so.static_secret = DEFAULT_TLS_SECRET;
	}

	rc_own_bind_addr(rh, &our_sockaddr);

	st = calloc(1, sizeof(tls_st));
	if (st == NULL) {
		ret = -1;
		goto cleanup;
	}

	st->rh = rh;
	st->flags = flags;

	rh->so.ptr = st;

	if (ca_file || (key_file && cert_file)) {
		ret = gnutls_certificate_allocate_credentials(&st->x509_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting X.509 credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		if (ca_file) {
			ret =
			    gnutls_certificate_set_x509_trust_file(st->x509_cred,
							   ca_file,
							   GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting X.509 trust file: %s",
				       __func__, gnutls_strerror(ret));
				goto cleanup;
			}
		}

		if (cert_file && key_file) {
			ret =
			    gnutls_certificate_set_x509_key_file(st->x509_cred,
								 cert_file,
								 key_file,
								 GNUTLS_X509_FMT_PEM);
			if (ret < 0) {
				ret = -1;
				rc_log(LOG_ERR,
				       "%s: error in setting X.509 cert and key file: %s",
				       __func__, gnutls_strerror(ret));
				goto cleanup;
			}
		}

		gnutls_certificate_set_verify_function(st->x509_cred,
						       cert_verify_callback);
	}

	/* Read the PSK key if any */
	authservers = rc_conf_srv(rh, "authserver");
	if (authservers == NULL) {
		rc_log(LOG_ERR,
		       "%s: cannot find authserver", __func__);
		ret = -1;
		goto cleanup;
	}
	if (authservers->max > 1) {
		ret = -1;
		rc_log(LOG_ERR,
		       "%s: too many auth servers for TLS/DTLS; only one is allowed",
		       __func__);
		goto cleanup;
	}
	strlcpy(hostname, authservers->name[0], sizeof(hostname));
	port = authservers->port[0];
	if (authservers->secret)
		pskkey = authservers->secret[0];

	if (pskkey && pskkey[0] != 0) {
		char *p;
		char username[64];
		gnutls_datum_t hexkey;
		int username_len;

		if (strncmp(pskkey, "psk@", 4) != 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: server secret is set but does not start with 'psk@'",
			       __func__);
			goto cleanup;
		}
		pskkey+=4;

		if ((p = strchr(pskkey, '@')) == NULL) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: PSK key is not in 'username@hexkey' format",
			       __func__);
			goto cleanup;
		}

		username_len = p - pskkey;
		if (username_len + 1 > sizeof(username)) {
			rc_log(LOG_ERR,
			       "%s: PSK username too big", __func__);
			ret = -1;
			goto cleanup;
		}

		strlcpy(username, pskkey, username_len + 1);

		p++;
		hexkey.data = (uint8_t*)p;
		hexkey.size = strlen(p);

		ret = gnutls_psk_allocate_client_credentials(&st->psk_cred);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK credentials: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}

		ret =
		    gnutls_psk_set_client_credentials(st->psk_cred,
						      username, &hexkey,
						      GNUTLS_PSK_KEY_HEX);
		if (ret < 0) {
			ret = -1;
			rc_log(LOG_ERR,
			       "%s: error in setting PSK key: %s",
			       __func__, gnutls_strerror(ret));
			goto cleanup;
		}
	}

	ret = init_session(rh, &st->ctx, hostname, port, &our_sockaddr, 0, flags);
	if (ret < 0) {
		ret = -1;
		goto cleanup;
	}

	rh->so.get_fd = tls_get_fd;
	rh->so.sendto = tls_sendto;
	rh->so.recvfrom = tls_recvfrom;
	rh->so.lock = tls_lock;
	rh->so.unlock = tls_unlock;
	return 0;
 cleanup:
	if (st) {
		if (st->ctx.init != 0)
			deinit_session(&st->ctx);
		if (st->x509_cred)
			gnutls_certificate_free_credentials(st->x509_cred);
		if (st->psk_cred)
			gnutls_psk_free_client_credentials(st->psk_cred);
	}
	free(st);
	return ret;
}

/** @} */
#endif

