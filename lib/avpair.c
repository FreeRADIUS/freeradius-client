/*
 * $Id: avpair.c,v 1.26 2010/06/15 09:22:52 aland Exp $
 *
 * Copyright (C) 1995 Lars Fenneberg
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

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>



/*
 *     Decode Tunnel-Password encrypted attributes.
 *
 *             Defined in RFC-2868, this uses a two char SALT along with the
 *             initial intermediate value, to differentiate it from the
 *             above.
 */
int rc_tunnel_pwdecode(uint8_t *passwd, int *pwlen, const char *secret,
                                               const char *vector)
{
       uint8_t         buffer[AUTH_VECTOR_LEN + MAX_STRING_LEN + 3];
       uint8_t         digest[AUTH_VECTOR_LEN];
       uint8_t         decrypted[MAX_STRING_LEN + 1];
       int             secretlen;
       unsigned        i, n, len;

       len = *pwlen;

       /*
        *      We need at least a salt.
        */
       if (len < 2) {
               rc_log(LOG_ERR, "tunnel password is too short");
               return -1;
       }

       /*
        *      There's a salt, but no password.  Or, there's a salt
        *      and a 'data_len' octet.  It's wrong, but at least we
        *      can figure out what it means: the password is empty.
        *
        *      Note that this means we ignore the 'data_len' field,
        *      if the attribute length tells us that there's no
        *      more data.      So the 'data_len' field may be wrong,
        *      but that's ok...
        */
       if (len <= 3) {
               passwd[0] = 0;
               *pwlen = 0;
               return 0;
       }

       len -= 2;               /* discount the salt */

       /*
        *      Use the secret to setup the decryption digest
        */
       secretlen = strlen(secret);

       /*
        *      Set up the initial key:
        *
        *       b(1) = MD5(secret + vector + salt)
        */
       memcpy(buffer, secret, secretlen);
       memcpy(buffer + secretlen, vector, AUTH_VECTOR_LEN);
       memcpy(buffer + secretlen + AUTH_VECTOR_LEN, passwd, 2);
       rc_md5_calc(digest, buffer, secretlen + AUTH_VECTOR_LEN + 2);

       /*
        *      A quick check: decrypt the first octet of the password,
        *      which is the 'data_len' field.  Ensure it's sane.
        *
        *      'n' doesn't include the 'data_len' octet
        *      'len' does.
        */
       n = passwd[2] ^ digest[0];
       if (n >= len) {
               rc_log(LOG_ERR, "tunnel password is \
                                too long for the attribute");
               return -1;
       }

       /*
        *      Loop over the data, decrypting it, and generating
        *      the key for the next round of decryption.
        */
       for (n = 0; n < len; n += AUTH_PASS_LEN) {
               for (i = 0; i < AUTH_PASS_LEN; i++) {
                       decrypted[n + i] = passwd[n + i + 2] ^ digest[i];

                       /*
                        *      Encrypted password may not be aligned
                        *      on 16 octets, so we catch that here...
                        */
                       if ((n + i) == len) break;
               }

               /*
                *      Update the digest, based on
                *
                *      b(n) = MD5(secret + cleartext(n-1)
                *
                *      but only if there's more data...
                */
               memcpy(buffer + secretlen, passwd + n + 2, AUTH_PASS_LEN);
               rc_md5_calc(digest, buffer, secretlen + AUTH_PASS_LEN);
       }

       /*
        *      We've already validated the length of the decrypted
        *      password.  Copy it back to the caller.
        */
       memcpy(passwd, decrypted + 1, decrypted[0]);
       passwd[decrypted[0]] = 0;
       *pwlen = decrypted[0];

       return decrypted[0];
}


/*
 * Function: rc_avpair_add
 *
 * Purpose: add an attribute-value pair to the given list.
 *
 * Returns: pointer to added a/v pair upon success, NULL pointer upon failure.
 *
 * Remarks: Always appends the new pair to the end of the list.
 *
 */

VALUE_PAIR *rc_avpair_add (const rc_handle *rh, VALUE_PAIR **list, int attrid, void *pval, int len, int vendorpec)
{
	VALUE_PAIR     *vp;

	vp = rc_avpair_new (rh, attrid, pval, len, vendorpec);

	if (vp != NULL)
	{
		rc_avpair_insert (list, NULL, vp);
	}

	return vp;

}

/*
 * Function: rc_avpair_assign
 *
 * Purpose: assign the given value to an attribute-value pair.
 *
 * Returns:  0 on success,
 *	    -1 on failure.
 *
 */

int rc_avpair_assign (VALUE_PAIR *vp, void *pval, int len)
{

	switch (vp->type)
	{
		case PW_TYPE_STRING:
			if (len == -1)
				len = (uint32_t)strlen((char *)pval);
			if (len > AUTH_STRING_LEN) {
		        	rc_log(LOG_ERR, "rc_avpair_assign: bad attribute length");
		        	return -1;
			}
			memcpy(vp->strvalue, (char *)pval, len);
			vp->strvalue[len] = '\0';
			vp->lvalue = len;
			break;

		case PW_TYPE_DATE:
		case PW_TYPE_INTEGER:
	        case PW_TYPE_IPADDR:
			vp->lvalue = * (uint32_t *) pval;
			break;

		default:
			rc_log(LOG_ERR, "rc_avpair_assign: unknown attribute %d", vp->type);
			return -1;
	}
	return 0;
}

/*
 * Function: rc_avpair_new
 *
 * Purpose: make a new attribute-value pair with given parameters.
 *
 * Returns: pointer to generated a/v pair when successful, NULL when failure.
 *
 */

VALUE_PAIR *rc_avpair_new (const rc_handle *rh, int attrid, void *pval, int len, int vendorpec)
{
	VALUE_PAIR     *vp = NULL;
	DICT_ATTR      *pda;
	int attrType;

	attrid = attrid | (vendorpec << 16);
	if ((pda = rc_dict_getattr (rh, attrid)) == NULL)
	{
		rc_log(LOG_ERR,"rc_avpair_new: unknown attribute %d", attrid);
		attrType = PW_TYPE_STRING;
	}
	else
		attrType = pda->type;

	if (vendorpec != 0 && rc_dict_getvend(rh, vendorpec) == NULL)
	{
		rc_log(LOG_ERR,"rc_avpair_new: unknown Vendor-Id %d", vendorpec);
		return NULL;
	}
	if ((vp = malloc (sizeof (VALUE_PAIR))) != NULL)
	{
		if(pda)
			strncpy (vp->name, pda->name, sizeof (vp->name));
		else
			sprintf(vp->name, "attr%d", attrid);
		vp->attribute = attrid;
		vp->next = NULL;
		vp->type = attrType;
		if (rc_avpair_assign (vp, pval, len) == 0)
		{
			/* XXX: Fix up Digest-Attributes */
			switch (vp->attribute) {
			case PW_DIGEST_REALM:
			case PW_DIGEST_NONCE:
			case PW_DIGEST_METHOD:
			case PW_DIGEST_URI:
			case PW_DIGEST_QOP:
			case PW_DIGEST_ALGORITHM:
			case PW_DIGEST_BODY_DIGEST:
			case PW_DIGEST_CNONCE:
			case PW_DIGEST_NONCE_COUNT:
			case PW_DIGEST_USER_NAME:
				/* overlapping! */
				if (vp->lvalue > AUTH_STRING_LEN - 2)
					vp->lvalue = AUTH_STRING_LEN - 2;
				memmove(&vp->strvalue[2], &vp->strvalue[0], vp->lvalue);
				vp->strvalue[0] = vp->attribute - PW_DIGEST_REALM + 1;
				vp->lvalue += 2;
				vp->strvalue[1] = vp->lvalue;
				vp->strvalue[vp->lvalue] = '\0';
				vp->attribute = PW_DIGEST_ATTRIBUTES;
			default:
				break;
			}
			return vp;
		}
		free (vp);
		vp = NULL;
	}
	else
	{
		rc_log(LOG_CRIT,"rc_avpair_new: out of memory");
	}

	return vp;
}

/*
 *
 * Function: rc_avpair_gen
 *
 * Purpose: takes attribute/value pairs from buffer and builds a
 *	    value_pair list using allocated memory. Uses recursion.
 *
 * Returns: value_pair list or NULL on failure
 */

VALUE_PAIR *
rc_avpair_gen(const rc_handle *rh, VALUE_PAIR *pair, unsigned char *ptr,
    int length, int vendorpec)
{
	int attribute, attrlen, x_len;
	unsigned char *x_ptr;
	uint32_t lvalue;
	DICT_ATTR *attr;
	VALUE_PAIR *rpair;
	char buffer[(AUTH_STRING_LEN * 2) + 1];
	/* For hex string conversion. */
	char hex[3];

	if (length < 2) {
		rc_log(LOG_ERR, "rc_avpair_gen: received attribute with "
		    "invalid length");
		goto shithappens;
	}
	attrlen = ptr[1];
	if (length < attrlen || attrlen < 2) {
		rc_log(LOG_ERR, "rc_avpair_gen: received attribute with "
		    "invalid length");
		goto shithappens;
	}

	/* Advance to the next attribute and process recursively */
	if (length != attrlen) {
		pair = rc_avpair_gen(rh, pair, ptr + attrlen, length - attrlen,
		    vendorpec);
		if (pair == NULL)
			return NULL;
	}

	/* Actual processing */
	attribute = ptr[0] | (vendorpec << 16);
	ptr += 2;
	attrlen -= 2;

	/* VSA */
	if (attribute == PW_VENDOR_SPECIFIC) {
		if (attrlen < 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received VSA "
			    "attribute with invalid length");
			goto shithappens;
		}
		memcpy(&lvalue, ptr, 4);
		vendorpec = ntohl(lvalue);
		if (rc_dict_getvend(rh, vendorpec) == NULL) {
			/* Warn and skip over the unknown VSA */
			rc_log(LOG_WARNING, "rc_avpair_gen: received VSA "
			    "attribute with unknown Vendor-Id %d", vendorpec);
			return pair;
		}
		/* Process recursively */
		return rc_avpair_gen(rh, pair, ptr + 4, attrlen - 4,
		    vendorpec);
	}

	/* Normal */
	attr = rc_dict_getattr(rh, attribute);
	if (attr == NULL) {
		buffer[0] = '\0';	/* Initial length. */
		x_ptr = ptr;
		for (x_len = attrlen; x_len > 0; x_len--, x_ptr++) {
			sprintf(hex, "%2.2X", x_ptr[0]);
			strcat(buffer, hex);
		}
		if (vendorpec == 0) {
			rc_log(LOG_WARNING, "rc_avpair_gen: received "
			    "unknown attribute %d of length %d: 0x%s",
			    attribute, attrlen + 2, buffer);
		} else {
			rc_log(LOG_WARNING, "rc_avpair_gen: received "
			    "unknown VSA attribute %d, vendor %d of "
			    "length %d: 0x%s", attribute & 0xffff,
			    VENDOR(attribute), attrlen + 2, buffer);
		}
		goto shithappens;
	}

	rpair = malloc(sizeof(*rpair));
	if (rpair == NULL) {
		rc_log(LOG_CRIT, "rc_avpair_gen: out of memory");
		goto shithappens;
	}
	memset(rpair, '\0', sizeof(*rpair));

	/* Insert this new pair at the beginning of the list */
	rpair->next = pair;
	pair = rpair;
	strcpy(pair->name, attr->name);
	pair->attribute = attr->value;
	pair->type = attr->type;
	pair->flags = attr->flags;

	/* Handle attributes with tags. */
	if (attr->flags.has_tag) 
	{
		pair->flags.tag = ptr[0];
	}

	switch (attr->type) {
	case PW_TYPE_STRING:
		/* We don't do decryption here - we don't have all the
		 * info. */
		if (attr->flags.has_tag) 
		{
			++ptr;
			--attrlen;
		}
		memcpy(pair->strvalue, (char *)ptr, (size_t)attrlen);
		pair->strvalue[attrlen] = '\0';
		pair->lvalue = attrlen;
		break;

	case PW_TYPE_INTEGER:
		if (attrlen != 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received INT "
			    "attribute with invalid length");
			goto shithappens;
		}
	case PW_TYPE_IPADDR:
		if (attrlen != 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPADDR"
			    " attribute with invalid length");
			goto shithappens;
		}
		memcpy((char *)&lvalue, (char *)ptr, 4);
		if (attr->flags.has_tag) 
		{
			/* suppress the tag */
			lvalue &= 0xFFF;
		}
		pair->lvalue = ntohl(lvalue);
		break;

	default:
		rc_log(LOG_WARNING, "rc_avpair_gen: %s has unknown type",
		    attr->name);
		goto shithappens;
	}
	return pair;

shithappens:
	while (pair != NULL) {
		rpair = pair->next;
		free(pair);
		pair = rpair;
	}
	return NULL;
}

/*
 * Function: rc_avpair_get
 *
 * Purpose: Find the first attribute value-pair (which matches the given
 *          attribute) from the specified value-pair list.
 *
 * Returns: found value_pair
 *
 */

VALUE_PAIR *rc_avpair_get (VALUE_PAIR *vp, int attrid, int vendorpec)
{
	for (; vp != NULL && !(ATTRID(vp->attribute) == ATTRID(attrid) &&
	    VENDOR(vp->attribute) == vendorpec); vp = vp->next)
	{
		continue;
	}
	return vp;
}

/*
 * Function: rc_avpair_insert
 *
 * Purpose: Given the address of an existing list "a" and a pointer
 *	    to an entry "p" in that list, add the value pair "b" to
 *	    the "a" list after the "p" entry.  If "p" is NULL, add
 *	    the value pair "b" to the end of "a".
 *
 */

void rc_avpair_insert (VALUE_PAIR **a, VALUE_PAIR *p, VALUE_PAIR *b)
{
	VALUE_PAIR     *this_node = NULL;
	VALUE_PAIR     *vp;

	if (b->next != NULL)
	{
		rc_log(LOG_CRIT, "rc_avpair_insert: value pair (0x%p) next ptr. (0x%p) not NULL", b, b->next);
		abort ();
	}

	if (*a == NULL)
	{
		*a = b;
		return;
	}

	vp = *a;

	if ( p == NULL) /* run to end of "a" list */
	{
		while (vp != NULL)
		{
			this_node = vp;
			vp = vp->next;
		}
	}
	else /* look for the "p" entry in the "a" list */
	{
		this_node = *a;
		while (this_node != NULL)
		{
			if (this_node == p)
			{
				break;
			}
			this_node = this_node->next;
		}
	}

	b->next = this_node->next;
	this_node->next = b;

	return;
}

/*
 * Function: rc_avpair_free
 *
 * Purpose: frees all value_pairs in the list
 *
 */

void rc_avpair_free (VALUE_PAIR *pair)
{
	VALUE_PAIR     *next;

	while (pair != NULL)
	{
		next = pair->next;
		free (pair);
		pair = next;
	}
}

/*
 * Function: rc_fieldcpy
 *
 * Purpose: Copy a data field from the buffer.  Advance the buffer
 *          past the data field. Ensure that no more than len - 1
 *          bytes are copied and that resulting string is terminated
 *          with '\0'.
 *
 */

static void
rc_fieldcpy(char *string, char **uptr, const char *stopat, size_t len)
{
	char *ptr, *estring;

	ptr = *uptr;
	estring = string + len - 1;
	if (*ptr == '"')
	{
		ptr++;
		while (*ptr != '"' && *ptr != '\0' && *ptr != '\n')
		{
			if (string < estring)
				*string++ = *ptr;
			ptr++;
		}
		if (*ptr == '"')
		{
			ptr++;
		}
		*string = '\0';
		*uptr = ptr;
		return;
	}

	while (*ptr != '\0' && strchr(stopat, *ptr) == NULL)
	{
		if (string < estring)
			*string++ = *ptr;
		ptr++;
	}
	*string = '\0';
	*uptr = ptr;
	return;
}


/*
 * Function: rc_avpair_parse
 *
 * Purpose: parses the buffer to extract the attribute-value pairs.
 *
 * Returns: 0 = successful parse of attribute-value pair,
 *	   -1 = syntax (or other) error detected.
 *
 */

#define PARSE_MODE_NAME		0
#define PARSE_MODE_EQUAL	1
#define PARSE_MODE_VALUE	2
#define PARSE_MODE_INVALID	3

int rc_avpair_parse (const rc_handle *rh, char *buffer, VALUE_PAIR **first_pair)
{
	int             mode;
	char            attrstr[AUTH_ID_LEN];
	char            valstr[AUTH_STRING_LEN + 1];
	DICT_ATTR      *attr = NULL;
	DICT_VALUE     *dval;
	VALUE_PAIR     *pair;
	VALUE_PAIR     *link;
	struct tm      *tm;
	time_t          timeval;

	mode = PARSE_MODE_NAME;
	while (*buffer != '\n' && *buffer != '\0')
	{
		if (*buffer == ' ' || *buffer == '\t')
		{
			buffer++;
			continue;
		}

		switch (mode)
		{
		    case PARSE_MODE_NAME:		/* Attribute Name */
			rc_fieldcpy (attrstr, &buffer, " \t\n=,", sizeof(attrstr));
			if ((attr =
				rc_dict_findattr (rh, attrstr)) == NULL)
			{
				rc_log(LOG_ERR, "rc_avpair_parse: unknown attribute");
				if (*first_pair) {
					rc_avpair_free(*first_pair);
					*first_pair = NULL;
				}
				return -1;
			}
			mode = PARSE_MODE_EQUAL;
			break;

		    case PARSE_MODE_EQUAL:		/* Equal sign */
			if (*buffer == '=')
			{
				mode = PARSE_MODE_VALUE;
				buffer++;
			}
			else
			{
				rc_log(LOG_ERR, "rc_avpair_parse: missing or misplaced equal sign");
				if (*first_pair) {
					rc_avpair_free(*first_pair);
					*first_pair = NULL;
				}
				return -1;
			}
			break;

		    case PARSE_MODE_VALUE:		/* Value */
			rc_fieldcpy (valstr, &buffer, " \t\n,", sizeof(valstr));

			if ((pair = malloc (sizeof (VALUE_PAIR))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_avpair_parse: out of memory");
				if (*first_pair) {
					rc_avpair_free(*first_pair);
					*first_pair = NULL;
				}
				return -1;
			}
			strcpy (pair->name, attr->name);
			pair->attribute = attr->value;
			pair->type = attr->type;

			switch (pair->type)
			{

			    case PW_TYPE_STRING:
				strcpy (pair->strvalue, valstr);
				pair->lvalue = (uint32_t)strlen(valstr);
				break;

			    case PW_TYPE_INTEGER:
				if (isdigit (*valstr))
				{
					pair->lvalue = atoi (valstr);
				}
				else
				{
					if ((dval = rc_dict_findval (rh, valstr))
							== NULL)
					{
						rc_log(LOG_ERR, "rc_avpair_parse: unknown attribute value: %s", valstr);
						if (*first_pair) {
							rc_avpair_free(*first_pair);
							*first_pair = NULL;
						}
						free (pair);
						return -1;
					}
					else
					{
						pair->lvalue = dval->value;
					}
				}
				break;

			    case PW_TYPE_IPADDR:
                                pair->lvalue = rc_get_ipaddr(valstr);
				break;

			    case PW_TYPE_DATE:
				timeval = time (0);
				tm = localtime (&timeval);
				tm->tm_hour = 0;
				tm->tm_min = 0;
				tm->tm_sec = 0;
				rc_str2tm (valstr, tm);
#ifdef TIMELOCAL
				pair->lvalue = (uint32_t) timelocal (tm);
#else	/* TIMELOCAL */
				pair->lvalue = (uint32_t) mktime (tm);
#endif	/* TIMELOCAL */
				break;

			    default:
				rc_log(LOG_ERR, "rc_avpair_parse: unknown attribute type %d", pair->type);
				if (*first_pair) {
					rc_avpair_free(*first_pair);
					*first_pair = NULL;
				}
				free (pair);
				return -1;
			}

			/* XXX: Fix up Digest-Attributes */
			switch (pair->attribute) {
			case PW_DIGEST_REALM:
			case PW_DIGEST_NONCE:
			case PW_DIGEST_METHOD:
			case PW_DIGEST_URI:
			case PW_DIGEST_QOP:
			case PW_DIGEST_ALGORITHM:
			case PW_DIGEST_BODY_DIGEST:
			case PW_DIGEST_CNONCE:
			case PW_DIGEST_NONCE_COUNT:
			case PW_DIGEST_USER_NAME:
				/* overlapping! */
				if (pair->lvalue > AUTH_STRING_LEN - 2)
					pair->lvalue = AUTH_STRING_LEN - 2;
				memmove(&pair->strvalue[2], &pair->strvalue[0], pair->lvalue);
				pair->strvalue[0] = pair->attribute - PW_DIGEST_REALM + 1;
				pair->lvalue += 2;
				pair->strvalue[1] = pair->lvalue;
				pair->strvalue[pair->lvalue] = '\0';
				pair->attribute = PW_DIGEST_ATTRIBUTES;
			}

			pair->next = NULL;

			if (*first_pair == NULL)
			{
				*first_pair = pair;
			}
			else
			{
				link = *first_pair;
				while (link->next != NULL)
				{
					link = link->next;
				}
				link->next = pair;
			}

			mode = PARSE_MODE_NAME;
			break;

		    default:
			mode = PARSE_MODE_NAME;
			break;
		}
	}
	return 0;
}

/*
 * Function: rc_avpair_tostr
 *
 * Purpose: Translate an av_pair into two strings
 *
 * Returns: 0 on success, -1 on failure
 *
 */

int rc_avpair_tostr (const rc_handle *rh, VALUE_PAIR *pair, char *name, int ln, char *value, int lv)
{
	DICT_VALUE     *dval;
	char            buffer[32];
	struct in_addr  inad;
	unsigned char         *ptr;

	*name = *value = '\0';

	if (!pair || pair->name[0] == '\0') {
		rc_log(LOG_ERR, "rc_avpair_tostr: pair is NULL or empty");
		return -1;
	}

	strncpy(name, pair->name, (size_t) ln);

	switch (pair->type)
	{
	    case PW_TYPE_STRING:
	    	lv--;
		ptr = (unsigned char *) pair->strvalue;
		if (pair->attribute == PW_DIGEST_ATTRIBUTES) {
			pair->strvalue[*(ptr + 1)] = '\0';
			ptr += 2;
		}
		while (*ptr != '\0')
		{
			if (!(isprint (*ptr)))
			{
				sprintf (buffer, "\\%03o", *ptr);
				strncat(value, buffer, (size_t) lv);
				lv -= 4;
				if (lv < 0) break;
			}
			else
			{
				strncat(value, (char *)ptr, 1);
				lv--;
				if (lv <= 0) break;
			}
			ptr++;
		}
		break;

	    case PW_TYPE_INTEGER:
		dval = rc_dict_getval (rh, pair->lvalue, pair->name);
		if (dval != NULL)
		{
			strncpy(value, dval->name, (size_t) lv-1);
		}
		else
		{
			sprintf (buffer, "%ld", (long int)pair->lvalue);
			strncpy(value, buffer, (size_t) lv);
		}
		break;

	    case PW_TYPE_IPADDR:
		inad.s_addr = htonl(pair->lvalue);
		strncpy (value, inet_ntoa (inad), (size_t) lv-1);
		break;

	    case PW_TYPE_DATE:
		strftime (buffer, sizeof (buffer), "%m/%d/%y %H:%M:%S",
			  gmtime ((time_t *) & pair->lvalue));
		strncpy(value, buffer, lv-1);
		break;

	    default:
		rc_log(LOG_ERR, "rc_avpair_tostr: unknown attribute type %d", pair->type);
		return -1;
		break;
	}

	return 0;
}

/*
 * Function: rc_avpair_log
 *
 * Purpose: format sequence of attribute value pairs into printable
 * string. The caller should provide a storage buffer and the buffer length.
 * Returns pointer to provided storage buffer.
 *
 */
char *
rc_avpair_log(rc_handle *rh, VALUE_PAIR *pair, char *buf, size_t buf_len)
{
	size_t len, nlen;
	VALUE_PAIR *vp;
	char name[33], value[256];

	len = 0;
	for (vp = pair; vp != NULL; vp = vp->next) {
		if (rc_avpair_tostr(rh, vp, name, sizeof(name), value,
		    sizeof(value)) == -1)
		        return NULL;
		nlen = len + 32 + 3 + strlen(value) + 2 + 2;
		if(nlen<buf_len-1) {
			sprintf(buf + len, "%-32s = '%s'\n", name, value);
		} else return buf;
		len = nlen - 1;
	}
	return buf;
}

/*
 * Function: rc_avpair_readin
 *
 * Purpose: get a sequence of attribute value pairs from the file input
 *	    and make them into a list of value_pairs
 *
 */

VALUE_PAIR *rc_avpair_readin(const rc_handle *rh, FILE *input)
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
