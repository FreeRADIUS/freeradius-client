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

/**
 * rc_avpair_add:
 * @rh: a handle to parsed configuration
 * @list: a #VALUE_PAIR array of values; initially must be %NULL
 * @attrid: The attribute of the pair to add (e.g., %PW_USER_NAME)
 * @pval: the value (e.g., the actual username)
 * @len: the length of @pval, or -1 if to calculate (in case of strings)
 * @vendorpec: The vendor ID in case of a vendor specific value - 0 otherwise
 *
 * Adds an attribute-value pair to the given list.
 *
 * Remarks: Always appends the new pair to the end of the list.
 *
 * Returns: pointer to added a/v pair upon success, NULL pointer upon failure.
 *
 **/

VALUE_PAIR *rc_avpair_add (rc_handle const *rh, VALUE_PAIR **list, int attrid, void const *pval, int len, int vendorpec)
{
	VALUE_PAIR     *vp;

	vp = rc_avpair_new (rh, attrid, pval, len, vendorpec);

	if (vp != NULL)
	{
		rc_avpair_insert (list, NULL, vp);
	}

	return vp;

}

/**
 * rc_avpair_assign:
 * @vp: a pointer to a #VALUE_PAIR structure
 * @pval: the value (e.g., the actual username)
 * @len: the length of @pval, or -1 if to calculate (in case of strings)
 *
 * Assigns the given value to an attribute-value pair.
 *
 * Returns: 0 on success or -1 on failure.
 **/

int rc_avpair_assign (VALUE_PAIR *vp, void const *pval, int len)
{

	switch (vp->type)
	{
		case PW_TYPE_STRING:
			if (len == -1)
				len = (uint32_t)strlen((char const *)pval);
			if (len > AUTH_STRING_LEN) {
		        	rc_log(LOG_ERR, "rc_avpair_assign: bad attribute length");
		        	return -1;
			}
			memcpy(vp->strvalue, (char const *)pval, len);
			vp->strvalue[len] = '\0';
			vp->lvalue = len;
			break;

		case PW_TYPE_DATE:
		case PW_TYPE_INTEGER:
	        case PW_TYPE_IPADDR:
			vp->lvalue = * (uint32_t *) pval;
			break;
	        case PW_TYPE_IPV6ADDR:
			if (len != 16) {
		        	rc_log(LOG_ERR, "rc_avpair_assign: bad IPv6 length");
		        	return -1;
			}
			memcpy(vp->strvalue, (char const *)pval, len);
			vp->lvalue = len;
			break;

	        case PW_TYPE_IPV6PREFIX:
			if (len < 2 || len > 18) {
		        	rc_log(LOG_ERR, "rc_avpair_assign: bad IPv6 prefix length");
		        	return -1;
			}
			memcpy(vp->strvalue, (char const *)pval, len);
			vp->lvalue = len;
			break;

		default:
			rc_log(LOG_ERR, "rc_avpair_assign: unknown attribute %d", vp->type);
			return -1;
	}
	return 0;
}

/**
 * rc_avpair_new:
 * @rh: a handle to parsed configuration
 * @attrid: The attribute of the pair to add (e.g., %PW_USER_NAME)
 * @pval: the value (e.g., the actual username)
 * @len: the length of @pval, or -1 if to calculate (in case of strings)
 * @vendorpec: The vendor ID in case of a vendor specific value - 0 otherwise
 *
 * Make a new attribute-value pair with given parameters.
 *
 * Returns: pointer to generated a/v pair when successful, NULL when failure.
 *
 **/

VALUE_PAIR *rc_avpair_new (rc_handle const *rh, int attrid, void const *pval, int len, int vendorpec)
{
	VALUE_PAIR     *vp = NULL;
	DICT_ATTR      *pda;

	attrid = attrid | (vendorpec << 16);
	if ((pda = rc_dict_getattr (rh, attrid)) == NULL)
	{
		rc_log(LOG_ERR,"rc_avpair_new: unknown attribute %d", attrid);
		return NULL;
	}
	if (vendorpec != 0 && rc_dict_getvend(rh, vendorpec) == NULL)
	{
		rc_log(LOG_ERR,"rc_avpair_new: unknown Vendor-Id %d", vendorpec);
		return NULL;
	}
	if ((vp = malloc (sizeof (VALUE_PAIR))) != NULL)
	{
		strncpy (vp->name, pda->name, sizeof (vp->name));
		vp->attribute = attrid;
		vp->next = NULL;
		vp->type = pda->type;
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

/**
 * rc_avpair_gen:
 * @rh: a handle to parsed configuration
 * @pair: a pointer to a #VALUE_PAIR structure
 * @ptr: the value (e.g., the actual username)
 * @length: the length of @ptr, or -1 if to calculate (in case of strings)
 * @vendorpec: The vendor ID in case of a vendor specific value - 0 otherwise
 *
 * Takes attribute/value pairs from buffer and builds a
 * value_pair list using allocated memory. Uses recursion.
 *
 * Returns: value_pair list or %NULL on failure
 **/

VALUE_PAIR *
rc_avpair_gen(rc_handle const *rh, VALUE_PAIR *pair, unsigned char const *ptr,
    int length, int vendorpec)
{
	int attribute, attrlen, x_len;
	unsigned char const *x_ptr;
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
			snprintf(hex, sizeof(hex), "%2.2X", x_ptr[0]);
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

	switch (attr->type) {
	case PW_TYPE_STRING:
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
		pair->lvalue = ntohl(lvalue);
		break;
	case PW_TYPE_IPV6ADDR:
		if (attrlen != 16) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPV6ADDR"
			    " attribute with invalid length");
			goto shithappens;
		}
		memcpy(pair->strvalue, (char *)ptr, 16);
		pair->lvalue = attrlen;
		break;
	case PW_TYPE_IPV6PREFIX:
		if (attrlen > 18 || attrlen < 2) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPV6PREFIX"
			    " attribute with invalid length: %d", attrlen);
			goto shithappens;
		}
		memcpy(pair->strvalue, (char *)ptr, attrlen);
		pair->lvalue = attrlen;
		break;
	case PW_TYPE_DATE:
		if (attrlen != 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received DATE "
			    "attribute with invalid length");
			goto shithappens;
		}

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

/**
 * rc_avpair_get:
 * @vp: a pointer to a #VALUE_PAIR structure
 * @attrid: The attribute of the pair to find (e.g., %PW_USER_NAME)
 * @vendorpec: The vendor ID in case of a vendor specific value - 0 otherwise
 *
 * Find the first attribute value-pair (which matches the given
 * attribute) from the specified value-pair list.
 *
 * Returns: the value pair found
 **/

VALUE_PAIR *rc_avpair_get (VALUE_PAIR *vp, int attrid, int vendorpec)
{
	for (; vp != NULL && !(ATTRID(vp->attribute) == ATTRID(attrid) &&
	    VENDOR(vp->attribute) == vendorpec); vp = vp->next)
	{
		continue;
	}
	return vp;
}

/**
 * rc_avpair_insert:
 * @a: a #VALUE_PAIR array of values
 * @p: a pointer to a #VALUE_PAIR in @a
 * @b: The #VALUE_PAIR pointer to add in @a
 *
 * Given the address of an existing list "a" and a pointer
 * to an entry "p" in that list, add the value pair "b" to
 * the "a" list after the "p" entry.  If "p" is NULL, add
 * the value pair "b" to the end of "a".
 *
 **/

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

/**
 * rc_avpair_free:
 * @pair: a pointer to a #VALUE_PAIR structure
 *
 * Frees all value_pairs in the list.
 *
 **/

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

/*-
 * rc_fieldcpy:
 * @string: the provided string to copy
 * @uptr: the current position of the buffer
 * @stopat: characters to which parsing should stop
 * @len: the maximum length of @string
 *
 * Copy a data field from the buffer.  Advance the buffer
 * past the data field. Ensure that no more than len - 1
 * bytes are copied and that resulting string is terminated
 * with '\0'.
 *
 -*/

static void
rc_fieldcpy(char *string, char const **uptr, char const *stopat, size_t len)
{
	char const *ptr, *estring;

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


/**
 * rc_avpair_parse:
 * @rh: a handle to parsed configuration
 * @buffer: the buffer to be parsed
 * @first_pair: an allocated array of values
 *
 * Parses the buffer to extract the attribute-value pairs.
 *
 * Returns: 0 on successful parse of attribute-value pair, or -1 on syntax (or other) error detected.
 *
 **/

#define PARSE_MODE_NAME		0
#define PARSE_MODE_EQUAL	1
#define PARSE_MODE_VALUE	2
#define PARSE_MODE_INVALID	3

int rc_avpair_parse (rc_handle const *rh, char const *buffer, VALUE_PAIR **first_pair)
{
	int             mode;
	char            attrstr[AUTH_ID_LEN];
	char            valstr[AUTH_STRING_LEN + 1], *p;
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

			    case PW_TYPE_IPV6ADDR:
			    	if (inet_pton(AF_INET6, valstr, pair->strvalue) == 0) {
			    		rc_log(LOG_ERR, "rc_avpair_parse: invalid IPv6 address %s", valstr);
			    		free(pair);
			    		return -1;
			    	}
				pair->lvalue = 16;
				break;

			    case PW_TYPE_IPV6PREFIX:
			    	p = strchr(valstr, '/');
			    	if (p == NULL) {
			    		rc_log(LOG_ERR, "rc_avpair_parse: invalid IPv6 prefix %s", valstr);
			    		free(pair);
			    		return -1;
			    	}
			    	*p = 0;
			    	p++;
			    	pair->strvalue[0] = 0;
			    	pair->strvalue[1] = atoi(p);

			    	if (inet_pton(AF_INET6, valstr, pair->strvalue+2) == 0) {
			    		rc_log(LOG_ERR, "rc_avpair_parse: invalid IPv6 prefix %s", valstr);
			    		free(pair);
			    		return -1;
			    	}
				pair->lvalue = 2+16;
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

/**
 * rc_avpair_tostr:
 * @rh: a handle to parsed configuration
 * @pair: a pointer to a #VALUE_PAIR structure
 * @name: the name of the @pair
 * @ln: the size of @name
 * @value: the value of the @pair
 * @lv: the size of @value
 *
 * Translate an av_pair into two strings.
 *
 * Returns: 0 on success, -1 on failure
 *
 **/

int rc_avpair_tostr (rc_handle const *rh, VALUE_PAIR *pair, char *name, int ln, char *value, int lv)
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
				snprintf (buffer, sizeof(buffer), "\\%03o", *ptr);
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
			snprintf(buffer, sizeof(buffer), "%ld", (long int)pair->lvalue);
			strncpy(value, buffer, (size_t) lv);
		}
		break;

	    case PW_TYPE_IPADDR:
		inad.s_addr = htonl(pair->lvalue);
		strncpy (value, inet_ntoa (inad), (size_t) lv-1);
		break;

	    case PW_TYPE_IPV6ADDR:
	    	if (inet_ntop(AF_INET6, pair->strvalue, value, lv-1) == NULL)
	    		return -1;
		break;

	    case PW_TYPE_IPV6PREFIX: {
	    	uint8_t ip[16];
	    	uint8_t txt[48];
	    	if (pair->lvalue < 2)
	    		return -1;

	    	memset(ip, 0, sizeof(ip));
	    	memcpy(ip, pair->strvalue+2, pair->lvalue-2);

	    	if (inet_ntop(AF_INET6, ip, txt, sizeof(txt)) == NULL)
	    		return -1;
		snprintf(value, lv-1, "%s/%u", txt, (unsigned)pair->strvalue[1]);

		break;
	    }
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

/**
 * rc_avpair_log:
 * @rh: a handle to parsed configuration
 * @pair: a pointer to a #VALUE_PAIR structure
 * @buf: will hold the string output of the @pair
 * @len: the size of @buf
 *
 * Format a sequence of attribute value pairs into a printable
 * string. The caller should provide a storage buffer and the buffer length.
 *
 * Returns: a pointer to provided storage buffer.
 *
 **/
char *
rc_avpair_log(rc_handle const *rh, VALUE_PAIR *pair, char *buf, size_t buf_len)
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

/**
 * rc_avpair_readin:
 * @rh: a handle to parsed configuration
 * @input: a %FILE handle
 *
 * Get a sequence of attribute value pairs from the file input
 * and make them into a list of value_pairs.
 *
 * Returns: the array of value pairs
 *
 **/

VALUE_PAIR *rc_avpair_readin(rc_handle const *rh, FILE *input)
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
