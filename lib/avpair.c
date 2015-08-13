/*
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
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
#include <radcli/radcli.h>
#include "util.h"

#define PARSE_MODE_NAME		0
#define PARSE_MODE_EQUAL	1
#define PARSE_MODE_VALUE	2
#define PARSE_MODE_INVALID	3

/**
 * @defgroup radcli-api Main API
 * @brief Main API Functions
 *
 * @{
 */

/** Adds an attribute-value pair to the given list
 *
 * See rc_avpair_assign() for the format of the data.
 *
 * @note It always appends the new pair to the end of the list.
 *
 * @param rh a handle to parsed configuration.
 * @param list a VALUE_PAIR array of values; initially must be NULL.
 * @param attrid The attribute of the pair to add (e.g., PW_USER_NAME).
 * @param pval the value (e.g., the actual username).
 * @param len the length of pval, or -1 if to calculate (in case of strings).
 * @param vendorpec The vendor ID in case of a vendor specific value - 0 otherwise.
 * @return pointer to added a/v pair upon success, NULL pointer upon failure.
 */
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

/** Iterates through the attribute-value pairs
 *
 * The attribute-value are organized in a linked-list, and this
 * function provides a way to iterate them given the first element
 * initially.
 *
 * @param t the current pair.
 * @return pointer to the next pair, or NULL when finished.
 */
VALUE_PAIR *rc_avpair_next (VALUE_PAIR *t)
{
	return t->next;
}

/** Assigns the given value to an attribute-value pair
 *
 * If the value is of type PW_TYPE_STRING it must either be
 * a null terminated string with len set to -1, or raw data
 * with length properly set. For PW_TYPE_DATE, PW_TYPE_INTEGER,
 * and PW_TYPE_IPADDR an uint32_t number should be set at pval.
 * For IPv4 addresses it should be in host byte order.
 *
 * For PW_TYPE_IPV6ADDR type a 16-byte long address is expected, and
 * for PW_TYPE_IPV6PREFIX the rfc3162 prefix format is expected. Simply
 * that is a zero byte, a byte with the value of prefix (e.g., 112), and
 * the remaining bytes are the IPv6 address.
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param pval the value (e.g., the actual username).
 * @param len the length of pval, or -1 if to calculate (in case of strings).
 * @return 0 on success or -1 on failure.
 */
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
			rc_log(LOG_ERR, "rc_avpair_assign: no attribute %d in dictionary", vp->type);
			return -1;
	}
	return 0;
}

/** Make a new attribute-value pair with given parameters
 *
 * See rc_avpair_assign() for the format of the data.
 *
 * @param rh a handle to parsed configuration.
 * @param attrid The attribute of the pair to add (e.g., PW_USER_NAME).
 * @param pval the value (e.g., the actual username).
 * @param len the length of pval, or -1 if to calculate (in case of strings).
 * @param vendorpec The vendor ID in case of a vendor specific value - 0 otherwise.
 * @return pointer to generated a/v pair when successful, NULL when failure.
 */
VALUE_PAIR *rc_avpair_new (rc_handle const *rh, int attrid, void const *pval, int len, int vendorpec)
{
	VALUE_PAIR     *vp = NULL;
	DICT_ATTR      *pda;
        int vattrid;

        if(vendorpec != VENDOR_NONE) {
                vattrid = attrid | (vendorpec << 16);
        } else {
                vattrid = attrid;
        }
	if ((pda = rc_dict_getattr (rh, vattrid)) == NULL)
	{
                rc_log(LOG_ERR,"rc_avpair_new: no attribute %d/%u in dictionary",
                       vendorpec,attrid);
                return NULL;
	}
	if (vendorpec != 0 && rc_dict_getvend(rh, vendorpec) == NULL)
	{
		rc_log(LOG_ERR,"rc_avpair_new: no Vendor-Id %d in dictionary", vendorpec);
		return NULL;
	}
	if ((vp = malloc (sizeof (VALUE_PAIR))) != NULL)
	{
		strlcpy (vp->name, pda->name, sizeof (vp->name));
		vp->attribute = vattrid;
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

/** Takes attribute/value pairs from buffer and builds a value_pair list using allocated memory
 *
 * @note Uses recursion.
 *
 * @param rh a handle to parsed configuration.
 * @param pair a pointer to a VALUE_PAIR structure.
 * @param ptr the value (e.g., the actual username).
 * @param length the length of ptr, or -1 if to calculate (in case of strings).
 * @param vendorpec The vendor ID in case of a vendor specific value - 0 otherwise.
 * @return value_pair list or NULL on failure.
 */
VALUE_PAIR *rc_avpair_gen(rc_handle const *rh, VALUE_PAIR *pair, unsigned char const *ptr,
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
			goto skipit;
		}
		memcpy(&lvalue, ptr, 4);
		vendorpec = ntohl(lvalue);
		if (rc_dict_getvend(rh, vendorpec) == NULL) {
			/* Warn and skip over the unknown VSA */
			rc_log(LOG_WARNING, "rc_avpair_gen: received VSA "
			    "attribute with unknown Vendor-Id %d", vendorpec);
			goto skipit;
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
		goto skipit;
	}

	rpair = calloc(1, sizeof(*rpair));
	if (rpair == NULL) {
		rc_log(LOG_CRIT, "rc_avpair_gen: out of memory");
		goto shithappens;
	}

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
			goto skipit;
		}
	case PW_TYPE_IPADDR:
		if (attrlen != 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPADDR"
			    " attribute with invalid length");
			goto skipit;
		}
		memcpy((char *)&lvalue, (char *)ptr, 4);
		pair->lvalue = ntohl(lvalue);
		break;
	case PW_TYPE_IPV6ADDR:
		if (attrlen != 16) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPV6ADDR"
			    " attribute with invalid length");
			goto skipit;
		}
		memcpy(pair->strvalue, (char *)ptr, 16);
		pair->lvalue = attrlen;
		break;
	case PW_TYPE_IPV6PREFIX:
		if (attrlen > 18 || attrlen < 2) {
			rc_log(LOG_ERR, "rc_avpair_gen: received IPV6PREFIX"
			    " attribute with invalid length: %d", attrlen);
			goto skipit;
		}
		memcpy(pair->strvalue, (char *)ptr, attrlen);
		pair->lvalue = attrlen;
		break;
	case PW_TYPE_DATE:
		if (attrlen != 4) {
			rc_log(LOG_ERR, "rc_avpair_gen: received DATE "
			    "attribute with invalid length");
			goto skipit;
		}

	default:
		rc_log(LOG_WARNING, "rc_avpair_gen: %s has unknown type",
		    attr->name);
		goto skipit;
	}

skipit:
	return pair;

shithappens:
	while (pair != NULL) {
		rpair = pair->next;
		free(pair);
		pair = rpair;
	}
	return NULL;
}

/** Find the first attribute value-pair (which matches the given attribute) from the specified value-pair list
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param attrid The attribute of the pair to find (e.g., PW_USER_NAME).
 * @param vendorpec The vendor ID in case of a vendor specific value - 0 otherwise.
 * @return the value pair found.
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
 * Function: rc_avpair_copy
 *
 * Purpose: Return a copy of the existing list "p" ala strdup().
 *
 */
VALUE_PAIR *rc_avpair_copy(VALUE_PAIR *p)
{
	VALUE_PAIR *vp, *fp = NULL, *lp = NULL;

	while (p) {
		vp = malloc(sizeof(VALUE_PAIR));
		if (!vp) {
                  rc_log(LOG_CRIT, "rc_avpair_copy: out of memory");
                  return NULL;  /* could leak pairs already copied */
		}
		*vp = *p;
		if (!fp)
			fp = vp;
		if (lp)
			lp->next = vp;
		lp = vp;
		p = p->next;
	}

	return fp;
}

/** Insert a VALUE_PAIR into a list
 *
 * Given the address of an existing list "a" and a pointer to an entry "p" in that list, add the value pair "b" to
 * the "a" list after the "p" entry.  If "p" is NULL, add the value pair "b" to the end of "a".
 *
 * @param a a VALUE_PAIR array of values.
 * @param p a pointer to a VALUE_PAIR in a.
 * @param b The VALUE_PAIR pointer to add in a.
 */
void rc_avpair_insert(VALUE_PAIR **a, VALUE_PAIR *p, VALUE_PAIR *b)
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

/** Frees all value_pairs in the list
 *
 * @param pair a pointer to a VALUE_PAIR structure.
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

/** Copy a data field from the buffer
 *
 * Advance the buffer past the data field. Ensure that no more than len - 1 bytes are copied and that resulting
 * string is terminated with '\0'.
 *
 * @param string the provided string to copy.
 * @param uptr the current position of the buffer.
 * @param stopat characters to which parsing should stop.
 * @param len the maximum length of string.
 */
static void rc_fieldcpy(char *string, char const **uptr, char const *stopat, size_t len)
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

/** Parses the buffer to extract the attribute-value pairs
 *
 * @param rh a handle to parsed configuration.
 * @param buffer the buffer to be parsed.
 * @param first_pair an allocated array of values.
 * @return 0 on successful parse of attribute-value pair, or -1 on syntax (or other) error detected.
 */
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
			    	if (inet_pton(AF_INET, valstr, &pair->lvalue) == 0) {
			    		rc_log(LOG_ERR, "rc_avpair_parse: invalid IPv4 address %s", valstr);
			    		free(pair);
			    		return -1;
			    	}

                                pair->lvalue = ntohl(pair->lvalue);
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
				break;
			default:
				break;
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

/** Translate an av_pair into printable strings
 *
 * @param rh a handle to parsed configuration.
 * @param pair a pointer to a VALUE_PAIR structure.
 * @param name the name of the pair.
 * @param ln the size of name.
 * @param value the value of the pair.
 * @param lv the size of value.
 * @return 0 on success, -1 on failure.
 */
int rc_avpair_tostr (rc_handle const *rh, VALUE_PAIR *pair, char *name, int ln, char *value, int lv)
{
	DICT_VALUE     *dval;
	struct in_addr  inad;
	unsigned char  *ptr;
	unsigned int    pos;

	*name = *value = '\0';

	if (!pair || pair->name[0] == '\0') {
		rc_log(LOG_ERR, "rc_avpair_tostr: pair is NULL or empty");
		return -1;
	}

	strlcpy(name, pair->name, (size_t) ln);

	switch (pair->type)
	{
	    case PW_TYPE_STRING:
	    	lv--;
	    	pos = 0;
		ptr = (unsigned char *) pair->strvalue;
		if (pair->attribute == PW_DIGEST_ATTRIBUTES) {
			pair->strvalue[*(ptr + 1)] = '\0';
			ptr += 2;
		}
		while (*ptr != '\0')
		{
			if (!(isprint (*ptr)))
			{
				if (lv >= 4) {
					snprintf (&value[pos], lv, "\\%03o", *ptr);
					pos += 4;
					lv -= 4;
				} else {
					break;
				}
			}
			else
			{
				if (lv > 0) {
					value[pos++] = *ptr;
					lv--;
				} else {
					break;
				}
			}
			ptr++;
		}
		if (lv > 0)
			value[pos++] = 0;
		else
			value[pos-1] = 0;
		break;

	    case PW_TYPE_INTEGER:
		dval = rc_dict_getval (rh, pair->lvalue, pair->name);
		if (dval != NULL)
		{
			strlcpy(value, dval->name, (size_t) lv);
		}
		else
		{
			snprintf(value, lv, "%ld", (long int)pair->lvalue);
		}
		break;

	    case PW_TYPE_IPADDR:
		inad.s_addr = htonl(pair->lvalue);
		strlcpy (value, inet_ntoa (inad), (size_t) lv);
		break;

	    case PW_TYPE_IPV6ADDR:
	    	if (inet_ntop(AF_INET6, pair->strvalue, value, lv) == NULL)
	    		return -1;
		break;

	    case PW_TYPE_IPV6PREFIX: {
	    	uint8_t ip[16];
	    	uint8_t txt[48];
	    	if (pair->lvalue < 2)
	    		return -1;

	    	memset(ip, 0, sizeof(ip));
	    	memcpy(ip, pair->strvalue+2, pair->lvalue-2);

	    	if (inet_ntop(AF_INET6, ip, (void*)txt, sizeof(txt)) == NULL)
	    		return -1;
		snprintf(value, lv, "%s/%u", txt, (unsigned)pair->strvalue[1]);

		break;
	    }
	    case PW_TYPE_DATE:
		strftime (value, lv, "%m/%d/%y %H:%M:%S",
			  gmtime ((time_t *) & pair->lvalue));
		break;

	    default:
		rc_log(LOG_ERR, "rc_avpair_tostr: unknown attribute type %d", pair->type);
		return -1;
		break;
	}

	return 0;
}

/** Format a sequence of attribute value pairs into a printable string
 *
 * The caller should provide a storage buffer and the buffer length.
 *
 * @param rh a handle to parsed configuration.
 * @param pair a pointer to a VALUE_PAIR structure.
 * @param buf will hold the string output of the pair.
 * @param buf_len the size of buf.
 * @return a pointer to provided storage buffer.
 */
char *rc_avpair_log(rc_handle const *rh, VALUE_PAIR *pair, char *buf, size_t buf_len)
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

/** Get the integer value of the given attribute value-pair
 *
 * This function is valid for PW_TYPE_INTEGER, PW_TYPE_IPADDR.
 * PW_TYPE_DATE. In PW_TYPE_IPADDR this value will contain the
 * IPv4 address in host by order.
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param res The integer value returned.
 * @return zero on success or -1 on failure.
 */
int rc_avpair_get_uint32 (VALUE_PAIR *vp, uint32_t *res)
{
	if (vp->type == PW_TYPE_DATE || vp->type == PW_TYPE_IPADDR ||
	    vp->type == PW_TYPE_INTEGER) {
	    	if (res)
		    *res = vp->lvalue;
		return 0;
	} else {
		return -1;
	}
}

/** Get the IPv6 address and prefix value of the given attribute value-pair
 *
 * This function is valid for PW_TYPE_IPV6ADDR, PW_TYPE_IPV6PREFIX.
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param res An in6_addr structure for result to be copied in.
 * @param prefix If of type PW_TYPE_IPV6PREFIX the prefix will be copied (may be NULL).
 * @return zero on success or -1 on failure.
 */
int rc_avpair_get_in6 (VALUE_PAIR *vp, struct in6_addr *res, unsigned *prefix)
{
	if (vp->type == PW_TYPE_IPV6ADDR) {
		memcpy(res, vp->strvalue, 16);
		return 0;
	} else if (vp->type == PW_TYPE_IPV6PREFIX) {
	    	if (vp->lvalue < 2 || vp->lvalue > 18)
	    		return -1;

		if (res) {
		    	memset(res, 0, 16);
		    	memcpy(res, vp->strvalue+2, vp->lvalue-2);
		}

		if (prefix)
		    	*prefix = (unsigned char)vp->strvalue[1];
	    	return 0;
	}

	return -1;
}

/** Get the raw value of the given attribute value-pair
 *
 * This function is valid for PW_TYPE_STRING, PW_TYPE_IPV6ADDR,
 * PW_TYPE_IPV6PREFIX.
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param res Will contain pointer to the data value.
 * @param res_size Will contain the data size.
 * @return zero on success or -1 on failure.
 */
int rc_avpair_get_raw (VALUE_PAIR *vp, char **res, unsigned *res_size)
{
	if (vp->type == PW_TYPE_STRING || vp->type == PW_TYPE_IPV6ADDR ||
	    vp->type == PW_TYPE_IPV6PREFIX) {
	    	if (res)
	    		*res = vp->strvalue;
		if (res_size)
			*res_size = vp->lvalue;
		return 0;
	} else {
		return -1;
	}
}

/** Get the attribute ID and type of the given attribute value-pair
 *
 * @param vp a pointer to a VALUE_PAIR structure.
 * @param type The attribute type, of type rc_attr_type
 * @param id The attribute identifier, of type rc_attr_id
 */
void rc_avpair_get_attr (VALUE_PAIR *vp, unsigned *type, unsigned *id)
{
	if (type)
		*type = vp->type;
	if (id)
		*id = vp->attribute;
}

/** @} */
/*
 * Local Variables:
 * c-basic-offset:8
 * c-style: whitesmith
 * End:
 */
