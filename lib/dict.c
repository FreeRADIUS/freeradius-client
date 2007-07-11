/*
 * $Id: dict.c,v 1.10 2007/07/11 17:29:29 cparker Exp $
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

#include <config.h>
#include <includes.h>
#include <freeradius-client.h>

/*
 * Function: rc_read_dictionary
 *
 * Purpose: Initialize the dictionary.  Read all ATTRIBUTES into
 *	    the dictionary_attributes list.  Read all VALUES into
 *	    the dictionary_values list.
 *
 */

int rc_read_dictionary (rc_handle *rh, const char *filename)
{
	FILE           *dictfd;
	char            dummystr[AUTH_ID_LEN];
	char            namestr[AUTH_ID_LEN];
	char            valstr[AUTH_ID_LEN];
	char            attrstr[AUTH_ID_LEN];
	char            typestr[AUTH_ID_LEN];
	char		optstr[AUTH_ID_LEN];
	char		*cp, *ifilename;
	int             line_no;
	DICT_ATTR      *attr;
	DICT_VALUE     *dval;
	DICT_VENDOR    *dvend;
	char            buffer[256];
	int             value;
	int             type;

	if ((dictfd = fopen (filename, "r")) == NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary: couldn't open dictionary %s: %s",
				filename, strerror(errno));
		return -1;
	}

	line_no = 0;
	while (fgets (buffer, sizeof (buffer), dictfd) != NULL)
	{
		line_no++;

		/* Skip empty space */
		if (*buffer == '#' || *buffer == '\0' || *buffer == '\n' || \
		    *buffer == '\r')
		{
			continue;
		}

		/* Strip out comments */
		cp = strchr(buffer, '#');
		if (cp != NULL)
		{
			*cp = '\0';
		}

		if (strncmp (buffer, "ATTRIBUTE", 9) == 0)
		{
			optstr[0] = '\0';
			/* Read the ATTRIBUTE line */
			if (sscanf (buffer, "%s%s%s%s%s", dummystr, namestr,
				    valstr, typestr, optstr) < 4)
			{
				rc_log(LOG_ERR, "rc_read_dictionary: invalid attribute on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			/*
			 * Validate all entries
			 */
			if (strlen (namestr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR, "rc_read_dictionary: invalid name length on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			if (!isdigit (*valstr))
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid value on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}
			value = atoi (valstr);

			if (strcmp (typestr, "string") == 0)
			{
				type = PW_TYPE_STRING;
			}
			else if (strcmp (typestr, "integer") == 0)
			{
				type = PW_TYPE_INTEGER;
			}
			else if (strcmp (typestr, "ipaddr") == 0)
			{
				type = PW_TYPE_IPADDR;
			}
			else if (strcmp (typestr, "date") == 0)
			{
				type = PW_TYPE_DATE;
			}
			else
			{
				rc_log(LOG_ERR,
				  "rc_read_dictionary: invalid type on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			dvend = NULL;
			if (optstr[0] != '\0') {
				char *cp1;
				for (cp1 = optstr; cp1 != NULL; cp1 = cp) {
					cp = strchr(cp1, ',');
					if (cp != NULL) {
						*cp = '\0';
						cp++;
					}
					if (strncmp(cp1, "vendor=", 7) == 0)
						cp1 += 7;
					dvend = rc_dict_findvend(rh, cp1);
					if (dvend == NULL) {
						rc_log(LOG_ERR,
						 "rc_read_dictionary: unknown Vendor-Id %s on line %d of dictionary %s",
							 cp1, line_no, filename);
						fclose(dictfd);
						return -1;
					}
				}
			}

			/* Create a new attribute for the list */
			if ((attr = malloc (sizeof (DICT_ATTR))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_read_dictionary: out of memory");
				fclose(dictfd);
				return -1;
			}
			strcpy (attr->name, namestr);
			attr->value = value;
			attr->type = type;

			if (dvend != NULL)
				attr->value |= (dvend->vendorpec << 16);

			/* Insert it into the list */
			attr->next = rh->dictionary_attributes;
			rh->dictionary_attributes = attr;
		}
		else if (strncmp (buffer, "VALUE", 5) == 0)
		{
			/* Read the VALUE line */
			if (sscanf (buffer, "%s%s%s%s", dummystr, attrstr,
				    namestr, valstr) != 4)
			{
				rc_log(LOG_ERR,
			   "rc_read_dictionary: invalid value entry on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			/*
			 * Validate all entries
			 */
			if (strlen (attrstr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR,
		      "rc_read_dictionary: invalid attribute length on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			if (strlen (namestr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR,
			   "rc_read_dictionary: invalid name length on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			if (!isdigit (*valstr))
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid value on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}
			value = atoi (valstr);

			/* Create a new VALUE entry for the list */
			if ((dval = malloc (sizeof (DICT_VALUE))) == NULL)
			{
				rc_log(LOG_CRIT, "rc_read_dictionary: out of memory");
				fclose(dictfd);
				return -1;
			}
			strcpy (dval->attrname, attrstr);
			strcpy (dval->name, namestr);
			dval->value = value;

			/* Insert it into the list */
			dval->next = rh->dictionary_values;
			rh->dictionary_values = dval;
		}
                else if (strncmp (buffer, "$INCLUDE", 8) == 0)
                {
			/* Read the $INCLUDE line */
			if (sscanf (buffer, "%s%s", dummystr, namestr) != 2)
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid include entry on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}
			ifilename = namestr;
			/* Append directory if necessary */
			if (namestr[0] != '/') {
				cp = strrchr(filename, '/');
				if (cp != NULL) {
					ifilename = alloca(AUTH_ID_LEN);
					*cp = '\0';
					sprintf(ifilename, "%s/%s", filename, namestr);
					*cp = '/';
				}
			}
			if (rc_read_dictionary(rh, ifilename) < 0)
			{
				fclose(dictfd);
				return -1;
			}
		}
		else if (strncmp (buffer, "VENDOR", 6) == 0)
		{
			/* Read the VALUE line */
			if (sscanf (buffer, "%s%s%s", dummystr, attrstr, valstr) != 3)
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid Vendor-Id on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			/* Validate all entries */
			if (strlen (attrstr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid attribute length on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}

			if (!isdigit (*valstr))
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid Vendor-Id on line %d of dictionary %s",
					 line_no, filename);
				fclose(dictfd);
				return -1;
			}
			value = atoi (valstr);

			/* Create a new VENDOR entry for the list */
			dvend = malloc(sizeof(DICT_VENDOR));
			if (dvend == NULL)
			{
				rc_log(LOG_CRIT, "rc_read_dictionary: out of memory");
				fclose(dictfd);
				return -1;
			}
			strcpy (dvend->vendorname, attrstr);
			dvend->vendorpec = value;

			/* Insert it into the list */
			dvend->next = rh->dictionary_vendors;
			rh->dictionary_vendors = dvend;
                }
	}
	fclose (dictfd);
	return 0;
}

/*
 * Function: rc_dict_getattr
 *
 * Purpose: Return the full attribute structure based on the
 *	    attribute id number.
 *
 */

DICT_ATTR *rc_dict_getattr (const rc_handle *rh, int attribute)
{
	DICT_ATTR      *attr;

	attr = rh->dictionary_attributes;
	while (attr != NULL)
	{
		if (attr->value == attribute)
		{
			return attr;
		}
		attr = attr->next;
	}
	return NULL;
}

/*
 * Function: rc_dict_findattr
 *
 * Purpose: Return the full attribute structure based on the
 *	    attribute name.
 *
 */

DICT_ATTR *rc_dict_findattr (const rc_handle *rh, const char *attrname)
{
	DICT_ATTR      *attr;

	attr = rh->dictionary_attributes;
	while (attr != NULL)
	{
		if (strcasecmp (attr->name, attrname) == 0)
		{
			return attr;
		}
		attr = attr->next;
	}
	return NULL;
}


/*
 * Function: rc_dict_findval
 *
 * Purpose: Return the full value structure based on the
 *         value name.
 *
 */

DICT_VALUE *rc_dict_findval (const rc_handle *rh, const char *valname)
{
	DICT_VALUE     *val;

	val = rh->dictionary_values;
	while (val != NULL)
	{
		if (strcasecmp (val->name, valname) == 0)
		{
			return val;
		}
		val = val->next;
	}
	return NULL;
}

/*
 * Function: rc_dict_findvend
 *
 * Purpose: Return the full vendor structure based on the
 *          vendor name.
 *
 */

DICT_VENDOR *
rc_dict_findvend(const rc_handle *rh, const char *vendorname)
{
	DICT_VENDOR	*vend;

	for (vend = rh->dictionary_vendors; vend != NULL; vend = vend->next)
		if (strcasecmp(vend->vendorname, vendorname) == 0)
			return vend;
	return NULL;
}

/*
 * Function: rc_dict_getvend
 *
 * Purpose: Return the full vendor structure based on the
 *          vendor id number.
 *
 */

DICT_VENDOR *
rc_dict_getvend (const rc_handle *rh, int vendorpec)
{
        DICT_VENDOR      *vend;

	for (vend = rh->dictionary_vendors; vend != NULL; vend = vend->next)
		if (vend->vendorpec == vendorpec)
			return vend;
	return NULL;
}

/*
 * Function: dict_getval
 *
 * Purpose: Return the full value structure based on the
 *          actual value and the associated attribute name.
 *
 */

DICT_VALUE *
rc_dict_getval (const rc_handle *rh, uint32_t value, const char *attrname)
{
	DICT_VALUE     *val;

	val = rh->dictionary_values;
	while (val != NULL)
	{
		if (strcmp (val->attrname, attrname) == 0 &&
				val->value == value)
		{
			return val;
		}
		val = val->next;
	}
	return NULL;
}

/*
 * Function: rc_dict_free
 *
 * Purpose: Free allocated av lists
 *
 * Arguments: Radius Client handle
 */

void
rc_dict_free(rc_handle *rh)
{
	DICT_ATTR	*attr, *nattr;
	DICT_VALUE	*val, *nval;
	DICT_VENDOR	*vend, *nvend;

	for (attr = rh->dictionary_attributes; attr != NULL; attr = nattr) {
		nattr = attr->next;
		free(attr);
	}
	for (val = rh->dictionary_values; val != NULL; val = nval) {
		nval = val->next;
		free(val);
	}
	for (vend = rh->dictionary_vendors; vend != NULL; vend = nvend) {
		nvend = vend->next;
		free(vend);
	}
	rh->dictionary_attributes = NULL;
	rh->dictionary_values = NULL;
	rh->dictionary_vendors = NULL;
}
