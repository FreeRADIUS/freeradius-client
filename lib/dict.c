/*
 * $Id: dict.c,v 1.1 2003/12/02 10:39:20 sobomax Exp $
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
#include <radiusclient.h>

static DICT_ATTR *dictionary_attributes;
static DICT_VALUE *dictionary_values;

/*
 * Function: rc_read_dictionary
 *
 * Purpose: Initialize the dictionary.  Read all ATTRIBUTES into
 *	    the dictionary_attributes list.  Read all VALUES into
 *	    the dictionary_values list.
 *
 */

int rc_read_dictionary (char *filename)
{
	FILE           *dictfd;
	char            dummystr[AUTH_ID_LEN];
	char            namestr[AUTH_ID_LEN];
	char            valstr[AUTH_ID_LEN];
	char            attrstr[AUTH_ID_LEN];
	char            typestr[AUTH_ID_LEN];
	int             line_no;
	DICT_ATTR      *attr;
	DICT_VALUE     *dval;
	char            buffer[256];
	int             value;
	int             type;

	if ((dictfd = fopen (filename, "r")) == (FILE *) NULL)
	{
		rc_log(LOG_ERR, "rc_read_dictionary: couldn't open dictionary %s: %s", 
				filename, strerror(errno));
		return (-1);
	}

	line_no = 0;
	while (fgets (buffer, sizeof (buffer), dictfd) != (char *) NULL)
	{
		line_no++;

		/* Skip empty space */
		if (*buffer == '#' || *buffer == '\0' || *buffer == '\n')
		{
			continue;
		}

		if (strncmp (buffer, "ATTRIBUTE", 9) == 0)
		{

			/* Read the ATTRIBUTE line */
			if (sscanf (buffer, "%s%s%s%s", dummystr, namestr,
				    valstr, typestr) != 4)
			{
				rc_log(LOG_ERR, "rc_read_dictionary: invalid attribute on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
			}

			/*
			 * Validate all entries
			 */
			if (strlen (namestr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR, "rc_read_dictionary: invalid name length on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
			}

			if (!isdigit (*valstr))
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid value on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
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
				return (-1);
			}

			/* Create a new attribute for the list */
			if ((attr =
				(DICT_ATTR *) malloc (sizeof (DICT_ATTR)))
							== (DICT_ATTR *) NULL)
			{
				rc_log(LOG_CRIT, "rc_read_dictionary: out of memory");
				return (-1);
			}
			strcpy (attr->name, namestr);
			attr->value = value;
			attr->type = type;

			/* Insert it into the list */
			attr->next = dictionary_attributes;
			dictionary_attributes = attr;
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
				return (-1);
			}

			/*
			 * Validate all entries
			 */
			if (strlen (attrstr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR,
		      "rc_read_dictionary: invalid attribute length on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
			}

			if (strlen (namestr) > NAME_LENGTH)
			{
				rc_log(LOG_ERR,
			   "rc_read_dictionary: invalid name length on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
			}

			if (!isdigit (*valstr))
			{
				rc_log(LOG_ERR,
				 "rc_read_dictionary: invalid value on line %d of dictionary %s",
					 line_no, filename);
				return (-1);
			}
			value = atoi (valstr);

			/* Create a new VALUE entry for the list */
			if ((dval =
				(DICT_VALUE *) malloc (sizeof (DICT_VALUE)))
							== (DICT_VALUE *) NULL)
			{
				rc_log(LOG_CRIT, "rc_read_dictionary: out of memory");
				return (-1);
			}
			strcpy (dval->attrname, attrstr);
			strcpy (dval->name, namestr);
			dval->value = value;

			/* Insert it into the list */
			dval->next = dictionary_values;
			dictionary_values = dval;
		}
	}
	fclose (dictfd);
	return (0);
} 

/*
 * Function: rc_dict_getattr
 *
 * Purpose: Return the full attribute structure based on the
 *	    attribute id number.
 *
 */
 
DICT_ATTR *rc_dict_getattr (int attribute)
{
	DICT_ATTR      *attr;

	attr = dictionary_attributes;
	while (attr != (DICT_ATTR *) NULL)
	{
		if (attr->value == attribute)
		{
			return (attr);
		}
		attr = attr->next;
	}
	return ((DICT_ATTR *) NULL);
} 

/*
 * Function: rc_dict_findattr
 *
 * Purpose: Return the full attribute structure based on the
 *	    attribute name.
 *
 */

DICT_ATTR *rc_dict_findattr (char *attrname)
{
	DICT_ATTR      *attr;

	attr = dictionary_attributes;
	while (attr != (DICT_ATTR *) NULL)
	{
		if (strcasecmp (attr->name, attrname) == 0)
		{
			return (attr);
		}
		attr = attr->next;
	}
	return ((DICT_ATTR *) NULL);
} 


/*
 * Function: rc_dict_findval
 *
 * Purpose: Return the full value structure based on the
 *         value name.
 *
 */

DICT_VALUE *rc_dict_findval (char *valname)
{
	DICT_VALUE     *val;

	val = dictionary_values;
	while (val != (DICT_VALUE *) NULL)
	{
		if (strcasecmp (val->name, valname) == 0)
		{
			return (val);
		}
		val = val->next;
	}
	return ((DICT_VALUE *) NULL);
}

/*
 * Function: dict_getval
 *
 * Purpose: Return the full value structure based on the
 *          actual value and the associated attribute name.
 *
 */

DICT_VALUE * rc_dict_getval (UINT4 value, char *attrname)
{
	DICT_VALUE     *val;

	val = dictionary_values;
	while (val != (DICT_VALUE *) NULL)
	{
		if (strcmp (val->attrname, attrname) == 0 &&
				val->value == value)
		{
			return (val);
		}
		val = val->next;
	}
	return ((DICT_VALUE *) NULL);
} 
