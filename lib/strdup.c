/*
 * $Id: strdup.c,v 1.1 2003/12/02 10:39:17 sobomax Exp $
 *
 * Copyright (C) 1996 Lars Fenneberg and Christian Graefe
 *
 * This file is provided under the terms and conditions of the GNU general 
 * public license, version 2 or any later version, incorporated herein by 
 * reference. 
 *
 */

#include "config.h"
#include "includes.h"

/*
 * Function: strdup
 *
 * Purpose:  strdup replacement for systems which lack it
 *
 */

char *strdup(char *str)
{
	char *p;

	if (str == NULL)
		return NULL;

	if ((p = (char *)malloc(strlen(str)+1)) == NULL)
		return p;

	return strcpy(p, str);	
}
