/*
 * $Id: memcmp.c,v 1.2 2004/02/23 20:10:39 sobomax Exp $
 *
 * Taken from the Linux kernel. GPL applies.
 * Copyright (C) 1991, 1992  Linus Torvalds
 *
 */

#include "config.h"
#include "includes.h"

int memcmp(const void * cs,const void * ct,size_t count)
{
	const unsigned char *su1, *su2;
	signed char res = 0;

	for( su1 = cs, su2 = ct; 0 < count; ++su1, ++su2, count--)
		if ((res = *su1 - *su2) != 0)
			break;
        return res;
}
