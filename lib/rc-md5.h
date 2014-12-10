/*
 * md5.h        Structures and prototypes for md5.
 *
 * Version:     $Id: md5.h,v 1.2 2007/06/21 18:07:24 cparker Exp $
 * License:	BSD
 *
 */

#ifndef _RC_MD5_H
#define _RC_MD5_H

#include "config.h"

#ifdef HAVE_NETTLE

#include <nettle/md5-compat.h>

#else

#include "md5.h"

#endif /* HAVE_NETTLE */

void rc_md5_calc(unsigned char *output, unsigned char const *input,
		     size_t inputlen);

#endif /* _RC_MD5_H */
