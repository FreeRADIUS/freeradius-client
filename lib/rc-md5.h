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
#include <stdlib.h>

#ifdef HAVE_NETTLE

#include <nettle/md5-compat.h>

#else

#include "md5.h"

#endif /* HAVE_NETTLE */

#endif /* _RC_MD5_H */
