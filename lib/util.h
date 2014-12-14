/*
 * util.h        Utility structures and prototypes.
 *
 * License:	BSD
 *
 */

#ifndef UTIL_H
# define UTIL_H

#include <string.h>

#ifndef HAVE_STRLCPY
size_t rc_strlcpy(char *dst, char const *src, size_t siz);
# define strlcpy rc_strlcpy
#endif

#ifndef HAVE_STRLCAT
size_t rc_strlcat(char *dst, const char *src, size_t size);
# define strlcat rc_strlcat
#endif

#endif /* UTIL_H */

