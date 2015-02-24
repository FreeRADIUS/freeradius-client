/* MD5 message-digest algorithm */

/* This file is licensed under the BSD License, but is largely derived from
 * public domain source code
 */

/*
 *  FORCE MD5 TO USE OUR MD5 HEADER FILE!
 *
 *  If we don't do this, it might pick up the systems broken MD5.
 *  - Alan DeKok <aland@ox.org>
 */
#include "rc-md5.h"

/**
 * rc_md5_calc:
 * @output: will hold a 16-byte checksum
 * @input: pointer to data to hash
 * @inlen: the length of @input
 *
 * This function will hash the provided data using MD5.
 *
 **/

void rc_md5_calc(unsigned char *output, unsigned char const *input,
		     size_t inlen)
{
	MD5_CTX	context;

	MD5Init(&context);
	MD5Update(&context, input, inlen);
	MD5Final(output, &context);
}

