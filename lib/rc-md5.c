/* MD5 message-digest algorithm */

/* This file is licensed under the BSD License, but is largely derived from
 * public domain source code
 */

/*
 *  FORCE MD5 TO USE OUR MD5 HEADER FILE!
 *
 *  If we don't do this, it might pick up the systems broken MD5.
 */
#include "rc-md5.h"

/**
 * @defgroup misc-api Miscellaneous API
 *
 * @{
 */

/** Hash the provided data using MD5
 *
 * @param[out] output will hold a 16-byte checksum.
 * @param[in] input pointer to data to hash.
 * @param[in] inlen the length of input.
 */
void rc_md5_calc(unsigned char *output, unsigned char const *input,
		 size_t inlen)
{
	MD5_CTX	context;

	MD5Init(&context);
	MD5Update(&context, input, inlen);
	MD5Final(output, &context);
}

/** @} */
