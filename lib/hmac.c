/*
 * FILE:    hmac.c
 * AUTHORS: Colin Perkins
 *
 * HMAC message authentication (RFC2104)
 *
 * Copyright (c) 1998-2000 University College London
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, is permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the Computer Science
 *      Department at University College London
 * 4. Neither the name of the University nor of the Department may be used
 *    to endorse or promote products derived from this software without
 *    specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "md5.h"
#include "hmac.h"

/**
 * hmac_md5:
 * @data: pointer to data stream.
 * @data_len: length of data stream in bytes.
 * @key: pointer to authentication key.
 * @key_len: length of authentication key in bytes.
 * @digest: digest to be filled in.
 *
 * Computes MD5 @digest of @data using key @key.
 *
 **/
void hmac_md5(unsigned char   *data,
	      int              data_len,
	      unsigned char   *key,
	      int              key_len,
	      unsigned char    digest[16])
{
        MD5_CTX       context;
        unsigned char k_ipad[65];    /* inner padding - key XORd with ipad */
        unsigned char k_opad[65];    /* outer padding - key XORd with opad */
        unsigned char tk[16];
        int           i;

        /* If key is longer than 64 bytes reset it to key=MD5(key) */
        if (key_len > 64) {
                MD5_CTX      tctx;

                MD5Init(&tctx);
                MD5Update(&tctx, key, key_len);
                MD5Final(tk, &tctx);

                key     = tk;
                key_len = 16;
        }

        /*
         * The HMAC_MD5 transform looks like:
         *
         * MD5(K XOR opad, MD5(K XOR ipad, data))
         *
         * where K is an n byte key
         * ipad is the byte 0x36 repeated 64 times
         * opad is the byte 0x5c repeated 64 times
         * and text is the data being protected
         */

        /* Start out by storing key in pads */
        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);

        /* XOR key with ipad and opad values */
        for (i=0; i<64; i++) {
                k_ipad[i] ^= 0x36;
                k_opad[i] ^= 0x5c;
        }
        /*
         * perform inner MD5
         */
        MD5Init(&context);                   /* init context for 1st pass */
        MD5Update(&context, k_ipad, 64);     /* start with inner pad      */
        MD5Update(&context, data, data_len); /* then text of datagram     */
        MD5Final(digest, &context);          /* finish up 1st pass        */
        /*
         * perform outer MD5
         */
        MD5Init(&context);                   /* init context for 2nd pass */
        MD5Update(&context, k_opad, 64);     /* start with outer pad      */
        MD5Update(&context, digest, 16);     /* then results of 1st hash  */
        MD5Final(digest, &context);          /* finish up 2nd pass        */
}

/*
 * Test Vectors (Trailing '\0' of a character string not included in test):
 *
 * key =         0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
 * key_len =     16 bytes
 * data =        "Hi There"
 * data_len =    8  bytes
 * digest =      0x9294727a3638bb1c13f48ef8158bfc9d
 *
 * key =         "Jefe"
 * data =        "what do ya want for nothing?"
 * data_len =    28 bytes
 * digest =      0x750c783e6ab0b503eaa86e310a5db738
 *
 * key =         0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
 * key_len       16 bytes
 * data =        0xDDDDDDDDDDDDDDDDDDDD...
 *               ..DDDDDDDDDDDDDDDDDDDD...
 *               ..DDDDDDDDDDDDDDDDDDDD...
 *               ..DDDDDDDDDDDDDDDDDDDD...
 *               ..DDDDDDDDDDDDDDDDDDDD
 * data_len =    50 bytes
 * digest =      0x56be34521d144c88dbb8c733f0e8b3f6
 */

#ifdef TEST_HMAC
int main()
{
	unsigned char	*key  = "Jefe";
	unsigned char	*data = "what do ya want for nothing?";
	unsigned char	 digest[16];
	int		 i;

	hmac_md5(data, 28, key, 4, digest);
	for (i = 0; i < 16; i++) {
		printf("%02x", digest[i]);
	}
	printf("\n");

	return 0;
}
#endif


