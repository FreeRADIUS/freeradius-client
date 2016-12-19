/**
* License: 2-clause BSD
*
* Copyright (c) 2016, Martin Belanger <nitram_67@hotmail.com>
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#include <string.h>   /* memset(), memcpy() */
#include "md5.h"
#include "hmac.h"

struct padding
{
    uint8_t  inner[65]; /* inner padding - key XORd with ipad */
    uint8_t  outer[65]; /* outer padding - key XORd with opad */
};

static void init_pad(struct padding * pad, const uint8_t *key, size_t key_len)
{
    size_t   i;
    uint8_t  tmpkey[16];

    if (key_len > 64)
    {
        MD5_CTX  tmpctx;
        MD5Init(&tmpctx);
        MD5Update(&tmpctx, key, key_len);
        MD5Final(tmpkey, &tmpctx);
        key = tmpkey;
        key_len = 16;
    }

    memset(pad, 0, sizeof(*pad));
    memcpy(pad->inner, key, key_len);
    memcpy(pad->outer, key, key_len);

    for (i = 0; i < 64; i++)
    {
        pad->inner[i] ^= 0x36;
        pad->outer[i] ^= 0x5c;
    }
}

/**
 * HMAC MD5 algorithm (RFC-2104)
 *
 * @author mbelanger (12/14/16)
 *
 * @param data - pointer to data to be processed
 * @param data_len - length of data
 * @param key - pointer to key
 * @param key_len - length of key
 * @param digest - caller digest to be filled in
 */
void hmac_md5(uint8_t *data, size_t data_len,
              uint8_t *key,  size_t key_len, uint8_t *digest)
{
    MD5_CTX         context;
    struct padding  pad;

    init_pad(&pad, key, key_len);

    /* inner MD5 */
    MD5Init(&context);
    MD5Update(&context, pad.inner, 64);
    MD5Update(&context, data, data_len);
    MD5Final(digest, &context);

    /* outer MD5 */
    MD5Init(&context);
    MD5Update(&context, pad.outer, 64);
    MD5Update(&context, digest, 16);
    MD5Final(digest, &context);
}

