#ifndef _RC_HMAC_H
#define _RC_HMAC_H
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

#include "config.h" /* HAVE_NETTLE */

#ifdef HAVE_NETTLE

#include <stddef.h>
#include <stdint.h>
#include <nettle/hmac.h>
extern void hmac_md5_with_nettle(uint8_t *data, size_t  data_len,
                                 uint8_t *key,  size_t  key_len,
                                 uint8_t  digest[MD5_DIGEST_SIZE]);
#define rc_hmac_md5      hmac_md5_with_nettle

#else  /* HAVE_NETTLE */

#include "hmac.h"

#define MD5_DIGEST_SIZE  16
#define rc_hmac_md5      hmac_md5

#endif /* HAVE_NETTLE */

#endif /* _RC_HMAC_H */
