/*
 * Copyright (C) 2016, Stephan Mueller <smueller@chronox.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU General Public License, in which case the provisions of the GPL2
 * are required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _INTERNAL_BSWAP_H
#define _INTERNAL_BSWAP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

static inline uint32_t rol32(uint32_t x, int n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}

static inline uint32_t ror32(uint32_t x, int n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

/* Byte swap for 32-bit and 64-bit integers. */
static inline uint32_t _bswap32(uint32_t x)
{
	return ((rol32(x, 8) & 0x00ff00ffL) | (ror32(x, 8) & 0xff00ff00L));
}

static inline uint64_t _bswap64(uint64_t x)
{
	return ((uint64_t)_bswap32(x) << 32) | (_bswap32(x >> 32));
}

/* Endian dependent byte swap operations.  */
#if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define le_bswap32(x) _bswap32(x)
# define be_bswap32(x) ((uint32_t)(x))
# define le_bswap64(x) _bswap64(x)
# define be_bswap64(x) ((uint64_t)(x))
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# define le_bswap32(x) ((uint32_t)(x))
# define be_bswap32(x) _bswap32(x)
# define le_bswap64(x) ((uint64_t)(x))
# define be_bswap64(x) _bswap64(x)
#else
#error "Endianess not defined"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _INTERNAL_BSWAP_H */
