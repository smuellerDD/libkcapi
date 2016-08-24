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

/*
 * For performing a KDF operation, the following input is required
 * from the caller:
 *
 *	* Keying material to be used to derive the new keys from
 *	  (denoted as Ko in SP800-108)
 *	* Label -- a free form binary string
 *	* Context -- a free form binary string
 *
 * The Ko keying material is provided when the caller invokes the
 * kcapi_md_setkey function with the data.
 *
 * The Label and Context concatenated string is provided when obtaining random
 * numbers, i.e. with the functions below. The caller must format
 * the free-form Label || Context input as deemed necessary for the given
 * purpose. Note, SP800-108 mandates that the Label and Context are separated
 * by a 0x00 byte, i.e. the caller shall provide the input as
 * Label || 0x00 || Context when trying to be compliant to SP800-108. For
 * the feedback KDF, an IV is required as documented below.
 *
 * Example without proper error handling:
 *	char *keying_material = "\x00\x11\x22\x33\x44\x55\x66\x77";
 *	char *label_context = "\xde\xad\xbe\xef\x00\xde\xad\xbe\xef";
 *	kdf = kcapi_md_init(&handle, "hmac(sha256)", 0);
 *	kcapi_md_setkey(handle, keying_material, 8);
 *	kcapi_kdf_ctr(kdf, label_context, 9, outbuf, outbuflen);
 */

#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

#include "kcapi.h"
#include "internal_bswap.h"

/* convert 32 bit integer into its string representation */
static inline void kcapi_kdf_cpu_to_be32(uint32_t val, uint8_t *buf)
{
	uint32_t *a = (uint32_t *)buf;

	*a = be_bswap32(val);
}

int32_t kcapi_kdf_dpi(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint8_t Ai[h];
	uint32_t i = 1;
	uint8_t iteration[sizeof(uint32_t)];

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	if (!h)
		return -EFAULT;

	memset(Ai, 0, h);

	while (dlen) {
		/* Calculate A(i) */
		if (dst == dst_orig && src && slen)
			/* 5.3 step 4 and 5.a */
			err = kcapi_md_digest(handle, src, slen, Ai, h);
		else
			/* 5.3 step 5.a */
			err = kcapi_md_digest(handle, Ai, h, Ai, h);
		if (err < 0)
			goto err;

		/* Calculate K(i) -- step 5.b */
		err = kcapi_md_update(handle, Ai, h);
		if (err < 0)
			goto err;

		kcapi_kdf_cpu_to_be32(i, iteration);
		err = kcapi_md_update(handle, iteration, sizeof(uint32_t));
		if (err < 0)
			goto err;
		if (src && slen) {
			err = kcapi_md_update(handle, src, slen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			uint8_t tmpbuffer[h];

			err = kcapi_md_final(handle, tmpbuffer, h);
			if (err < 0)
				goto err;
			memcpy(dst, tmpbuffer, dlen);
			kcapi_memset_secure(tmpbuffer, 0, h);
			dlen = 0;
		} else {
			err = kcapi_md_final(handle, dst, h);
			if (err < 0)
				goto err;
			dlen -= h;
			dst += h;
			i++;
		}
	}

	kcapi_memset_secure(Ai, 0, h);
	return err;

err:
	kcapi_memset_secure(dst_orig, 0, dlen);
	kcapi_memset_secure(Ai, 0, h);
	return err;
}

int32_t kcapi_kdf_fb(struct kcapi_handle *handle,
		     const uint8_t *src, uint32_t slen,
		     uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	const uint8_t *label;
	uint32_t labellen = 0;
	uint32_t i = 1;
	uint8_t iteration[sizeof(uint32_t)];

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	if (!h)
		return -EFAULT;

	/* require the presence of an IV */
	if (!src || slen < h)
		return -EINVAL;

	/* calculate the offset of the label / context data */
	label = src + h;
	labellen = slen - h;

	while (dlen) {
		/*
		 * Feedback mode applies to all rounds except first which uses
		 * the IV.
		 */
		if (dst_orig == dst)
			err = kcapi_md_update(handle, src, h);
		else
			err = kcapi_md_update(handle, dst - h, h);
		if (err)
			goto err;

		kcapi_kdf_cpu_to_be32(i, iteration);
		err = kcapi_md_update(handle, iteration, sizeof(uint32_t));
		if (err)
			goto err;
		if (labellen) {
			err = kcapi_md_update(handle, label, labellen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			uint8_t tmpbuffer[h];

			err = kcapi_md_final(handle, tmpbuffer, h);
			if (err < 0)
				goto err;
			memcpy(dst, tmpbuffer, dlen);
			kcapi_memset_secure(tmpbuffer, 0, h);
			return 0;
		} else {
			err = kcapi_md_final(handle, dst, h);
			if (err < 0)
				goto err;
			dlen -= h;
			dst += h;
			i++;
		}
	}

	return 0;

err:
	kcapi_memset_secure(dst_orig, 0, dlen);
	return err;
}

int32_t kcapi_kdf_ctr(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint32_t i = 1;
	uint8_t iteration[sizeof(uint32_t)];

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	if (!h)
		return -EFAULT;

	while (dlen) {
		kcapi_kdf_cpu_to_be32(i, iteration);
		err = kcapi_md_update(handle, iteration, sizeof(uint32_t));
		if (err)
			goto err;

		if (src && slen) {
			err = kcapi_md_update(handle, src, slen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			uint8_t tmpbuffer[h];

			err = kcapi_md_final(handle, tmpbuffer, h);
			if (err < 0)
				goto err;
			memcpy(dst, tmpbuffer, dlen);
			kcapi_memset_secure(tmpbuffer, 0, h);
			return 0;
		} else {
			err = kcapi_md_final(handle, dst, h);
			if (err < 0)
				goto err;

			dlen -= h;
			dst += h;
			i++;
		}
	}

	return 0;

err:
	kcapi_memset_secure(dst_orig, 0, dlen);
	return err;
}

static inline uint64_t kcapi_get_time(void)
{
	struct timespec time;

	if (clock_gettime(CLOCK_REALTIME, &time) == 0) {
		return time.tv_nsec;
	}

	return 0;
}

uint32_t kcapi_pbkdf_iteration_count(uint64_t timeshresh)
{
#define SAFE_ITERATION_COUNT (1<<18U)
#define SAFE_ITERATION_TIME (1<<27UL) /* more than 100,000,000 ns */
	uint32_t i;

	/* Safety measure */
	if (!kcapi_get_time())
		return (SAFE_ITERATION_COUNT);

	if (timeshresh == 0)
		timeshresh = SAFE_ITERATION_TIME;

	for (i = 1; i < UINT_MAX; i<<=1) {
		uint64_t end, start = kcapi_get_time();
		uint8_t outbuf[16];
		int32_t ret = kcapi_pbkdf("hmac(sha1)",
					  (uint8_t *)"password", 8,
					  (uint8_t *)"salt", 4,
					  i, outbuf, sizeof(outbuf));

		end = kcapi_get_time();

		/* Safety measure */
		if (ret < 0)
			return (SAFE_ITERATION_COUNT);

		/* Take precautions if time runs backwards */
		if (end > start)
			end = end - start;
		else
			end = start - end;

		if (end > timeshresh)
			break;
	}

	return i;
}

static int kcapi_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((unsigned long)ptr & alignmask)
		return 0;
	return 1;
}

static void kcapi_xor_byte(uint8_t *dst, const uint8_t *src, uint32_t size)
{
	for (; size; size--)
                *dst++ ^= *src++;
}

static void kcapi_xor_word(uint8_t *dst, const uint8_t *src, uint32_t size)
{
        uint32_t *dst_word = (uint32_t *)dst;
        uint32_t *src_word = (uint32_t *)src;

	/*
	 * Only do word-wise XOR when pointers are aligned (which should be
	 * the case most of the time).
	 */
	if (kcapi_aligned(src, sizeof(*src_word) - 1) &&
	    kcapi_aligned(dst, sizeof(*dst_word) - 1)) {
		for (; size >= 4; size -= 4)
			*dst_word++ ^= *src_word++;
	}

	kcapi_xor_byte(dst, src, size);
}

int32_t kcapi_pbkdf(const char *hashname,
		    const uint8_t *pw, uint32_t pwlen,
		    const uint8_t *salt, uint32_t saltlen,
		    uint32_t count,
		    uint8_t *key, uint32_t keylen)
{
	struct kcapi_handle *handle;
	uint32_t h;
	uint8_t u[64];
	uint32_t i = 1;
	uint8_t iteration[sizeof(uint32_t)];
	int32_t err = 0;

	if (keylen > INT_MAX)
		return -EMSGSIZE;

	err = kcapi_md_init(&handle, hashname, 0);
	if (err)
		return err;

	h = kcapi_md_digestsize(handle);
	if (h > sizeof(u))
		return -EFAULT;

	err = kcapi_md_setkey(handle, pw, pwlen);
	if (err)
		goto err;

	memset(key, 0, keylen);

	while (keylen) {
		uint32_t j;
		uint8_t T[h];

		memset(T, 0, h);

		kcapi_kdf_cpu_to_be32(i, iteration);

		err = kcapi_md_update(handle, salt, saltlen);
		if (err < 0)
			goto err;

		err = kcapi_md_update(handle, iteration, sizeof(uint32_t));
		if (err < 0)
			goto err;

		for (j = 0; j < count; j++) {
			if (j) {
				err = kcapi_md_update(handle, u, h);
				if (err)
					goto err;
			}

			err = kcapi_md_final(handle, u, h);
			if (err < 0)
				goto err;

			if (keylen < h)
				kcapi_xor_word(T, u, h);
			else
				kcapi_xor_word(key, u, h);
		}

		if (keylen < h) {
			memcpy(key, T, keylen);
			kcapi_memset_secure(T, 0, keylen);
			keylen = 0;
		} else {
			keylen -= h;
			key += h;
			i++;
		}
	}

	err = 0;

err:
	kcapi_memset_secure(u, 0, h);
	if (err)
		kcapi_memset_secure(key, 0, keylen);
	kcapi_md_destroy(handle);

	return err;
}

