/* Kernel crypto API AF_ALG SP800-108 / SP800-132 KDF API
 *
 * Copyright (C) 2016 - 2020, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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
#include "internal.h"

#ifndef __has_builtin
# define __has_builtin(x) 0
#endif

#define GCC_VERSION (__GNUC__ * 10000		\
		     + __GNUC_MINOR__ * 100	\
		     + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40400 || (defined(__clang__) && __has_builtin(__builtin_bswap32))
# define __HAVE_BUILTIN_BSWAP32__
#endif

/* Endian dependent byte swap operations.  */
#if  __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__
# define be_bswap32(x) ((uint32_t)(x))
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
# ifdef __HAVE_BUILTIN_BSWAP32__
#  define be_bswap32(x) (uint32_t)__builtin_bswap32((uint32_t)(x))
# else
static inline uint32_t rol32(uint32_t x, int n)
{
	return ( (x << (n&(32-1))) | (x >> ((32-n)&(32-1))) );
}

static inline uint32_t ror32(uint32_t x, int n)
{
	return ( (x >> (n&(32-1))) | (x << ((32-n)&(32-1))) );
}

static inline uint32_t _bswap32(uint32_t x)
{
	return ((rol32(x, 8) & 0x00ff00ffL) | (ror32(x, 8) & 0xff00ff00L));
}
#  define be_bswap32(x) _bswap32(x)
# endif
#else
# error "Endianess not defined"
#endif

DSO_PUBLIC
int32_t kcapi_kdf_dpi(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint32_t dlen_orig = dlen;
	uint8_t Ai[h];
	uint32_t i = 1;

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	if (!h)
		return -EFAULT;

	memset(Ai, 0, h);

	while (dlen) {
		uint32_t ibe = be_bswap32(i);

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

		err = kcapi_md_update(handle, (uint8_t *)&ibe,
				      sizeof(uint32_t));
		if (err < 0)
			goto err;
		if (src && slen) {
			err = kcapi_md_update(handle, src, slen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			err = kcapi_md_final(handle, dst, dlen);
			if (err < 0)
				goto err;
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
	return 0;

err:
	kcapi_memset_secure(dst_orig, 0, dlen_orig);
	kcapi_memset_secure(Ai, 0, h);
	return err;
}

DSO_PUBLIC
int32_t kcapi_kdf_fb(struct kcapi_handle *handle,
		     const uint8_t *src, uint32_t slen,
		     uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint32_t dlen_orig = dlen;
	const uint8_t *label;
	uint32_t labellen = 0;
	uint32_t i = 1;

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
		uint32_t ibe = be_bswap32(i);

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

		err = kcapi_md_update(handle, (uint8_t *)&ibe,
				      sizeof(uint32_t));
		if (err)
			goto err;
		if (labellen) {
			err = kcapi_md_update(handle, label, labellen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			err = kcapi_md_final(handle, dst, dlen);
			if (err < 0)
				goto err;
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

	return 0;

err:
	kcapi_memset_secure(dst_orig, 0, dlen_orig);
	return err;
}

DSO_PUBLIC
int32_t kcapi_kdf_ctr(struct kcapi_handle *handle,
		      const uint8_t *src, uint32_t slen,
		      uint8_t *dst, uint32_t dlen)
{
	uint32_t h = kcapi_md_digestsize(handle);
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint32_t dlen_orig = dlen;
	uint32_t i = 1;

	if (dlen > INT_MAX)
		return -EMSGSIZE;

	if (!h)
		return -EFAULT;

	while (dlen) {
		uint32_t ibe = be_bswap32(i);

		err = kcapi_md_update(handle, (uint8_t *)&ibe,
			       	      sizeof(uint32_t));
		if (err)
			goto err;

		if (src && slen) {
			err = kcapi_md_update(handle, src, slen);
			if (err < 0)
				goto err;
		}

		if (dlen < h) {
			err = kcapi_md_final(handle, dst, dlen);
			if (err < 0)
				goto err;
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

	return 0;

err:
	kcapi_memset_secure(dst_orig, 0, dlen_orig);
	return err;
}

/*
 * RFC 5869 KDF
 */
DSO_PUBLIC
int32_t kcapi_hkdf(const char *hashname,
		   const uint8_t *ikm, uint32_t ikmlen,
		   const uint8_t *salt, uint32_t saltlen,
		   const uint8_t *info, uint32_t infolen,
		   uint8_t *dst, uint32_t dlen)
{
#define HKDF_MAXHASH 64
	uint32_t h;
	const uint8_t null_salt[HKDF_MAXHASH] = { 0 };
	uint8_t prk_tmp[HKDF_MAXHASH];
	uint8_t *prev = NULL;
	int32_t err = 0;
	uint8_t *dst_orig = dst;
	uint32_t dlen_orig = dlen;
	uint8_t ctr = 0x01;
	struct kcapi_handle *handle = NULL;

	if (!ikm || !ikmlen || !dst)
		return -EINVAL;

	err = kcapi_md_init(&handle, hashname, 0);
	if (err)
		return err;

	h = kcapi_md_digestsize(handle);

	if (!h) {
		err = -EFAULT;
		goto err;
	}

	if (h > HKDF_MAXHASH) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Null salt size too small for hash\n");
		h = HKDF_MAXHASH;
		err = -EFAULT;
		goto err;
	}

	if (dlen > h * 255) {
		err = -EINVAL;
		goto err;
	}

	/* Extract phase */
	if (salt)
		err = kcapi_md_setkey(handle, salt, saltlen);
	else
		err = kcapi_md_setkey(handle, null_salt, h);

	if (err)
		goto err;
	err = kcapi_md_digest(handle, ikm, ikmlen, prk_tmp, h);
	if (err < 0)
		goto err;
	kcapi_md_destroy(handle);
	handle = NULL;

	/* Expand phase */
	err = kcapi_md_init(&handle, hashname, 0);
	if (err)
		return err;

	err = kcapi_md_setkey(handle, prk_tmp, h);
	if (err)
		goto err;

	/* T(1) and following */
	while (dlen) {
		if (prev) {
			err = kcapi_md_update(handle, prev, h);
			if (err)
				goto err;
		}

		if (info) {
			err = kcapi_md_update(handle, info, infolen);
			if (err)
				goto err;
		}

		err = kcapi_md_update(handle, &ctr, 1);
		if (err)
			goto err;

		if (dlen < h) {
			err = kcapi_md_final(handle, dst, dlen);
			if (err < 0)
				goto err;

			dlen = 0;
		} else {
			err = kcapi_md_final(handle, dst, h);
			if (err < 0)
				goto err;

			prev = dst;
			dst += h;
			dlen -= h;
			ctr++;
		}
	}

	err = 0;
	goto out;

err:
	kcapi_memset_secure(dst_orig, 0, dlen_orig);
out:
	kcapi_memset_secure(prk_tmp, 0, h);
	kcapi_md_destroy(handle);
	return err;
}

static inline uint64_t kcapi_get_time(void)
{
	struct timespec time;

	if (clock_gettime(CLOCK_REALTIME, &time) == 0)
		return time.tv_nsec;

	return 0;
}

DSO_PUBLIC
uint32_t kcapi_pbkdf_iteration_count(const char *hashname, uint64_t timeshresh)
{
#define LOW_ITERATION_COUNT	(UINT32_C(1<<16))
#define SAFE_ITERATION_COUNT	(UINT32_C(1<<18))
#define SAFE_ITERATION_TIME	(UINT32_C(1<<27)) /* more than 100,000,000 ns */
	uint32_t i = 1;
	uint32_t j;

	/* Safety measure */
	if (!kcapi_get_time())
		return (SAFE_ITERATION_COUNT);

	if (timeshresh == 0)
		timeshresh = SAFE_ITERATION_TIME;

	/* The outer loop catches rescheduling operations */
	for (j = 0; j < 2; j++) {
		for (; i < UINT_MAX; i<<=1) {
			uint64_t end, start = kcapi_get_time();
			uint8_t outbuf[16];
			int32_t ret = kcapi_pbkdf(hashname,
						  (uint8_t *)"passwordpassword",
						  16, (uint8_t *)"salt", 4,
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
			else
				j = 0;
		}
	}

	if (i < LOW_ITERATION_COUNT)
		i = LOW_ITERATION_COUNT;

	return i;
}

static inline int kcapi_aligned(const uint8_t *ptr, uint32_t alignmask)
{
	if ((uintptr_t)ptr & alignmask)
		return 0;
	return 1;
}

static inline void kcapi_xor_8(uint8_t *dst, const uint8_t *src, uint32_t size)
{
	for (; size; size--)
		*dst++ ^= *src++;
}

static inline void kcapi_xor_32_aligned(uint8_t *dst, const uint8_t *src,
				        uint32_t size)
{
	uint32_t *dst_word = (uint32_t *)dst;
	uint32_t *src_word = (uint32_t *)src;

	for (; size >= sizeof(*src_word); size -= sizeof(*src_word))
		*dst_word++ ^= *src_word++;

	kcapi_xor_8((uint8_t *)dst_word, (uint8_t *)src_word, size);
}

static inline void kcapi_xor_32(uint8_t *dst, const uint8_t *src, uint32_t size)
{
	if (kcapi_aligned(src, sizeof(uint32_t) - 1) &&
	    kcapi_aligned(dst, sizeof(uint32_t) - 1))
		kcapi_xor_32_aligned(dst, src, size);
	else
		kcapi_xor_8(dst, src, size);
}

#ifdef __LP64__
static inline void kcapi_xor_64_aligned(uint8_t *dst, const uint8_t *src,
				        uint32_t size)
{
	uint64_t *dst_dword = (uint64_t *)dst;
	uint64_t *src_dword = (uint64_t *)src;

	for (; size >= sizeof(*src_dword); size -= sizeof(*src_dword))
		*dst_dword++ ^= *src_dword++;

	kcapi_xor_32_aligned((uint8_t *)dst_dword, (uint8_t *)src_dword, size);
}
#endif

static inline void kcapi_xor_64(uint8_t *dst, const uint8_t *src, uint32_t size)
{
#ifdef __LP64__
	if (kcapi_aligned(src, sizeof(uint64_t) - 1) &&
	    kcapi_aligned(dst, sizeof(uint64_t) - 1))
		kcapi_xor_64_aligned(dst, src, size);
	else
#endif
		kcapi_xor_32(dst, src, size);
}

DSO_PUBLIC
int32_t kcapi_pbkdf(const char *hashname,
		    const uint8_t *pw, uint32_t pwlen,
		    const uint8_t *salt, uint32_t saltlen,
		    uint32_t count,
		    uint8_t *key, uint32_t keylen)
{
	struct kcapi_handle *handle;
	uint8_t *key_orig = key;
	uint32_t keylen_orig = keylen;
	uint32_t h, i = 1;
#define MAX_DIGESTSIZE 64
	uint8_t u[MAX_DIGESTSIZE] __attribute__ ((aligned (sizeof(uint64_t))));
	int32_t err = 0;

	if (keylen > INT_MAX)
		return -EMSGSIZE;

	if (count == 0)
		return -EINVAL;

	err = kcapi_md_init(&handle, hashname, 0);
	if (err)
		return err;

	h = kcapi_md_digestsize(handle);
	if (h > sizeof(u)) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Programming error in file %s at line %u\n",
			    __FILE__, __LINE__);
		h = MAX_DIGESTSIZE;
		err = -EFAULT;
		goto err;
	}

	if (!h) {
		err = -EFAULT;
		goto err;
	}

	err = kcapi_md_setkey(handle, pw, pwlen);
	if (err)
		goto err;

	memset(key, 0, keylen);

	while (keylen) {
		uint32_t j;
		uint32_t ibe = be_bswap32(i);

		err = kcapi_md_update(handle, salt, saltlen);
		if (err < 0)
			goto err;

		err = kcapi_md_update(handle, (uint8_t *)&ibe,
				      sizeof(uint32_t));
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

			kcapi_xor_64(key, u, keylen < h ? keylen : h);
		}

		if (keylen < h)
			keylen = 0;
		else {
			keylen -= h;
			key += h;
			i++;
		}
	}

	err = 0;

err:
	kcapi_memset_secure(u, 0, h);
	if (err)
		kcapi_memset_secure(key_orig, 0, keylen_orig);
	kcapi_md_destroy(handle);

	return err;
}

