/* Kernel crypto API AF_ALG Random Number Generator API
 *
 * Copyright (C) 2016 - 2022, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <unistd.h>
#include <linux/random.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include "internal.h"
#include "kcapi.h"

int kcapi_rng_init(struct kcapi_handle **handle, const char *ciphername,
		   uint32_t flags)
{
	return _kcapi_handle_init(handle, "rng", ciphername, flags);
}

void kcapi_rng_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

int kcapi_rng_seed(struct kcapi_handle *handle, uint8_t *seed,
		   uint32_t seedlen)
{
	kcapi_dolog(KCAPI_LOG_VERBOSE, "Seed DRNG with %u bytes of seed",
		    seedlen);
	return _kcapi_common_setkey(handle, seed, seedlen);
}

int kcapi_rng_setentropy(struct kcapi_handle *handle, uint8_t *ent,
			 uint32_t entlen)
{
	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "Set %u bytes of initial entropy of DRBG", entlen);
	return _kcapi_common_setentropy(handle, ent, entlen);
}

int kcapi_rng_setaddtl(struct kcapi_handle *handle, uint8_t *addtl,
		       uint32_t len)
{
	ssize_t ret = 0;

	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "Set %u bytes of additional data for DRBG", len);

	if (len > INT_MAX)
		return -EMSGSIZE;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return (int)ret;
	ret = send(*_kcapi_get_opfd(handle), addtl, len, MSG_MORE);

	if (ret < 0)
		return (int)ret;
	if ((uint32_t)ret < len)
		return -EIO;

	handle->processed_sg += 1;
	return 0;
}

IMPL_SYMVER(rng_generate, "1.3.1")
ssize_t impl_rng_generate(struct kcapi_handle *handle,
			  uint8_t *buffer, size_t len)
{
	ssize_t out = 0;
	struct iovec iov;

	while (len) {
		ssize_t r = 0;

		iov.iov_base = (void *)(uintptr_t)buffer;
		iov.iov_len = len;
		r = _kcapi_common_recv_data(handle, &iov, 1);
		if (0 >= r)
			return r;
		len -= (size_t)r;
		out += r;

		buffer += r;
	}

	return out;
}

ORIG_SYMVER(rng_generate, "0.12.0")
int32_t orig_rng_generate(struct kcapi_handle *handle,
			  uint8_t *buffer, uint32_t len)
{
	return (int32_t)impl_rng_generate(handle, buffer, len);
}

uint32_t kcapi_rng_seedsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.rng_seedsize;
}

#if !defined(HAVE_GETRANDOM) && !defined(__NR_getrandom)
static int random_fd = -1;
static int open_random(void)
{
	random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
	if (0 > random_fd)
		return random_fd;

	return 0;
}

static void close_random(void)
{
	close(random_fd);
}
#endif

static int get_random(uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	ret = open_random();
	if (ret)
		return ret;
#endif

	do {
#ifdef HAVE_GETRANDOM
		ret = getrandom(buf, buflen, 0);
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Accessed getrandom system call for %zu bytes",
			    buflen);
#elif defined __NR_getrandom
		ret = syscall(__NR_getrandom, buf, buflen, 0);
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Accessed getrandom system call for %zu bytes",
			    buflen);
#else
		ret = read(random_fd, buf, buflen);
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Accessed /dev/urandom for %zu bytes", buflen);
#endif
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	close_random();
#endif

	if (buflen == 0)
		return 0;
	return 1;
}

/* For efficiency reasons, this should be identical to algif_rng.c:MAXSIZE. */
#define KCAPI_RNG_BUFSIZE  128
/* Minimum seed is 256 bits. */
#define KCAPI_RNG_MINSEEDSIZE 32
#define KCAPI_APP_ALIGN 8
#define __aligned(x)	__attribute__((aligned(x)))

IMPL_SYMVER(rng_get_bytes, "1.3.1")
ssize_t impl_rng_get_bytes(uint8_t *buffer, size_t outlen)
{
	struct kcapi_handle *handle;
	uint8_t buf[KCAPI_RNG_BUFSIZE] __aligned(KCAPI_APP_ALIGN);
	uint8_t *seedbuf = buf;
	uint32_t seedsize = 0;
	size_t orig_outlen = outlen;
	ssize_t ret = _kcapi_handle_init(&handle, "rng", "stdrng", 0);
	if (ret)
		return ret;

	seedsize = kcapi_rng_seedsize(handle);
	if (seedsize) {
		/*
		 * Only reseed, if there is a seedsize defined. For example,
		 * the DRBG has a seedsize of 0 because it seeds itself from
		 * known good noise sources.
		 */
		if (seedsize < KCAPI_RNG_MINSEEDSIZE)
			seedsize = KCAPI_RNG_MINSEEDSIZE;

		/*
		 * Only allocate a new buffer if our buffer is
		 * insufficiently large.
		 */
		if (seedsize > KCAPI_RNG_BUFSIZE) {
			seedbuf = calloc(1, seedsize);
			if (!seedbuf) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = get_random(seedbuf, seedsize);
		if (ret)
			goto out;
	}

	/*
	 * Invoke seeding even if seedsize is 0 -- this also triggers any
	 * internal seeding operation like in the DRBG.
	 */
	ret = kcapi_rng_seed(handle, seedbuf, seedsize);
	if (ret)
		goto out;

	while (outlen) {
		size_t todo = (outlen < KCAPI_RNG_BUFSIZE) ?
					outlen : KCAPI_RNG_BUFSIZE;

		ret = kcapi_rng_generate(handle, buffer, todo);
		if (ret < 0)
			goto out;

		if (ret == 0) {
			ret = -EFAULT;
			goto out;
		}
		outlen -= (size_t)ret;
		buffer += ret;
	}

	ret = (ssize_t)orig_outlen;

out:
	/* Free seedbuf if it was allocated. */
	if (seedbuf && (seedbuf != buf)) {
		kcapi_memset_secure(seedbuf, 0, seedsize);
		free(seedbuf);
	} else
		kcapi_memset_secure(buf, 0, sizeof(buf));
	_kcapi_handle_destroy(handle);
	return ret;
}

ORIG_SYMVER(rng_get_bytes, "1.0.0")
int32_t orig_rng_get_bytes(uint8_t *buffer, uint32_t outlen)
{
        return (int32_t)impl_rng_get_bytes(buffer, outlen);
}
