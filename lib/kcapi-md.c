/* Kernel crypto API AF_ALG Message Digest API
 *
 * Copyright (C) 2016 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include "internal.h"
#include "kcapi.h"

int kcapi_md_init(struct kcapi_handle **handle, const char *ciphername,
		  uint32_t flags)
{
	return _kcapi_handle_init(handle, "hash", ciphername, flags);
}

void kcapi_md_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

int kcapi_md_setkey(struct kcapi_handle *handle,
		    const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

static inline ssize_t _kcapi_md_update(struct kcapi_handle *handle,
				       const uint8_t *buffer, size_t len)
{
	ssize_t ret = 0;

	if (len > INT_MAX)
		return -EMSGSIZE;

	/* zero buffer length cannot be handled via splice */
	if (len < (1<<15)) {
		ret = _kcapi_common_accept(handle);
		if (ret)
			return ret;
		ret = send(*_kcapi_get_opfd(handle), buffer, len, MSG_MORE);
	} else {
		ret = _kcapi_common_vmsplice_chunk(handle, buffer, len,
						   SPLICE_F_MORE);
	}

	if (ret < 0)
		return ret;
	if ((uint32_t)ret < len)
		return -EIO;

	handle->processed_sg += 1;
	return 0;
}

ssize_t kcapi_md_update(struct kcapi_handle *handle,
			const uint8_t *buffer, size_t len)
{
	return _kcapi_md_update(handle, buffer, len);
}

static ssize_t _kcapi_md_final(struct kcapi_handle *handle,
			       uint8_t *buffer, size_t len)
{
	struct iovec iov;
	struct kcapi_handle_tfm *tfm = handle->tfm;

	if (!buffer || !len) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Message digest: output buffer too small (seen %lu - required %u)",
			    (unsigned long)len,	tfm->info.hash_digestsize);
		return -EINVAL;
	}

	/* Work around zero-sized hashing bug in pre-4.9 kernels: */
	if (!handle->flags.ge_v4_9 && !handle->processed_sg)
		_kcapi_md_update(handle, NULL, 0);

	iov.iov_base = (void*)(uintptr_t)buffer;
	iov.iov_len = len;
	return _kcapi_common_recv_data(handle, &iov, 1);
}

IMPL_SYMVER(md_final, "1.3.1")
ssize_t impl_md_final(struct kcapi_handle *handle,
		      uint8_t *buffer, size_t len)
{
	return _kcapi_md_final(handle, buffer, len);
}

ORIG_SYMVER(md_final, "0.12.0")
int32_t orig_md_final(struct kcapi_handle *handle,
		      uint8_t *buffer, uint32_t len)
{
	return (int32_t)_kcapi_md_final(handle, buffer, len);
}

IMPL_SYMVER(md_digest, "1.3.1")
ssize_t impl_md_digest(struct kcapi_handle *handle,
		       const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t outlen)
{
	ssize_t ret = 0;

	ret = _kcapi_md_update(handle, in, inlen);
	if (0 > ret)
		return ret;
	return _kcapi_md_final(handle, out, outlen);
}

ORIG_SYMVER(md_digest, "0.12.0")
int32_t orig_md_digest(struct kcapi_handle *handle,
		       const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	return (int32_t)impl_md_digest(handle, in, inlen, out, outlen);
}

uint32_t kcapi_md_digestsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.hash_digestsize;
}

uint32_t kcapi_md_blocksize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.blocksize;
}

static inline ssize_t kcapi_md_conv_common(const char *name,
					   const uint8_t *in, size_t inlen,
					   uint8_t *out, size_t outlen)
{
	struct kcapi_handle *handle;
	ssize_t ret = _kcapi_handle_init(&handle, "hash", name, 0);

	if (ret)
		return ret;

	ret = kcapi_md_digest(handle, in, inlen, out, outlen);

	_kcapi_handle_destroy(handle);

	return ret;
}

IMPL_SYMVER(md_sha1, "1.3.1")
ssize_t impl_md_sha1(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha1", in, inlen, out, outlen);
}

ORIG_SYMVER(md_sha1, "1.0.0")
int32_t orig_md_sha1(const uint8_t *in, uint32_t inlen,
		     uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_conv_common("sha1", in, inlen, out, outlen);
}

IMPL_SYMVER(md_sha224, "1.3.1")
ssize_t impl_md_sha224(const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha224", in, inlen, out, outlen);
}

ORIG_SYMVER(md_sha224, "1.0.0")
int32_t orig_md_sha224(const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_conv_common("sha224", in, inlen, out, outlen);
}

IMPL_SYMVER(md_sha256, "1.3.1")
ssize_t impl_md_sha256(const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha256", in, inlen, out, outlen);
}

ORIG_SYMVER(md_sha256, "1.0.0")
ssize_t orig_md_sha256(const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_conv_common("sha256", in, inlen, out, outlen);
}

IMPL_SYMVER(md_sha384, "1.3.1")
ssize_t impl_md_sha384(const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha384", in, inlen, out, outlen);
}

ORIG_SYMVER(md_sha384, "1.0.0")
int32_t orig_md_sha384(const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_conv_common("sha384", in, inlen, out, outlen);
}

IMPL_SYMVER(md_sha512, "1.3.1")
ssize_t impl_md_sha512(const uint8_t *in, size_t inlen,
		       uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha512", in, inlen, out, outlen);
}

ORIG_SYMVER(md_sha512, "1.0.0")
int32_t orig_md_sha512(const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_conv_common("sha512", in, inlen, out, outlen);
}

ssize_t kcapi_md_sm3(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sm3", in, inlen, out, outlen);
}

ssize_t kcapi_md_sha3_224(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha3-224", in, inlen, out, outlen);
}
ssize_t kcapi_md_sha3_256(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha3-256", in, inlen, out, outlen);
}
ssize_t kcapi_md_sha3_384(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha3-384", in, inlen, out, outlen);
}
ssize_t kcapi_md_sha3_512(const uint8_t *in, size_t inlen,
		     uint8_t *out, size_t outlen)
{
	return kcapi_md_conv_common("sha3-512", in, inlen, out, outlen);
}

static inline ssize_t kcapi_md_mac_conv_common(const char *name,
	const uint8_t *key, uint32_t keylen,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
	struct kcapi_handle *handle;
	ssize_t ret = _kcapi_handle_init(&handle, "hash", name, 0);

	if (ret)
		return ret;

	ret = kcapi_md_setkey(handle, key, keylen);
	if (ret)
		goto out;

	ret = kcapi_md_digest(handle, in, inlen, out, outlen);

out:
	_kcapi_handle_destroy(handle);
	return ret;
}

IMPL_SYMVER(md_hmac_sha1, "1.3.1")
ssize_t impl_md_hmac_sha1(const uint8_t *key, uint32_t keylen,
			  const uint8_t *in, size_t inlen,
			  uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sha1)", key, keylen, in, inlen,
					out, outlen);
}

ORIG_SYMVER(md_hmac_sha1, "1.0.0")
int32_t orig_md_hmac_sha1(const uint8_t *key, uint32_t keylen,
			  const uint8_t *in, uint32_t inlen,
			  uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_mac_conv_common("hmac(sha1)", key, keylen,
						 in, inlen, out, outlen);
}

IMPL_SYMVER(md_hmac_sha224, "1.3.1")
ssize_t impl_md_hmac_sha224(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, size_t inlen,
			    uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sha224)", key, keylen, in, inlen,
					out, outlen);
}

ORIG_SYMVER(md_hmac_sha224, "1.0.0")
int32_t orig_md_hmac_sha224(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, uint32_t inlen,
			    uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_mac_conv_common("hmac(sha224)", key, keylen,
						 in, inlen, out, outlen);
}

IMPL_SYMVER(md_hmac_sha256, "1.3.1")
ssize_t impl_md_hmac_sha256(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, size_t inlen,
			    uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sha256)", key, keylen, in, inlen,
					out, outlen);
}

ORIG_SYMVER(md_hmac_sha256, "1.0.0")
int32_t orig_md_hmac_sha256(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, uint32_t inlen,
			    uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_mac_conv_common("hmac(sha256)", key, keylen,
						 in, inlen, out, outlen);
}

IMPL_SYMVER(md_hmac_sha384, "1.3.1")
ssize_t impl_md_hmac_sha384(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, size_t inlen,
			    uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sha384)", key, keylen, in, inlen,
					out, outlen);
}

ORIG_SYMVER(md_hmac_sha384, "1.0.0")
int32_t orig_md_hmac_sha384(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, uint32_t inlen,
			    uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_mac_conv_common("hmac(sha384)", key, keylen,
						 in, inlen, out, outlen);
}

IMPL_SYMVER(md_hmac_sha512, "1.3.1")
ssize_t impl_md_hmac_sha512(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, size_t inlen,
			    uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sha512)", key, keylen, in, inlen,
					out, outlen);
}

ORIG_SYMVER(md_hmac_sha512, "1.0.0")
int32_t orig_md_hmac_sha512(const uint8_t *key, uint32_t keylen,
			    const uint8_t *in, uint32_t inlen,
			    uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_md_mac_conv_common("hmac(sha512)", key, keylen,
						 in, inlen, out, outlen);
}

ssize_t kcapi_md_hmac_sm3(const uint8_t *key, uint32_t keylen,
			  const uint8_t *in, size_t inlen,
			  uint8_t *out, size_t outlen)
{
	return kcapi_md_mac_conv_common("hmac(sm3)", key, keylen, in, inlen,
					out, outlen);
}
