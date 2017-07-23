/* Kernel crypto API AF_ALG Message Digest API
 *
 * Copyright (C) 2016, Stephan Mueller <smueller@chronox.de>
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

DSO_PUBLIC
int kcapi_md_init(struct kcapi_handle **handle, const char *ciphername,
		  uint32_t flags)
{
	return _kcapi_handle_init(handle, "hash", ciphername, flags);
}

DSO_PUBLIC
void kcapi_md_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

DSO_PUBLIC
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

static inline int32_t _kcapi_md_update(struct kcapi_handle *handle,
				       const uint8_t *buffer, uint32_t len)
{
	int32_t ret = 0;

	if (len > INT_MAX)
		return -EMSGSIZE;

	/* zero buffer length cannot be handled via splice */
	if (len < (1<<15)) {
		ret = _kcapi_common_accept(handle, &handle->opfd);
		if (ret)
			return ret;
		ret = send(handle->opfd, buffer, len, MSG_MORE);
	} else {
		ret = _kcapi_common_vmsplice_chunk(handle, buffer, len,
						   SPLICE_F_MORE);
	}

	if (ret < 0 || (uint32_t)ret < len)
		return -EIO;
	return 0;
}

DSO_PUBLIC
int32_t kcapi_md_update(struct kcapi_handle *handle,
			const uint8_t *buffer, uint32_t len)
{
	return _kcapi_md_update(handle, buffer, len);
}

static int32_t _kcapi_md_final(struct kcapi_handle *handle,
			       uint8_t *buffer, uint32_t len)
{
	struct iovec iov;

	if (!buffer || !len) {
		kcapi_dolog(LOG_ERR,
			    "Message digest: output buffer too small (seen %lu - required %u)",
			    (unsigned long)len,	handle->info.hash_digestsize);
		return -EINVAL;
	}

	iov.iov_base = (void*)(uintptr_t)buffer;
	iov.iov_len = len;
	return _kcapi_common_recv_data(handle, &iov, 1);
}

DSO_PUBLIC
int32_t kcapi_md_final(struct kcapi_handle *handle,
		       uint8_t *buffer, uint32_t len)
{
	return _kcapi_md_final(handle, buffer, len);
}

DSO_PUBLIC
int32_t kcapi_md_digest(struct kcapi_handle *handle,
		       const uint8_t *in, uint32_t inlen,
		       uint8_t *out, uint32_t outlen)
{
	int32_t ret = 0;

	ret = _kcapi_md_update(handle, in, inlen);
	if (0 > ret)
		return ret;
	return _kcapi_md_final(handle, out, outlen);
}

DSO_PUBLIC
uint32_t kcapi_md_digestsize(struct kcapi_handle *handle)
{
	return handle->info.hash_digestsize;
}

DSO_PUBLIC
uint32_t kcapi_md_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}
