/* Kernel crypto API AF_ALG Symmetric Cipher API
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
int kcapi_cipher_init(struct kcapi_handle **handle, const char *ciphername,
		      uint32_t flags)
{
	return _kcapi_handle_init(handle, "skcipher", ciphername, flags);
}

DSO_PUBLIC
void kcapi_cipher_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

DSO_PUBLIC
int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

DSO_PUBLIC
int32_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access)
{
	uint32_t bs = handle->info.blocksize;

	/* require properly sized output data size */
	if (outlen < ((inlen + bs - 1) / bs * bs)) {
		kcapi_dolog(LOG_ERR,
			    "Symmetric Encryption: Ciphertext buffer (%lu) is not plaintext buffer (%lu) rounded up to multiple of block size %u",
			    (unsigned long) outlen, (unsigned long)inlen, bs);
		return -EINVAL;
	}

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
					 ALG_OP_ENCRYPT);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static int32_t
_kcapi_cipher_encrypt_aio_helper(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv)
{
	int32_t ret = 0;
	uint32_t i;

	/* every IOVEC for AIO is an independent cipher invocation */
	for (i = 0; i < iovlen; i++) {
		int32_t rc = kcapi_cipher_stream_init_enc(handle, iv, &iniov[i],
							  1);

		if (rc < 0)
			return rc;

		rc = kcapi_cipher_stream_op(handle, &outiov[i], 1);
		if (rc < 0)
			return rc;

		ret += rc;
	}

	return ret;
}

DSO_PUBLIC
int32_t kcapi_cipher_encrypt_aio(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv, int access)
{
	int32_t ret;

	handle->cipher.iv = iv;
	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen, access,
				      ALG_OP_ENCRYPT);

	if (ret == -EOPNOTSUPP)
		return _kcapi_cipher_encrypt_aio_helper(handle, iniov, outiov,
							iovlen, iv);

	return ret;
}

DSO_PUBLIC
int32_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const uint8_t *in, uint32_t inlen,
			     const uint8_t *iv,
			     uint8_t *out, uint32_t outlen, int access)
{
	/* require properly sized output data size */
	if (inlen % handle->info.blocksize) {
		kcapi_dolog(LOG_ERR,
			    "Symmetric Decryption: Ciphertext buffer is not multiple of block size %u",
			    handle->info.blocksize);
		return -EINVAL;
	}

	if (outlen < inlen) {
		kcapi_dolog(LOG_ERR,
			    "Symmetric Decryption: Plaintext buffer (%lu) is smaller as ciphertext buffer (%lu)",
			    (unsigned long)outlen, (unsigned long)inlen);
		return -EINVAL;
	}

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
					 ALG_OP_DECRYPT);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static int32_t
_kcapi_cipher_decrypt_aio_helper(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv)
{
	int32_t ret = 0;
	uint32_t i;

	/* every IOVEC for AIO is an independent cipher invocation */
	for (i = 0; i < iovlen; i++) {
		int32_t rc = kcapi_cipher_stream_init_dec(handle, iv, &iniov[i],
							  1);

		if (rc < 0)
			return rc;

		rc = kcapi_cipher_stream_op(handle, &outiov[i], 1);
		if (rc < 0)
			return rc;

		ret += rc;
	}

	return ret;
}

DSO_PUBLIC
int32_t kcapi_cipher_decrypt_aio(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv, int access)
{
	int32_t ret;

	handle->cipher.iv = iv;
	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen, access,
				      ALG_OP_DECRYPT);

	if (ret == -EOPNOTSUPP)
		return _kcapi_cipher_decrypt_aio_helper(handle, iniov, outiov,
							iovlen, iv);

	return ret;
}

DSO_PUBLIC
int32_t kcapi_cipher_stream_init_enc(struct kcapi_handle *handle,
				     const uint8_t *iv,
				     struct iovec *iov, uint32_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_cipher_stream_init_dec(struct kcapi_handle *handle,
				     const uint8_t *iv,
				     struct iovec *iov, uint32_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_cipher_stream_update(struct kcapi_handle *handle,
				   struct iovec *iov, uint32_t iovlen)
{
	if (handle->processed_sg <= ALG_MAX_PAGES)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen,
						  SPLICE_F_MORE);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_cipher_stream_op(struct kcapi_handle *handle,
			       struct iovec *iov, uint32_t iovlen)
{
	if (!iov || !iovlen) {
		kcapi_dolog(LOG_ERR,
			    "Symmetric operation: No buffer for output data provided");
		return -EINVAL;
	}
	return _kcapi_common_recv_data(handle, iov, iovlen);
}

DSO_PUBLIC
uint32_t kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

DSO_PUBLIC
uint32_t kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}
