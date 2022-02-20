/* Kernel crypto API AF_ALG Symmetric Cipher API
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

#include "internal.h"
#include "kcapi.h"

int kcapi_cipher_init(struct kcapi_handle **handle, const char *ciphername,
		      uint32_t flags)
{
	return _kcapi_handle_init(handle, "skcipher", ciphername, flags);
}

void kcapi_cipher_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

IMPL_SYMVER(cipher_encrypt, "1.3.1")
ssize_t impl_cipher_encrypt(struct kcapi_handle *handle,
			    const uint8_t *in, size_t inlen,
			    const uint8_t *iv,
			    uint8_t *out, size_t outlen, int access)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t bs = tfm->info.blocksize;

	/* require properly sized output data size */
	if (outlen < ((inlen + bs - 1) / bs * bs))
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Encryption: Ciphertext buffer (%lu) is not plaintext buffer (%lu) rounded up to multiple of block size %u",
			    (unsigned long) outlen, (unsigned long)inlen, bs);

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
					 ALG_OP_ENCRYPT);
}

ORIG_SYMVER(cipher_encrypt, "0.12.0")
int32_t orig_cipher_encrypt(struct kcapi_handle *handle,
			    const uint8_t *in, uint32_t inlen,
			    const uint8_t *iv,
			    uint8_t *out, uint32_t outlen, int access)
{
    return (int32_t)impl_cipher_encrypt(handle, in, inlen, iv, out, outlen,
					access);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static ssize_t
_kcapi_cipher_encrypt_aio_fallback(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 size_t iovlen, const uint8_t *iv)
{
	ssize_t rc = kcapi_cipher_stream_init_enc(handle, iv, iniov, iovlen);

	if (rc < 0)
		return rc;

	return kcapi_cipher_stream_op(handle, outiov, iovlen);
}

IMPL_SYMVER(cipher_encrypt_aio, "1.3.1")
ssize_t impl_cipher_encrypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				size_t iovlen, const uint8_t *iv, int access)
{
	ssize_t ret;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_ENCRYPT);
	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_cipher_encrypt_aio_fallback(handle, iniov, outiov,
						  iovlen, iv);
}

ORIG_SYMVER(cipher_encrypt_aio, "0.12.0")
int32_t orig_cipher_encrypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				uint32_t iovlen, const uint8_t *iv,
				int access)
{
    return (int32_t)impl_cipher_encrypt_aio(handle, iniov, outiov, iovlen,
					    iv, access);
}

IMPL_SYMVER(cipher_decrypt, "1.3.1")
ssize_t impl_cipher_decrypt(struct kcapi_handle *handle,
			    const uint8_t *in, size_t inlen,
			    const uint8_t *iv,
			    uint8_t *out, size_t outlen, int access)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	/* require properly sized output data size */
	if (inlen % tfm->info.blocksize)
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Decryption: Ciphertext buffer is not multiple of block size %u",
			    tfm->info.blocksize);

	if (outlen < inlen)
		kcapi_dolog(KCAPI_LOG_WARN,
			    "Symmetric Decryption: Plaintext buffer (%lu) is smaller as ciphertext buffer (%lu)",
			    (unsigned long)outlen, (unsigned long)inlen);

	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt_chunk(handle, in, inlen, out, outlen, access,
					 ALG_OP_DECRYPT);
}

ORIG_SYMVER(cipher_decrypt, "0.12.0")
int32_t orig_cipher_decrypt(struct kcapi_handle *handle,
			    const uint8_t *in, uint32_t inlen,
			    const uint8_t *iv,
			    uint8_t *out, uint32_t outlen, int access)
{
	return (int32_t)impl_cipher_decrypt(handle, in, inlen, iv, out, outlen,
					    access);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static ssize_t
_kcapi_cipher_decrypt_aio_fallback(struct kcapi_handle *handle,
				   struct iovec *iniov, struct iovec *outiov,
				   size_t iovlen, const uint8_t *iv)
{
	ssize_t rc = kcapi_cipher_stream_init_dec(handle, iv, iniov, iovlen);

	if (rc < 0)
		return rc;

	return kcapi_cipher_stream_op(handle, outiov, iovlen);
}

IMPL_SYMVER(cipher_decrypt_aio, "1.3.1")
ssize_t impl_cipher_decrypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				size_t iovlen, const uint8_t *iv, int access)
{
	ssize_t ret;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_DECRYPT);
	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_cipher_decrypt_aio_fallback(handle, iniov, outiov,
						  iovlen, iv);
}

ORIG_SYMVER(cipher_decrypt_aio, "0.12.0")
int32_t orig_cipher_decrypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				uint32_t iovlen, const uint8_t *iv, int access)
{
	return (int32_t)impl_cipher_decrypt_aio(handle, iniov, outiov, iovlen,
						iv, access);
}

IMPL_SYMVER(cipher_stream_init_enc, "1.3.1")
ssize_t impl_cipher_stream_init_enc(struct kcapi_handle *handle,
				    const uint8_t *iv,
				    struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

ORIG_SYMVER(cipher_stream_init_enc, "0.12.0")
int32_t orig_cipher_stream_init_enc(struct kcapi_handle *handle,
				    const uint8_t *iv,
				    struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_cipher_stream_init_enc(handle, iv, iov, iovlen);
}

IMPL_SYMVER(cipher_stream_init_dec, "1.3.1")
ssize_t impl_cipher_stream_init_dec(struct kcapi_handle *handle,
				    const uint8_t *iv,
				    struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

ORIG_SYMVER(cipher_stream_init_dec, "0.12.0")
int32_t orig_cipher_stream_init_dec(struct kcapi_handle *handle,
				    const uint8_t *iv,
				    struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_cipher_stream_init_dec(handle, iv, iov, iovlen);
}

IMPL_SYMVER(cipher_stream_update, "1.3.1")
ssize_t impl_cipher_stream_update(struct kcapi_handle *handle,
				  struct iovec *iov, size_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen,
						  SPLICE_F_MORE);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

ORIG_SYMVER(cipher_stream_update, "0.12.0")
int32_t orig_cipher_stream_update(struct kcapi_handle *handle,
				  struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_cipher_stream_update(handle, iov, iovlen);
}

IMPL_SYMVER(cipher_stream_update_last, "1.3.1")
ssize_t impl_cipher_stream_update_last(struct kcapi_handle *handle,
				       struct iovec *iov, size_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen, 0);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, 0);
}

ORIG_SYMVER(cipher_stream_update_last, "1.2.0")
int32_t orig_cipher_stream_update_last(struct kcapi_handle *handle,
				       struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_cipher_stream_update_last(handle, iov, iovlen);
}

IMPL_SYMVER(cipher_stream_op, "1.3.1")
ssize_t impl_cipher_stream_op(struct kcapi_handle *handle,
			      struct iovec *iov, size_t iovlen)
{
	if (!iov || !iovlen) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Symmetric operation: No buffer for output data provided");
		return -EINVAL;
	}
	return _kcapi_common_recv_data(handle, iov, iovlen);
}

ORIG_SYMVER(cipher_stream_op, "0.12.0")
int32_t orig_cipher_stream_op(struct kcapi_handle *handle,
			      struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_cipher_stream_op(handle, iov, iovlen);
}

uint32_t kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.ivsize;
}

uint32_t kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.blocksize;
}

static inline ssize_t kcapi_cipher_conv_enc_common(const char *name,
					const uint8_t *key, uint32_t keylen,
					const uint8_t *in, size_t inlen,
					const uint8_t *iv,
					uint8_t *out, size_t outlen)
{
	struct kcapi_handle *handle;
	ssize_t ret = _kcapi_handle_init(&handle, "skcipher", name, 0);
	if (ret)
		return ret;

	ret = kcapi_cipher_setkey(handle, key, keylen);
	if (ret)
		goto out;

	ret = kcapi_cipher_encrypt(handle, in, inlen, iv, out, outlen, 0);

out:
	_kcapi_handle_destroy(handle);
	return ret;
}

static inline ssize_t kcapi_cipher_conv_dec_common(const char *name,
					const uint8_t *key, uint32_t keylen,
					const uint8_t *in, size_t inlen,
					const uint8_t *iv,
					uint8_t *out, size_t outlen)
{
	struct kcapi_handle *handle;
	ssize_t ret = _kcapi_handle_init(&handle, "skcipher", name, 0);

	if (ret)
		return ret;

	ret = kcapi_cipher_setkey(handle, key, keylen);
	if (ret)
		goto out;

	ret = kcapi_cipher_decrypt(handle, in, inlen, iv, out, outlen, 0);

out:
	_kcapi_handle_destroy(handle);
	return ret;
}

IMPL_SYMVER(cipher_enc_aes_cbc, "1.3.1")
ssize_t impl_cipher_enc_aes_cbc(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, size_t inlen,
				const uint8_t *iv,
				uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_enc_common("cbc(aes)", key, keylen, in, inlen,
					    iv, out, outlen);
}

ORIG_SYMVER(cipher_enc_aes_cbc, "1.0.0")
int32_t orig_cipher_enc_aes_cbc(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, uint32_t inlen,
				const uint8_t *iv,
				uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_cipher_conv_enc_common("cbc(aes)", key, keylen,
						     in, inlen, iv,
						     out, outlen);
}

IMPL_SYMVER(cipher_enc_aes_ctr, "1.3.1")
ssize_t impl_cipher_enc_aes_ctr(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, size_t inlen,
				const uint8_t *ctr,
				uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_enc_common("ctr(aes)", key, keylen, in, inlen,
					    ctr, out, outlen);
}

ORIG_SYMVER(cipher_enc_aes_ctr, "1.0.0")
int32_t orig_cipher_enc_aes_ctr(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, uint32_t inlen,
				const uint8_t *ctr,
				uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_cipher_conv_enc_common("ctr(aes)", key, keylen,
						     in, inlen, ctr,
						     out, outlen);
}

IMPL_SYMVER(cipher_dec_aes_cbc, "1.3.1")
ssize_t impl_cipher_dec_aes_cbc(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, size_t inlen,
				const uint8_t *iv,
				uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_dec_common("cbc(aes)", key, keylen, in, inlen,
					    iv, out, outlen);
}

ORIG_SYMVER(cipher_dec_aes_cbc, "1.0.0")
int32_t orig_cipher_dec_aes_cbc(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, uint32_t inlen,
				const uint8_t *iv,
				uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_cipher_conv_dec_common("cbc(aes)", key, keylen,
						     in, inlen, iv,
						     out, outlen);
}

IMPL_SYMVER(cipher_dec_aes_ctr, "1.3.1")
ssize_t impl_cipher_dec_aes_ctr(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, size_t inlen,
				const uint8_t *ctr,
				uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_dec_common("ctr(aes)", key, keylen, in, inlen,
					    ctr, out, outlen);
}

ORIG_SYMVER(cipher_dec_aes_ctr, "1.0.0")
int32_t orig_cipher_dec_aes_ctr(const uint8_t *key, uint32_t keylen,
				const uint8_t *in, uint32_t inlen,
				const uint8_t *ctr,
				uint8_t *out, uint32_t outlen)
{
	return (int32_t)kcapi_cipher_conv_dec_common("ctr(aes)", key, keylen,
						     in, inlen, ctr,
						     out, outlen);
}

ssize_t kcapi_cipher_enc_sm4_cbc(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, size_t inlen,
				 const uint8_t *iv,
				 uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_enc_common("cbc(sm4)", key, keylen, in, inlen,
					    iv, out, outlen);
}

ssize_t kcapi_cipher_enc_sm4_ctr(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, size_t inlen,
				 const uint8_t *ctr,
				 uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_enc_common("ctr(sm4)", key, keylen, in, inlen,
					    ctr, out, outlen);
}

ssize_t kcapi_cipher_dec_sm4_cbc(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, size_t inlen,
				 const uint8_t *iv,
				 uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_dec_common("cbc(sm4)", key, keylen, in, inlen,
					    iv, out, outlen);
}

ssize_t kcapi_cipher_dec_sm4_ctr(const uint8_t *key, uint32_t keylen,
				 const uint8_t *in, size_t inlen,
				 const uint8_t *ctr,
				 uint8_t *out, size_t outlen)
{
	return kcapi_cipher_conv_dec_common("ctr(sm4)", key, keylen, in, inlen,
					    ctr, out, outlen);
}
