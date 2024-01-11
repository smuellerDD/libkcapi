/* Kernel crypto API AF_ALG AEAD API
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

int kcapi_aead_init(struct kcapi_handle **handle, const char *ciphername,
		    uint32_t flags)
{
	return _kcapi_handle_init(handle, "aead", ciphername, flags);
}

void kcapi_aead_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

int kcapi_aead_settaglen(struct kcapi_handle *handle, uint32_t taglen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	handle->aead.tag = NULL;
	handle->aead.taglen = taglen;
	if (setsockopt(tfm->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       NULL, taglen) == -1)
		return -EINVAL;

	return 0;
}

IMPL_SYMVER(aead_setassoclen, "1.3.1")
void impl_aead_setassoclen(struct kcapi_handle *handle, size_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

ORIG_SYMVER(aead_setassoclen, "0.12.0")
void orig_aead_setassoclen(struct kcapi_handle *handle, uint32_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

IMPL_SYMVER(aead_getdata_input, "1.3.1")
void impl_aead_getdata_input(struct kcapi_handle *handle,
			     uint8_t *encdata, size_t encdatalen, int enc,
			     uint8_t **aad, size_t *aadlen,
			     uint8_t **data, size_t *datalen,
			     uint8_t **tag, size_t *taglen)
{
	uint8_t *l_aad, *l_data, *l_tag;
	size_t l_aadlen, l_datalen, l_taglen;

	if (encdatalen < handle->aead.assoclen) {
		kcapi_dolog(KCAPI_LOG_DEBUG, "AAD data not found");
		l_aad = NULL;
		l_aadlen = 0;
	} else {
		l_aad = encdata;
		l_aadlen = handle->aead.assoclen;
		encdatalen -= handle->aead.assoclen;
	}

	l_taglen = (enc && handle->flags.ge_v4_9 == true) ? 0 :
							handle->aead.taglen;
	/* databuffer is all between AAD buffer (if present) and tag */
	if (encdatalen < l_taglen) {
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Cipher result data not found");
		l_data = NULL;
		l_datalen = 0;
	} else {
		l_data = encdata + l_aadlen;
		l_datalen = encdatalen - l_taglen;
		encdatalen -= l_datalen;
	}

	if (l_taglen && encdatalen >= l_taglen)
		l_tag = encdata + l_aadlen + l_datalen;
	else {
		l_tag = NULL;
		l_taglen = 0;
	}

	if (aad && encdata)
		*aad = l_aad;
	if (aadlen)
		*aadlen = l_aadlen;
	if (data && encdata)
		*data = l_data;
	if (datalen)
		*datalen = l_datalen;
	if (tag && encdata)
		*tag = l_tag;
	if (taglen)
		*taglen = l_taglen;
}

ORIG_SYMVER(aead_getdata_input, "0.13.0")
void orig_aead_getdata_input(struct kcapi_handle *handle,
			     uint8_t *encdata, uint32_t encdatalen, int enc,
			     uint8_t **aad, uint32_t *aadlen,
			     uint8_t **data, uint32_t *datalen,
			     uint8_t **tag, uint32_t *taglen)
{
	size_t s_aadlen;
	size_t s_datalen;
	size_t s_taglen;

	impl_aead_getdata_input(handle, encdata, encdatalen, enc,
				aad, aadlen?(&s_aadlen):NULL,
				data, datalen?(&s_datalen):NULL,
				tag, taglen?(&s_taglen):NULL);

	if (aadlen)
	    *aadlen = (uint32_t)s_aadlen;

	if (datalen)
	    *datalen = (uint32_t)s_datalen;

	if (taglen)
	    *taglen = (uint32_t)s_taglen;
}

IMPL_SYMVER(aead_getdata_output, "1.3.1")
void impl_aead_getdata_output(struct kcapi_handle *handle,
			      uint8_t *encdata, size_t encdatalen, int enc,
			      uint8_t **aad, size_t *aadlen,
			      uint8_t **data, size_t *datalen,
			      uint8_t **tag, size_t *taglen)
{
	uint8_t *l_aad, *l_data, *l_tag;
	size_t l_aadlen, l_datalen, l_taglen;

	if (encdatalen < handle->aead.assoclen) {
		kcapi_dolog(KCAPI_LOG_ERR, "AAD data not found");
		l_aad = NULL;
		l_aadlen = 0;
	} else {
		l_aad = encdata;
		l_aadlen = handle->aead.assoclen;
		encdatalen -= handle->aead.assoclen;
	}

	/* with 4.9.0 we do not have a tag for decryption */
	if (handle->flags.ge_v4_9 == true)
		l_taglen = (enc) ? handle->aead.taglen : 0;
	else
		l_taglen = handle->aead.taglen;
	/* databuffer is all between AAD buffer (if present) and tag */
	if (encdatalen < l_taglen) {
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Cipher result data not found");
		l_data = NULL;
		l_datalen = 0;
	} else {
		l_data = encdata + l_aadlen;
		l_datalen = encdatalen - l_taglen;
		encdatalen -= l_datalen;
	}

	if (enc) {
		if (encdatalen >= handle->aead.taglen) {
			l_tag = encdata + l_aadlen + l_datalen;
			l_taglen = handle->aead.taglen;
		} else {
			kcapi_dolog(KCAPI_LOG_DEBUG,
				    "Tag data not found");
			l_tag = NULL;
			l_taglen = 0;
		}
	} else {
		l_tag = NULL;
		l_taglen = 0;
	}

	if (aad && encdata)
		*aad = l_aad;
	if (aadlen)
		*aadlen = l_aadlen;
	if (data && encdata)
		*data = l_data;
	if (datalen)
		*datalen = l_datalen;
	if (tag && encdata)
		*tag = l_tag;
	if (taglen)
		*taglen = l_taglen;
}

ORIG_SYMVER(aead_getdata_output, "0.13.0")
void orig_aead_getdata_output(struct kcapi_handle *handle,
			      uint8_t *encdata, uint32_t encdatalen, int enc,
			      uint8_t **aad, uint32_t *aadlen,
			      uint8_t **data, uint32_t *datalen,
			      uint8_t **tag, uint32_t *taglen)
{
	size_t s_aadlen;
	size_t s_datalen;
	size_t s_taglen;

	impl_aead_getdata_output(handle, encdata, encdatalen, enc,
				 aad, aadlen?(&s_aadlen):NULL,
				 data, datalen?(&s_datalen):NULL,
				 tag, taglen?(&s_taglen):NULL);

	if (aadlen)
	    *aadlen = (uint32_t)s_aadlen;

	if (datalen)
	    *datalen = (uint32_t)s_datalen;

	if (taglen)
	    *taglen = (uint32_t)s_taglen;
}

IMPL_SYMVER(aead_encrypt, "1.3.1")
ssize_t impl_aead_encrypt(struct kcapi_handle *handle,
			  const uint8_t *in, size_t inlen,
			  const uint8_t *iv,
			  uint8_t *out, size_t outlen, int access)
{
	ssize_t ret = 0;

	handle->cipher.iv = iv;
	ret = _kcapi_cipher_crypt(handle, in, inlen, out, outlen, access,
				  ALG_OP_ENCRYPT);
	if (ret < 0)
		return ret;
	if ((ret < (int32_t)handle->aead.taglen))
		return -E2BIG;

	return ret;
}

ORIG_SYMVER(aead_encrypt, "0.12.0")
int32_t orig_aead_encrypt(struct kcapi_handle *handle,
			  const uint8_t *in, uint32_t inlen,
			  const uint8_t *iv,
			  uint8_t *out, uint32_t outlen, int access)
{
	return (int32_t)impl_aead_encrypt(handle, in, inlen, iv, out, outlen,
					  access);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static ssize_t
_kcapi_aead_encrypt_aio_fallback(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 size_t iovlen, const uint8_t *iv)
{
	size_t i;
	ssize_t ret = 0;

	for (i = 0; i < iovlen; i++) {
		ssize_t rc = kcapi_aead_stream_init_enc(handle, iv, NULL, 0);

		if (rc < 0)
			return rc;

		rc = kcapi_aead_stream_update_last(handle, iniov, 1);
		if (rc < 0)
			return rc;

		rc = kcapi_aead_stream_op(handle, outiov, 1);
		if (rc < 0)
			return rc;

		ret += rc;

		iniov++;
		outiov++;
	}

	return ret;
}

IMPL_SYMVER(aead_encrypt_aio, "1.3.1")
ssize_t impl_aead_encrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			      struct iovec *outiov, size_t iovlen,
			      const uint8_t *iv, int access)
{
	ssize_t ret = 0;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_ENCRYPT);
	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_aead_encrypt_aio_fallback(handle, iniov, outiov, iovlen,
						iv);
}

ORIG_SYMVER(aead_encrypt_aio, "0.12.0")
int32_t orig_aead_encrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			      struct iovec *outiov, uint32_t iovlen,
			      const uint8_t *iv, int access)
{
	return (int32_t)impl_aead_encrypt_aio(handle, iniov, outiov, iovlen,
					      iv, access);
}

IMPL_SYMVER(aead_decrypt, "1.3.1")
ssize_t impl_aead_decrypt(struct kcapi_handle *handle,
			  const uint8_t *in, size_t inlen,
			  const uint8_t *iv,
			  uint8_t *out, size_t outlen, int access)
{
	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt(handle, in, inlen, out, outlen, access,
				   ALG_OP_DECRYPT);
}

ORIG_SYMVER(aead_decrypt, "0.12.0")
int32_t orig_aead_decrypt(struct kcapi_handle *handle,
			  const uint8_t *in, uint32_t inlen,
			  const uint8_t *iv,
			  uint8_t *out, uint32_t outlen, int access)
{
	return (int32_t)impl_aead_decrypt(handle, in, inlen, iv, out, outlen,
					  access);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static ssize_t
_kcapi_aead_decrypt_aio_fallback(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 size_t iovlen, const uint8_t *iv)
{
	size_t i;
	ssize_t ret = 0;

	for (i = 0; i < iovlen; i++) {
		ssize_t rc = kcapi_aead_stream_init_dec(handle, iv, NULL, 0);

		if (rc < 0)
			return rc;

		rc = kcapi_aead_stream_update_last(handle, iniov, 1);
		if (rc < 0)
			return rc;

		rc = kcapi_aead_stream_op(handle, outiov, 1);
		if (rc < 0)
			return rc;

		ret += rc;

		iniov++;
		outiov++;
	}

	return ret;
}

IMPL_SYMVER(aead_decrypt_aio, "1.3.1")
ssize_t impl_aead_decrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			      struct iovec *outiov, size_t iovlen,
			      const uint8_t *iv, int access)
{
	ssize_t ret = 0;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_DECRYPT);

	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_aead_decrypt_aio_fallback(handle, iniov, outiov, iovlen,
						iv);
}

ORIG_SYMVER(aead_decrypt_aio, "0.12.0")
int32_t orig_aead_decrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			      struct iovec *outiov, uint32_t iovlen,
			      const uint8_t *iv, int access)
{
	return (int32_t)impl_aead_decrypt_aio(handle, iniov, outiov, iovlen,
					      iv, access);
}

IMPL_SYMVER(aead_stream_init_enc, "1.3.1")
ssize_t impl_aead_stream_init_enc(struct kcapi_handle *handle,
				  const uint8_t *iv,
				  struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

ORIG_SYMVER(aead_stream_init_enc, "0.12.0")
int32_t orig_aead_stream_init_enc(struct kcapi_handle *handle,
				  const uint8_t *iv,
				  struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_aead_stream_init_enc(handle, iv, iov, iovlen);
}

IMPL_SYMVER(aead_stream_init_dec, "1.3.1")
ssize_t impl_aead_stream_init_dec(struct kcapi_handle *handle,
				  const uint8_t *iv,
				  struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

ORIG_SYMVER(aead_stream_init_dec, "0.12.0")
int32_t orig_aead_stream_init_dec(struct kcapi_handle *handle,
				  const uint8_t *iv,
				  struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_aead_stream_init_dec(handle, iv, iov, iovlen);
}

IMPL_SYMVER(aead_stream_update, "1.3.1")
ssize_t impl_aead_stream_update(struct kcapi_handle *handle,
				struct iovec *iov, size_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen,
						  SPLICE_F_MORE);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

ORIG_SYMVER(aead_stream_update, "0.12.0")
int32_t orig_aead_stream_update(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_aead_stream_update(handle, iov, iovlen);
}

IMPL_SYMVER(aead_stream_update_last, "1.3.1")
ssize_t impl_aead_stream_update_last(struct kcapi_handle *handle,
				     struct iovec *iov, size_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen, 0);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, 0);
}

ORIG_SYMVER(aead_stream_update_last, "0.12.0")
int32_t orig_aead_stream_update_last(struct kcapi_handle *handle,
				     struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_aead_stream_update_last(handle, iov, iovlen);
}

IMPL_SYMVER(aead_stream_op, "1.3.1")
ssize_t impl_aead_stream_op(struct kcapi_handle *handle,
			    struct iovec *iov, size_t iovlen)
{
	if (!iov) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "AEAD operation: No buffer for output data provided");
		return -EINVAL;
	}

	return _kcapi_common_recv_data(handle, iov, iovlen);
}

ORIG_SYMVER(aead_stream_op, "0.12.0")
int32_t orig_aead_stream_op(struct kcapi_handle *handle,
			    struct iovec *iov, uint32_t iovlen)
{
	return (int32_t)impl_aead_stream_op(handle, iov, iovlen);
}

uint32_t kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.ivsize;
}

uint32_t kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.blocksize;
}

uint32_t kcapi_aead_authsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.aead_maxauthsize;
}

IMPL_SYMVER(aead_inbuflen_enc, "1.3.1")
size_t impl_aead_inbuflen_enc(struct kcapi_handle *handle,
			      size_t inlen, size_t assoclen, size_t taglen)
{
	size_t len = inlen + assoclen;

	if (!handle->flags.ge_v4_9 == true)
		len += taglen;

	return len;
}

ORIG_SYMVER(aead_inbuflen_enc, "0.13.0")
uint32_t orig_aead_inbuflen_enc(struct kcapi_handle *handle,
				uint32_t inlen, uint32_t assoclen,
				uint32_t taglen)
{
	return (uint32_t)impl_aead_inbuflen_enc(handle, inlen, assoclen,
						taglen);
}

IMPL_SYMVER(aead_inbuflen_dec, "1.3.1")
size_t impl_aead_inbuflen_dec(struct kcapi_handle *handle,
			      size_t inlen, size_t assoclen, size_t taglen)
{
	(void)handle;
	return (inlen + assoclen + taglen);
}

ORIG_SYMVER(aead_inbuflen_dec, "0.13.0")
uint32_t orig_aead_inbuflen_dec(struct kcapi_handle *handle,
				uint32_t inlen, uint32_t assoclen,
				uint32_t taglen)
{
	return (uint32_t)impl_aead_inbuflen_dec(handle, inlen, assoclen,
						taglen);
}

IMPL_SYMVER(aead_outbuflen_enc, "1.3.1")
size_t impl_aead_outbuflen_enc(struct kcapi_handle *handle,
			       size_t inlen, size_t assoclen,
			       size_t taglen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t bs = tfm->info.blocksize;
	size_t outlen = (inlen + bs - 1) / bs * bs + taglen + assoclen;

	/* the kernel does not like zero length output buffers */
	if (!outlen)
		outlen = 1;

	return outlen;
}

ORIG_SYMVER(aead_outbuflen_enc, "0.13.0")
uint32_t orig_aead_outbuflen_enc(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen)
{
	return (uint32_t)impl_aead_outbuflen_enc(handle, inlen, assoclen,
						 taglen);
}

IMPL_SYMVER(aead_outbuflen_dec, "1.3.1")
size_t impl_aead_outbuflen_dec(struct kcapi_handle *handle,
			       size_t inlen, size_t assoclen,
			       size_t taglen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t bs = tfm->info.blocksize;
	size_t outlen = (inlen + bs - 1) / bs * bs + assoclen;

	if (!handle->flags.ge_v4_9 == true)
		outlen += taglen;

	/* the kernel does not like zero length output buffers */
	if (!outlen)
		outlen = 1;

	return outlen;
}

ORIG_SYMVER(aead_outbuflen_dec, "0.13.0")
uint32_t orig_aead_outbuflen_dec(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen)
{
	return (uint32_t)impl_aead_outbuflen_dec(handle, inlen, assoclen,
						 taglen);
}

int kcapi_aead_ccm_nonce_to_iv(const uint8_t *nonce, uint32_t noncelen,
			       uint8_t **iv, uint32_t *ivlen)
{
	uint8_t *newiv = NULL;
	uint8_t l = (uint8_t)(16 - 2 - noncelen);
	int ret = 0;

	if (noncelen > 16 - 2)
		return -EINVAL;
	ret = posix_memalign((void *)&newiv, 16, 16);
	if (ret)
		return -ret;
	memset(newiv, 0, 16);
	newiv[0] = l;
	memcpy(newiv + 1, nonce, noncelen);

	*iv = newiv;
	*ivlen = 16;

	return 0;
}
