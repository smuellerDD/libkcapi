/* Kernel crypto API AF_ALG AEAD API
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

#include "internal.h"
#include "kcapi.h"

DSO_PUBLIC
int kcapi_aead_init(struct kcapi_handle **handle, const char *ciphername,
		    uint32_t flags)
{
	return _kcapi_handle_init(handle, "aead", ciphername, flags);
}

DSO_PUBLIC
void kcapi_aead_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

DSO_PUBLIC
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

DSO_PUBLIC
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

DSO_PUBLIC
void kcapi_aead_setassoclen(struct kcapi_handle *handle, uint32_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

DSO_PUBLIC
void kcapi_aead_getdata_input(struct kcapi_handle *handle,
			      uint8_t *encdata, uint32_t encdatalen, int enc,
			      uint8_t **aad, uint32_t *aadlen,
			      uint8_t **data, uint32_t *datalen,
			      uint8_t **tag, uint32_t *taglen)
{
	uint8_t *l_aad, *l_data, *l_tag;
	uint32_t l_aadlen, l_datalen, l_taglen;

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

DSO_PUBLIC
void kcapi_aead_getdata_output(struct kcapi_handle *handle,
			       uint8_t *encdata, uint32_t encdatalen, int enc,
			       uint8_t **aad, uint32_t *aadlen,
			       uint8_t **data, uint32_t *datalen,
			       uint8_t **tag, uint32_t *taglen)
{
	uint8_t *l_aad, *l_data, *l_tag;
	uint32_t l_aadlen, l_datalen, l_taglen;

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

DSO_PUBLIC
int32_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const uint8_t *in, uint32_t inlen,
			   const uint8_t *iv,
			   uint8_t *out, uint32_t outlen, int access)
{
	int32_t ret = 0;

	handle->cipher.iv = iv;
	ret = _kcapi_cipher_crypt(handle, in, inlen, out, outlen, access,
				  ALG_OP_ENCRYPT);
	if (ret < 0)
		return ret;
	if ((ret < (int32_t)handle->aead.taglen))
		return -E2BIG;

	return ret;
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static int32_t
_kcapi_aead_encrypt_aio_fallback(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv)
{
	uint32_t i;
	int32_t ret = kcapi_aead_stream_init_enc(handle, iv, NULL, 0);

	if (ret < 0)
		return ret;

	for (i = 0; i < iovlen; i++) {
		int rc = kcapi_aead_stream_update_last(handle, iniov, 1);
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

DSO_PUBLIC
int32_t kcapi_aead_encrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			       struct iovec *outiov, uint32_t iovlen,
			       const uint8_t *iv, int access)
{
	int32_t ret = 0;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_ENCRYPT);
	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_aead_encrypt_aio_fallback(handle, iniov, outiov, iovlen,
						iv);
}

DSO_PUBLIC
int32_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const uint8_t *in, uint32_t inlen,
			   const uint8_t *iv,
			   uint8_t *out, uint32_t outlen, int access)
{
	handle->cipher.iv = iv;
	return _kcapi_cipher_crypt(handle, in, inlen, out, outlen, access,
				   ALG_OP_DECRYPT);
}

/*
 * Fallback function if AIO is not present, but caller requested AIO operation.
 */
static int32_t
_kcapi_aead_decrypt_aio_fallback(struct kcapi_handle *handle,
				 struct iovec *iniov, struct iovec *outiov,
				 uint32_t iovlen, const uint8_t *iv)
{
	uint32_t i;
	int32_t ret = kcapi_aead_stream_init_dec(handle, iv, NULL, 0);

	if (ret < 0)
		return ret;

	for (i = 0; i < iovlen; i++) {
		int rc = kcapi_aead_stream_update_last(handle, iniov, 1);
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

DSO_PUBLIC
int32_t kcapi_aead_decrypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
			       struct iovec *outiov, uint32_t iovlen,
			       const uint8_t *iv, int access)
{
	int32_t ret = 0;

	handle->cipher.iv = iv;

	ret = _kcapi_cipher_crypt_aio(handle, iniov, outiov, iovlen,
				      access, ALG_OP_DECRYPT);

	if (ret != -EOPNOTSUPP)
		return ret;

	return _kcapi_aead_decrypt_aio_fallback(handle, iniov, outiov, iovlen,
						iv);
}

DSO_PUBLIC
int32_t kcapi_aead_stream_init_enc(struct kcapi_handle *handle,
				   const uint8_t *iv,
				   struct iovec *iov, uint32_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_aead_stream_init_dec(struct kcapi_handle *handle,
				   const uint8_t *iv,
				   struct iovec *iov, uint32_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_aead_stream_update(struct kcapi_handle *handle,
				 struct iovec *iov, uint32_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen,
						  SPLICE_F_MORE);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

DSO_PUBLIC
int32_t kcapi_aead_stream_update_last(struct kcapi_handle *handle,
				      struct iovec *iov, uint32_t iovlen)
{
	if (handle->processed_sg <= handle->flags.alg_max_pages)
		return _kcapi_common_vmsplice_iov(handle, iov, iovlen, 0);
	else
		return _kcapi_common_send_data(handle, iov, iovlen, 0);
}

DSO_PUBLIC
int32_t kcapi_aead_stream_op(struct kcapi_handle *handle,
			     struct iovec *iov, uint32_t iovlen)
{
	if (!iov) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "AEAD operation: No buffer for output data provided");
		return -EINVAL;
	}

	return _kcapi_common_recv_data(handle, iov, iovlen);
}

DSO_PUBLIC
uint32_t kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.ivsize;
}

DSO_PUBLIC
uint32_t kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.blocksize;
}

DSO_PUBLIC
uint32_t kcapi_aead_authsize(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	return tfm->info.aead_maxauthsize;
}

DSO_PUBLIC
uint32_t kcapi_aead_inbuflen_enc(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen)
{
	uint32_t len = inlen + assoclen;

	if (!handle->flags.ge_v4_9 == true)
		len += taglen;

	return len;
}

DSO_PUBLIC
uint32_t kcapi_aead_inbuflen_dec(struct kcapi_handle *handle,
				 uint32_t inlen, uint32_t assoclen,
				 uint32_t taglen)
{
	(void)handle;
	return (inlen + assoclen + taglen);
}

DSO_PUBLIC
uint32_t kcapi_aead_outbuflen_enc(struct kcapi_handle *handle,
				  uint32_t inlen, uint32_t assoclen,
				  uint32_t taglen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int bs = tfm->info.blocksize;
	uint32_t outlen = (inlen + bs - 1) / bs * bs + taglen + assoclen;

	/* the kernel does not like zero length output buffers */
	if (!outlen)
		outlen = 1;

	return outlen;
}

DSO_PUBLIC
uint32_t kcapi_aead_outbuflen_dec(struct kcapi_handle *handle,
				  uint32_t inlen, uint32_t assoclen,
				  uint32_t taglen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int bs = tfm->info.blocksize;
	uint32_t outlen = (inlen + bs - 1) / bs * bs + assoclen;

	if (!handle->flags.ge_v4_9 == true)
		outlen += taglen;

	/* the kernel does not like zero length output buffers */
	if (!outlen)
		outlen = 1;

	return outlen;
}

DSO_PUBLIC
int kcapi_aead_ccm_nonce_to_iv(const uint8_t *nonce, uint32_t noncelen,
			       uint8_t **iv, uint32_t *ivlen)
{
	uint8_t *newiv = NULL;
	uint8_t l = 16 - 2 - noncelen;
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
