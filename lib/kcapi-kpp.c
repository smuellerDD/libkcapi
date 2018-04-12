/* Kernel crypto API AF_ALG Key-Agreement Protocol Primitives API
 *
 * Copyright (C) 2017 - 2018, Stephan Mueller <smueller@chronox.de>
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
int kcapi_kpp_init(struct kcapi_handle **handle, const char *ciphername,
		   uint32_t flags)
{
	int ret = _kcapi_handle_init(handle, "kpp", ciphername, flags);

	if (ret)
		return ret;

	return 0;
}

DSO_PUBLIC
void kcapi_kpp_destroy(struct kcapi_handle *handle)
{
	_kcapi_handle_destroy(handle);
}

DSO_PUBLIC
int kcapi_kpp_dh_setparam_pkcs3(struct kcapi_handle *handle,
				const uint8_t *pkcs3, uint32_t pkcs3len)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int ret = 0;

	ret = setsockopt(tfm->tfmfd, SOL_ALG, ALG_SET_DH_PARAMETERS,
			 pkcs3, pkcs3len);
	return (ret >= 0) ? ret : -errno;
}

DSO_PUBLIC
int kcapi_kpp_ecdh_setcurve(struct kcapi_handle *handle,
			    unsigned long curve_id)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	char curve_id_str[sizeof(unsigned long)];
	int ret = 0;

	snprintf(curve_id_str, sizeof(curve_id_str), "%lu", curve_id);
	ret = setsockopt(tfm->tfmfd, SOL_ALG, ALG_SET_ECDH_CURVE,
			 curve_id_str, sizeof(curve_id_str));
	return (ret >= 0) ? ret : -errno;
}

DSO_PUBLIC
int kcapi_kpp_setkey(struct kcapi_handle *handle,
		     const uint8_t *key, uint32_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

DSO_PUBLIC
int32_t kcapi_kpp_keygen(struct kcapi_handle *handle,
			 uint8_t *pubkey, uint32_t pubkeylen, int access)
{
	return _kcapi_cipher_crypt(handle, NULL, 0, pubkey, pubkeylen, access,
				   ALG_OP_KEYGEN);
}

DSO_PUBLIC
int32_t kcapi_kpp_ssgen(struct kcapi_handle *handle,
			const uint8_t *pubkey, uint32_t pubkeylen,
			uint8_t *ss, uint32_t sslen, int access)
{
	return _kcapi_cipher_crypt(handle, pubkey, pubkeylen, ss, sslen, access,
				   ALG_OP_SSGEN);
}

static int32_t
_kcapi_kpp_crypt_aio(struct kcapi_handle *handle, struct iovec *iniov,
		     struct iovec *outiov, uint32_t iovlen, int access, int enc)
{
	struct iovec zeroiov;
	uint32_t processed = 0;
	int32_t ret;

	/* TODO Every IOVEC is processed as its individual cipher operation. */
	while (iovlen) {
		ret = _kcapi_cipher_crypt_aio(handle, iniov ? iniov : &zeroiov,
					      outiov, 1, access, enc);
		if (ret < 0)
			return ret;

		processed += ret;

		if (iniov)
			iniov++;
		outiov++;
		iovlen--;
	}
	return processed;
}

DSO_PUBLIC
int32_t kcapi_kpp_keygen_aio(struct kcapi_handle *handle, struct iovec *outiov,
			     uint32_t iovlen, int access)
{
	return _kcapi_kpp_crypt_aio(handle, NULL, outiov, iovlen, access,
				    ALG_OP_KEYGEN);
}

DSO_PUBLIC
int32_t kcapi_kpp_ssgen_aio(struct kcapi_handle *handle,
			    struct iovec *iniov, struct iovec *outiov,
			    uint32_t iovlen, int access)
{
	return _kcapi_kpp_crypt_aio(handle, iniov, outiov, iovlen, access,
				    ALG_OP_SSGEN);
}
