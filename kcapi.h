/*
 * Copyright (C) 2014, Stephan Mueller <smueller@chronox.de>
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

#ifndef _KCAPI_H
#define _KCAPI_H

/**
 * Common data required for symmetric and AEAD ciphers
 * @in: Input data (plaintext for encryption, ciphertext for
 *	decryption) - input
 * @inlen: Length of in buffer - input
 * @out: output buffer (ciphertext for encryption, plaintext for
 *	 decryption) - output
 * @outlen: Length of output buffer - input
 * @iv: IV - input
 * @ivlen: Length of IV - input
 */
struct kcapi_skcipher_data {
	const unsigned char *in;
	size_t inlen;
	unsigned char *out;
	size_t outlen;
	const unsigned char *iv;
	size_t ivlen;
};

/**
 * AEAD data
 * @assoc: Associated data - input
 * @assoclen: Length of associated data - input
 * @taglen: Length of authentication tag - input
 * @tag: Authentication tag - input for decryption, output for encryption
 */
struct kcapi_aead_data {
	const unsigned char *assoc;
	size_t assoclen;
	size_t taglen;
	unsigned char *tag;
};

/**
 * Cipher handle
 * @tfmfd: Socket descriptor for AF_ALG
 * @opfd: FD to open kernel crypto API TFM
 * @skdata: Common data for all ciphers
 * @aead: AEAD cipher specific data
 */
struct kcapi_handle {
	int tfmfd;
	int opfd;
	struct kcapi_skcipher_data skdata;
	struct kcapi_aead_data aead;
};

int kcapi_cipher_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_cipher_destroy(struct kcapi_handle *handle);
int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const unsigned char *key, size_t keylen);
int kcapi_cipher_setiv(struct kcapi_handle *handle,
		       const unsigned char *iv, size_t ivlen);
ssize_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen);
ssize_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen);
int kcapi_cipher_ivsize(struct kcapi_handle *handle);
int kcapi_cipher_blocksize(struct kcapi_handle *handle);

int kcapi_aead_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_aead_destroy(struct kcapi_handle *handle);
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const unsigned char *key, size_t keylen);
int kcapi_aead_setiv(struct kcapi_handle *handle,
		     const unsigned char *iv, size_t ivlen);
void kcapi_aead_setassoc(struct kcapi_handle *handle,
			 const unsigned char *assoc, size_t assoclen);
void kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen);
ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen);
ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen);
void kcapi_aead_gettag(struct kcapi_handle *handle,
		       unsigned char **tag, size_t *taglen);
int kcapi_aead_ivsize(struct kcapi_handle *handle);
int kcapi_aead_blocksize(struct kcapi_handle *handle);
int kcapi_aead_authsize(struct kcapi_handle *handle);
int kcapi_aead_ccm_nonce_to_iv(const unsigned char *nonce, size_t noncelen,
			       unsigned char **iv, size_t *ivlen);

int kcapi_md_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_md_destroy(struct kcapi_handle *handle);
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const unsigned char *key, size_t keylen);
int kcapi_md_update(struct kcapi_handle *handle,
		    const unsigned char *buffer, size_t len);
ssize_t kcapi_md_final(struct kcapi_handle *handle,
		       unsigned char *buffer, size_t len);
int kcapi_md_digestsize(struct kcapi_handle *handle);

int kcapi_rng_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_rng_destroy(struct kcapi_handle *handle);
ssize_t kcapi_rng_generate(struct kcapi_handle *handle,
			   unsigned char *buffer, size_t len);

void kcapi_versionstring(char *buf, size_t buflen);
int kcapi_pad_iv(struct kcapi_handle *handle,
		 const unsigned char *iv, size_t ivlen,
		 unsigned char **newiv, size_t *newivlen);

#endif /* _KCAPI_H */
