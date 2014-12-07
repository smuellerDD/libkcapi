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

#include <linux/if_alg.h>
#include <sys/uio.h>

/**
 * Information obtained for different ciphers during handle init time
 * using the NETLINK_CRYPTO interface.
 * @blocksize block size of cipher (hash, symmetric, AEAD)
 * @ivsize size of IV of cipher (symmetric, AEAD)
 * @hash_digestsize size of message digest (hash)
 * @blk_min_keysize minimum key size (symmetric)
 * @blk_max_keysize maximum key size (symmetric)
 * @aead_maxauthsize maximum authentication tag size (AEAD)
 * @rng_seedsize seed size (RNG)
 */
struct kcapi_cipher_info {
	/* generic */
	unsigned int blocksize;
	unsigned int ivsize;
	/* hash */
	unsigned int hash_digestsize;
	/* blkcipher */
	unsigned int blk_min_keysize;
	unsigned int blk_max_keysize;
	/* aead */
	unsigned int aead_maxauthsize;
	/* rng */
	unsigned int rng_seedsize;
};

/**
 * Common data required for symmetric and AEAD ciphers
 * @iv: IV - input
 * @ivlen: Length of IV - input
 */
struct kcapi_cipher_data {
	const unsigned char *iv;
	size_t ivlen;
};

/**
 * AEAD data
 * @datalen: Length of plaintext / ciphertext data - input
 * @data: Pointer to plaintext / ciphertext data - input / output (the length is
 *	  calculated with: kcapi_skcipher_data->inlen -
 *			   kcapi_aead_data->taglen - kcapi_aead_data->assoclen)
 * @assoclen: Length of associated data - input
 * @assoc: Pointer to associated data - input
 * @taglen: Length of authentication tag - input
 * @tag: Authentication tag - input for decryption, output for encryption
 * @retlen: internal data -- number plaintext / ciphertext bytes returned by
 *	    the read system call
 */
struct kcapi_aead_data {
	size_t datalen;
	unsigned char *data;
	size_t assoclen;
	unsigned char *assoc;
	size_t taglen;
	unsigned char *tag;
};

/**
 * Cipher handle
 * @tfmfd: Socket descriptor for AF_ALG
 * @opfd: FD to open kernel crypto API TFM
 * @skdata: Common data for all ciphers
 * @aead: AEAD cipher specific data
 * @info: properties of ciphers
 */
struct kcapi_handle {
	int tfmfd;
	int opfd;
	int pipes[2];
	struct kcapi_cipher_data cipher;
	struct kcapi_aead_data aead;
	struct kcapi_cipher_info info;
};

/* Symmetric Cipher API */
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
ssize_t kcapi_cipher_stream_init_enc(struct kcapi_handle *handle,
				     struct iovec *iov, size_t iovlen);
ssize_t kcapi_cipher_stream_init_dec(struct kcapi_handle *handle,
				     struct iovec *iov, size_t iovlen);
ssize_t kcapi_cipher_stream_update(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen);
ssize_t kcapi_cipher_stream_op(struct kcapi_handle *handle,
			       struct iovec *iov, size_t iovlen);
unsigned int kcapi_cipher_ivsize(struct kcapi_handle *handle);
unsigned int kcapi_cipher_blocksize(struct kcapi_handle *handle);

/* AEAD Cipher API */
int kcapi_aead_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_aead_destroy(struct kcapi_handle *handle);
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const unsigned char *key, size_t keylen);
int kcapi_aead_setiv(struct kcapi_handle *handle,
		     const unsigned char *iv, size_t ivlen);
int kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen);
void kcapi_aead_setassoclen(struct kcapi_handle *handle, size_t assoclen);
ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *assoc, unsigned char *out,
			   size_t outlen);
void kcapi_aead_getdata(struct kcapi_handle *handle,
			unsigned char *encdata, size_t encdatalen,
			unsigned char **data, size_t *datalen,
			unsigned char **tag, size_t *taglen);
ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *assoc, const unsigned char *tag,
			   unsigned char *out, size_t outlen);
ssize_t kcapi_aead_stream_init_enc(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen);
ssize_t kcapi_aead_stream_init_dec(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen);
ssize_t kcapi_aead_stream_update(struct kcapi_handle *handle,
				 struct iovec *iov, size_t iovlen);
ssize_t kcapi_aead_stream_update_last(struct kcapi_handle *handle,
				      struct iovec *iov, size_t iovlen);
ssize_t kcapi_aead_stream_op(struct kcapi_handle *handle,
			     struct iovec *iov, size_t iovlen);
unsigned int kcapi_aead_ivsize(struct kcapi_handle *handle);
unsigned int kcapi_aead_blocksize(struct kcapi_handle *handle);
unsigned int kcapi_aead_authsize(struct kcapi_handle *handle);
size_t kcapi_aead_outbuflen(struct kcapi_handle *handle,
			    size_t inlen, size_t taglen, int enc);
int kcapi_aead_ccm_nonce_to_iv(const unsigned char *nonce, size_t noncelen,
			       unsigned char **iv, size_t *ivlen);

/* Message Digest Cipher API */
int kcapi_md_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_md_destroy(struct kcapi_handle *handle);
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const unsigned char *key, size_t keylen);
ssize_t kcapi_md_update(struct kcapi_handle *handle,
			const unsigned char *buffer, size_t len);
ssize_t kcapi_md_final(struct kcapi_handle *handle,
		       unsigned char *buffer, size_t len);
ssize_t kcapi_md_digest(struct kcapi_handle *handle,
		       const unsigned char *in, size_t inlen,
		       unsigned char *out, size_t outlen);
unsigned int kcapi_md_digestsize(struct kcapi_handle *handle);

/* Random Number API */
int kcapi_rng_init(struct kcapi_handle *handle, const char *ciphername);
int kcapi_rng_destroy(struct kcapi_handle *handle);
int kcapi_rng_seed(struct kcapi_handle *handle, unsigned char *seed,
		   size_t seedlen);
ssize_t kcapi_rng_generate(struct kcapi_handle *handle,
			   unsigned char *buffer, size_t len);

void kcapi_versionstring(char *buf, size_t buflen);
int kcapi_pad_iv(struct kcapi_handle *handle,
		 const unsigned char *iv, size_t ivlen,
		 unsigned char **newiv, size_t *newivlen);

#endif /* _KCAPI_H */
