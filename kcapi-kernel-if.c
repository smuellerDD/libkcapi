/*
 * Generic kernel crypto API user space interface library
 *
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
 * the GNU General Public License, in which case the provisions of the GPL2 are
 * required INSTEAD OF the above restrictions.  (This clause is
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

#include <stdio.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_alg.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "kcapi.h"

#define MAJVERSION 0 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated */
#define MINVERSION 1 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 0 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/* remove once in if_alg.h */
#define ALG_SET_AEAD_ASSOC		4
#define ALG_SET_AEAD_AUTHSIZE		5
#define ALG_GET_BLOCKSIZE		6
#define ALG_GET_IVSIZE			7
#define ALG_GET_AEAD_AUTHSIZE		8

struct af_alg_aead_assoc {
	__u32	aead_assoclen;
	__u8	aead_assoc[0];
};

/* remove once in socket.h */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif


/************************************************************
 * Internal logic
 ************************************************************/

/* The in/out should be aligned to page boundary */
static ssize_t _kcapi_common_crypt(struct kcapi_handle *handle,
				   uint32_t enc)
{
	ssize_t ret = -EINVAL;
	char *buffer = NULL;
	volatile void *_buffer = NULL;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct iovec iov;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	size_t iv_msg_size = handle->skdata.iv ?
			  CMSG_SPACE(sizeof(*alg_iv) + handle->skdata.ivlen) :
			  0;

	/* AEAD data */
	uint32_t *taglen = NULL;
	size_t taglen_msg_size = handle->aead.taglen ?
				 CMSG_SPACE(sizeof(*taglen)) : 0;
	struct af_alg_aead_assoc *alg_assoc = NULL;
	size_t assoc_msg_size = handle->aead.taglen ?
				CMSG_SPACE(sizeof(*alg_assoc) +
					   handle->aead.assoclen) : 0;

	size_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + 	/* Encryption / Decryption */
		iv_msg_size +			/* IV */
		taglen_msg_size +		/* AEAD tag length */
		assoc_msg_size;			/* AEAD associated data */

	memset(&msg, 0, sizeof(msg));

	buffer = calloc(1, bufferlen);
	if (!buffer)
		return -ENOMEM;

	iov.iov_base = (void*)(uintptr_t)handle->skdata.in;
	iov.iov_len = handle->skdata.inlen;
	msg.msg_control = buffer;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = enc;

	/* set IV */
	if (handle->skdata.iv) {
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = handle->skdata.ivlen;
		memcpy(alg_iv->iv, handle->skdata.iv, handle->skdata.ivlen);
	}

	/* set AEAD information */
	if (handle->aead.taglen) {
		if (enc &&
		    ((handle->skdata.inlen + handle->aead.taglen) <
		     handle->skdata.outlen)) {
			ret = -ENOMEM;
			goto bad;
		}
		/* Set tag length */
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_AEAD_AUTHSIZE;
		header->cmsg_len = CMSG_LEN(sizeof(*taglen));
		taglen = (void*)CMSG_DATA(header);
		*taglen = handle->aead.taglen;

		/* Set associated data length */
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_AEAD_ASSOC;
		header->cmsg_len = assoc_msg_size;
		alg_assoc = (void*)CMSG_DATA(header);
		alg_assoc->aead_assoclen = handle->aead.assoclen;
		memcpy(alg_assoc->aead_assoc, handle->aead.assoc,
		       handle->aead.assoclen);
	}

	ret = sendmsg(handle->opfd, &msg, 0);
	if (ret != (ssize_t)handle->skdata.inlen)
		goto bad;

	ret = read(handle->opfd, handle->skdata.out, handle->skdata.outlen);
	if (0 > ret)
		goto bad;
	if ((enc && ret < (ssize_t)handle->aead.taglen) ||
	    (ret < 0)) {
		ret = -E2BIG;
		goto bad;
	}

	if (enc && handle->aead.taglen) {
		handle->aead.tag = handle->skdata.out +
				  (ret - handle->aead.taglen);
		handle->skdata.outlen = ret - handle->aead.taglen;
	}

bad:
	memset(buffer, 0, bufferlen);
	_buffer = memchr(buffer, 1, bufferlen);
	if (_buffer)
		_buffer = '\0';
	free(buffer);
	return ret;
}

static inline ssize_t _kcapi_common_encrypt(struct kcapi_handle *handle,
					    const unsigned char *in,
					    size_t inlen,
					    unsigned char *out, size_t outlen)
{
	handle->skdata.in = in;
	handle->skdata.inlen = inlen;
	handle->skdata.out = out;
	handle->skdata.outlen = outlen;

	return _kcapi_common_crypt(handle, ALG_OP_ENCRYPT);
}

static inline ssize_t _kcapi_common_decrypt(struct kcapi_handle *handle,
					    const unsigned char *in,
					    size_t inlen,
					    unsigned char *out, size_t outlen)
{
	handle->skdata.in = in;
	handle->skdata.inlen = inlen;
	handle->skdata.out = out;
	handle->skdata.outlen = outlen;

	return _kcapi_common_crypt(handle, ALG_OP_DECRYPT);
}

static inline int _kcapi_common_setkey(struct kcapi_handle *handle,
				       const unsigned char *key, size_t keylen)
{
	if (setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_KEY,
		       key, keylen) == -1)
		return -EINVAL;

	return 0;
}

static inline unsigned int _kcapi_common_getinfo(struct kcapi_handle *handle,
						 int optval)
{
	socklen_t len = 0;
	if (getsockopt(handle->opfd, SOL_ALG, optval, NULL, &len) == -1)
		return 0;

	return (int)len;
}

static int _kcapi_handle_init(struct kcapi_handle *handle,
			      const char *type, const char *ciphername)
{
	struct sockaddr_alg sa;

	memset(handle, 0, sizeof(struct kcapi_handle));

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type),"%s", type);
	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),"%s", ciphername);

	handle->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (handle->tfmfd == -1)
		return -ENOTSUP;

	if (bind(handle->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -ENOENT;
	}

	handle->opfd = accept(handle->tfmfd, NULL, 0);
	if (handle->opfd == -1) {
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -EINVAL;
	}

	return 0;
}

static inline int _kcapi_handle_destroy(struct kcapi_handle *handle)
{
	if (handle->tfmfd != -1)
		close(handle->tfmfd);
	if (handle->opfd != -1)
		close(handle->opfd);
	return 0;
}

/************************************************************
 * Common API
 ************************************************************/

/**
 * Obtain version string of kcapi library
 *
 * @buf buffer to place version string into
 * @buflen length of buffer
 */
void kcapi_versionstring(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "libkcapi %d.%d.%d", MAJVERSION, MINVERSION,
		 PATCHLEVEL);
}

/************************************************************
 * Symmetric Cipher API
 ************************************************************/

/**
 * Initialization of a symmetric cipher handle and establishing the connection
 * to the kernel
 *
 * @handle cipher handle filled during the call - output
 * @ciphername kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 *		ENOENT - algorithm not available
 *		ENOTSUP - AF_ALG family not available
 *		EINVAL - accept syscall failed
 */
int kcapi_cipher_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "skcipher", ciphername);
}

/**
 * Close the cipher handle and release resources
 *
 * @handle cipher handle to release - input
 *
 * return: 0 upon success
 */
int kcapi_cipher_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * Set the key for the cipher handle -- for symmetric and AEAD ciphers
 *
 * @handle cipher handle - input
 * @key key buffer - input
 * @keylen length of key buffer - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 */
int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * Set IV for the cipher operation
 *
 * This function requires IV to be exactly block size.
 *
 * @handle cipher handle - input
 * @iv buffer holding the IV (may be NULL if IV is not needed) - input
 * @ivlen length of iv (should be zero if iv is NULL) - input
 */
void kcapi_cipher_setiv(struct kcapi_handle *handle,
			const unsigned char *iv, size_t ivlen)
{
	handle->skdata.iv = iv;
	handle->skdata.ivlen = iv ? ivlen : 0;
}

/**
 * Encrypt data
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * @handle cipher handle - input
 * @in plaintext data buffer - input
 * @inlen length of in buffer - input
 * @out ciphertext data buffer - output
 * @outlen length of out buffer - input
 *
 * return: number of bytes encrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	return _kcapi_common_encrypt(handle, in, inlen, out, outlen);
}

/**
 * Decrypt data
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * @handle cipher handle - input
 * @in ciphertext data buffer - input
 * @inlen length of in buffer - input
 * @out plaintext data buffer - output
 * @outlen length of out buffer - input
 *
 * return: number of bytes decrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	return _kcapi_common_decrypt(handle, in, inlen, out, outlen);
}

/**
 * Return size of IV required for cipher pointed to by the cipher handle
 *
 * @handle cipher handle
 *
 * return: > 0 specifying the IV size
 * 	   0 on error
 */
int kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);
}

/**
 * Return size of one block of the cipher pointed to by the cipher handle
 *
 * @handle cipher handle
 *
 * return: > 0 specifying the block size
 * 	   0 on error
 */
int kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_BLOCKSIZE);
}

/************************************************************
 * AEAD Cipher API
 ************************************************************/

/**
 * Initialization of an AEAD cipher handle and establishing the connection
 * to the kernel
 *
 * @handle cipher handle filled during the call - output
 * @ciphername kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 *		ENOENT - algorithm not available
 *		ENOTSUP - AF_ALG family not available
 *		EINVAL - accept syscall failed
 */
int kcapi_aead_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "aead", ciphername);
}

/**
 * Close the AEAD handle and release resources
 *
 * @handle cipher handle to release - input
 *
 * return: 0 upon success
 */
int kcapi_aead_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * Set the key for the AEAD handle
 *
 * @handle cipher handle - input
 * @key key buffer - input
 * @keylen length of key buffer - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 */
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * Set IV for the AEAD operation
 *
 * This function requires IV to be exactly block size.
 *
 * @handle cipher handle - input
 * @iv buffer holding the IV (may be NULL if IV is not needed) - input
 * @ivlen length of iv (should be zero if iv is NULL) - input
 */
void kcapi_aead_setiv(struct kcapi_handle *handle,
		      const unsigned char *iv, size_t ivlen)
{
	handle->skdata.iv = iv;
	handle->skdata.ivlen = iv ? ivlen : 0;
}

/**
 * Set associated data for AEAD operation
 *
 * This call is applicable for AEAD ciphers
 *
 * @handle cipher handle - input
 * @assoc buffer holding the IV (may be NULL if associated data is not
 *	  needed) - input
 * @assoclen length of assoc (should be zero if assoc is NULL) - input
 */
void kcapi_aead_setassoc(struct kcapi_handle *handle,
			 const unsigned char *assoc, size_t assoclen)
{
	handle->aead.assoc = assoc;
	handle->aead.assoclen = assoc ? assoclen : 0;
}

/**
 * Set tag size / authentication data size for AEAD operation
 *
 * This call is applicable for AEAD ciphers
 *
 * Note, for decryption, the tag must be appended to the ciphertext memory. For
 * encryption, the tag will be appended to the ciphertext.
 *
 * @handle cipher handle - input
 * @taglen length of tag - input
 */
void kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen)
{
	handle->aead.taglen = taglen;
}

/**
 * Encrypt data
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * The ciphertext buffer will hold the tag as follows:
 * 	ciphertext || tag
 * The caller must ensure that the ciphertext buffer is large enough to hold
 * the ciphertext together with the tag of the size set by the caller using
 * the kcapi_cipher_settaglen function.
 *
 * @handle cipher handle - input
 * @in plaintext data buffer - input
 * @inlen length of in buffer - input
 * @out ciphertext data buffer - output
 * @outlen length of out buffer - input
 *
 * return: number of bytes encrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen)
{
	return _kcapi_common_encrypt(handle, in, inlen, out, outlen);
}

/**
 * Decrypt data
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * The ciphertext buffer must contain the tag as follows:
 * 	ciphertext || tag
 * The plaintext buffer will not hold the tag which means the caller only needs
 * to allocate memory sufficient to hold the plaintext.
 *
 * To catch authentication errors (i.e. integrity violations) during the
 * decryption operation, the errno of this call shall be checked for EBADMSG.
 * If this function returns < 0 and errno is set to EBADMSG, an authentication
 * error is detected.
 *
 * @handle cipher handle - input
 * @in ciphertext data buffer - input
 * @inlen length of in buffer - input
 * @out plaintext data buffer - output
 * @outlen length of out buffer - input
 *
 * return: number of bytes decrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen)
{
	return _kcapi_common_decrypt(handle, in, inlen, out, outlen);
}

/**
 * Get the tag / authentication data and its size from AEAD operation
 *
 * This call is applicable for AEAD ciphers
 *
 * Note, this call is only needed for obtaining the generated tag after
 * after encryption.
 *
 * @handle cipher handle - input
 * @tag tag buffer pointer - output
 * @taglen length of tag - output
 */
void kcapi_aead_gettag(struct kcapi_handle *handle,
		       unsigned char **tag, size_t *taglen)
{
	*tag = handle->aead.tag;
	*taglen = handle->aead.taglen;
}

/**
 * Return size of IV required for cipher pointed to by the AEAD handle
 *
 * @handle cipher handle
 *
 * return: > 0 specifying the IV size
 * 	   0 on error
 */
int kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);
}

/**
 * Return size of one block of the cipher pointed to by the AEAD handle
 *
 * @handle cipher handle
 *
 * return: > 0 specifying the block size
 * 	   0 on error
 */
int kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_BLOCKSIZE);
}

/**
 * Return the maximum size of the tag that can be produced by the AEAD
 * cipher. Smaller tag sizes may be chosen depending on the AEAD cipher
 * type.
 *
 * @handle cipher handle
 *
 * return: > 0 specifying the block size
 * 	   0 on error
 */
int kcapi_aead_authsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_AEAD_AUTHSIZE);
}

/**
 * Service function to convert a CCM nonce value into an IV usable by
 * the kernel crypto API.
 *
 * Caller must free iv.
 *
 * @nonce buffer with nonce - input
 * @noncelen length of nonce - input
 * @iv newly allocated buffer with IV - output
 * @ivlen length of IV - output
 *
 * return: 0 upon success
 *	   < 0 upon failure
 */
int kcapi_aead_ccm_nonce_to_iv(const unsigned char *nonce, size_t noncelen,
			       unsigned char **iv, size_t *ivlen)
{
	unsigned char *newiv = NULL;
	unsigned char l = 16 - 2 - noncelen;

	if (noncelen > 16 - 2)
		return -EINVAL;
	newiv = calloc(1, 16);
	if (!newiv)
		return -ENOMEM;
	newiv[0] = l;
	memcpy(newiv + 1, nonce, noncelen);

	*iv = newiv;
	*ivlen = 16;

	return 0;
}

/************************************************************
 * Message Digest Cipher API
 ************************************************************/

/**
 * Initialization of a (keyed) message digest handle and establishing the
 * connection to the kernel
 *
 * @handle cipher handle filled during the call - output
 * @ciphername kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 *		ENOENT - algorithm not available
 *		ENOTSUP - AF_ALG family not available
 *		EINVAL - accept syscall failed
 */
int kcapi_md_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "hash", ciphername);
}

/**
 * Close the message digest handle and release resources
 *
 * @handle cipher handle to release - input
 *
 * return: 0 upon success
 */
int kcapi_md_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * Set the key for the message digest handle
 *
 * This call is applicable for keyed message digests.
 *
 * @handle cipher handle - input
 * @key key buffer - input
 * @keylen length of key buffer - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 */
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * Message digest update function
 *
 * @handle cipher handle - input
 * @buffer holding the data to add to the message digest - input
 * @len buffer length - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 */
int kcapi_md_update(struct kcapi_handle *handle,
		    const unsigned char *buffer, size_t len)
{
	ssize_t r;

	r = send(handle->opfd, buffer, len, MSG_MORE);
	if (r < 0 || (size_t)r < len)
		return -EIO;

	return 0;
}

/**
 * Message digest finalization function
 *
 * @handle cipher handle - input
 * @buffer filled with the message digest - output
 * @len buffer length - input
 *
 * return: size of message digest upon success
 *	   < 0 in case of error
 *		EIO - data cannot be obtained
 *		ENOMEM - buffer is too small for the complete message digest,
 *			 the buffer is filled with the truncated message digest
 */

ssize_t kcapi_md_final(struct kcapi_handle *handle,
		       unsigned char *buffer, size_t len)
{
	ssize_t r;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = (void*)(uintptr_t)buffer;
	iov.iov_len = len;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	r = recvmsg(handle->opfd, &msg, 0);
	if (r < 0)
		return -EIO;
	if (msg.msg_flags & MSG_TRUNC)
		return -ENOMEM;

	return r;
}


/************************************************************
 * Deterministic Random Number API
 ************************************************************/

/**
 * Initialization of a random number generator handle and establishing the
 * connection to the kernel
 *
 * @handle cipher handle filled during the call - output
 * @ciphername kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * return: 0 upon success
 *	   < 0 in case of error
 *		ENOENT - algorithm not available
 *		ENOTSUP - AF_ALG family not available
 *		EINVAL - accept syscall failed
 */
int kcapi_rng_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "rng", ciphername);
}

/**
 * Close the random number generator handle and release resources
 *
 * @handle cipher handle to release - input
 *
 * return: 0 upon success
 */
int kcapi_rng_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * Random number generation
 *
 * @handle cipher handle - input
 * @buffer filled with the random number - output
 * @len buffer length - input
 *
 * return: size of random number generated upon success
 *	   < 0 in case of error
 *		EIO - data cannot be obtained
 */
ssize_t kcapi_rng_generate(struct kcapi_handle *handle,
			   unsigned char *buffer, size_t len)
{
	ssize_t out = 0;
	struct iovec iov;
	struct msghdr msg;

	while (len) {
		ssize_t r = 0;

		iov.iov_base = (void*)(uintptr_t)buffer;
		iov.iov_len = len;
		msg.msg_name = NULL;
		msg.msg_namelen = 0;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		msg.msg_control = NULL;
		msg.msg_controllen = 0;

		r = recvmsg(handle->opfd, &msg, 0);
		if (0 >= r)
			return -EIO;
		len -= r;
		out += r;

		buffer += r;
	}

	return out;
}
