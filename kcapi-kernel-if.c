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
#define MINVERSION 3 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 0 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/* remove once in if_alg.h */
#define ALG_SET_AEAD_ASSOC		4
#define ALG_SET_AEAD_AUTHSIZE		5

#define ALG_GET_BLOCKSIZE		1
#define ALG_GET_IVSIZE			2
#define ALG_GET_AEAD_AUTHSIZE		3
#define ALG_GET_DIGESTSIZE		4

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

	if (handle->aead.taglen) {
		handle->aead.retlen = ret;
		if (enc) {
			handle->aead.tag = handle->skdata.out +
					   (ret - handle->aead.taglen);
			handle->aead.retlen -= handle->aead.taglen;
		}
	}

bad:
	memset(buffer, 0, bufferlen);
	/* magic to convince GCC to memset the buffer */
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
	int outlen = 0;

	if (getsockopt(handle->opfd, SOL_ALG, optval, NULL, &len) == -1)
		return 0;

	outlen = (int)len;
	if (outlen < 0)
		outlen = 0;
	return outlen;
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
		return -EOPNOTSUPP;

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

/**
 * DOC: Common API
 *
 * The following API calls are common to all cipher types.
 */

/**
 * kcapi_versionstring() - Obtain version string of kcapi library
 * @buf: buffer to place version string into - output
 * @buflen: length of buffer - input
 */
void kcapi_versionstring(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "libkcapi %d.%d.%d", MAJVERSION, MINVERSION,
		 PATCHLEVEL);
}

/**
 * kcapi_pad_iv() - realign the key as necessary for cipher
 * @handle: cipher handle
 * @iv: current IV buffer - input
 * @ivlen: length of IV buffer - input
 * @newiv: buffer of aligned IV - output
 * @newivlen: length of newly aligned IV - output
 *
 * The function allocates memory for @newiv in case the return code indicates
 * success. The consumer must free the memory after use.
 *
 * Return: 0 for success; -ERANGE when the provided IV already satisfies the
 *	   the alignment requirement; < 0 for any other errors
 */
int kcapi_pad_iv(struct kcapi_handle *handle,
		 const unsigned char *iv, size_t ivlen,
		 unsigned char **newiv, size_t *newivlen)
{
	unsigned char *niv = NULL;
	unsigned int nivlen = _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);

	if (nivlen == ivlen)
		return -ERANGE;

	niv = calloc(1, nivlen);
	if (!niv)
		return -ENOMEM;
	memcpy(niv, iv, nivlen);

	*newiv = niv;
	*newivlen = nivlen;

	return 0;
}

/**
 * DOC: Symmetric Cipher API
 *
 * API function calls used to invoke symmetric ciphers.
 */

/**
 * kcapi_cipher_init() - initialize cipher handle
 * @handle: cipher handle filled during the call - output
 * @ciphername: kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * This function provides the initialization of a symmetric cipher handle and
 * establishes the connection to the kernel.
 *
 * Return: 0 upon success; ENOENT - algorithm not available; 
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 */
int kcapi_cipher_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "skcipher", ciphername);
}

/**
 * kcapi_cipher_destroy() - close the cipher handle and release resources
 * @handle: cipher handle to release - input
 *
 * Return: 0 upon success
 */
int kcapi_cipher_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * kcapi_cipher_setkey() - set the key for the cipher handle
 * @handle: cipher handle - input
 * @key: key buffer - input
 * @keylen: length of key buffer - input
 *
 * Return: 0 upon success; < 0 in case of error
 */
int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * kcapi_cipher_setiv() -set IV for the cipher operation
 * @handle: cipher handle - input
 * @iv: buffer holding the IV (may be NULL if IV is not needed) - input
 * @ivlen: length of iv (should be zero if iv is NULL) - input
 *
 * Return: 0 upon success; < 0 in case of an error
 *
 * This function requires IV to be exactly IV size. The function verifies
 * the IV size to avoid unnecessary kernel round trips.
 */
int kcapi_cipher_setiv(struct kcapi_handle *handle,
		       const unsigned char *iv, size_t ivlen)
{
	int cipher_ivlen = _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);

	if (cipher_ivlen < 0)
		return cipher_ivlen;
	if (!iv || ivlen != (size_t)cipher_ivlen)
		return -EINVAL;

	handle->skdata.iv = iv;
	handle->skdata.ivlen = ivlen;

	return 0;
}

/**
 * kcapi_cipher_encrypt() - encrypt data
 * @handle: cipher handle - input
 * @in: plaintext data buffer - input
 * @inlen: length of in buffer - input
 * @out: ciphertext data buffer - output
 * @outlen: length of out buffer - input
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * Return: number of bytes encrypted upon success; < 0 in case of error with
 *	   errno set
 */
ssize_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	return _kcapi_common_encrypt(handle, in, inlen, out, outlen);
}

/**
 * kcapi_cipher_decrypt() - decrypt data
 * @handle: cipher handle - input
 * @in: ciphertext data buffer - input
 * @inlen: length of in buffer - input
 * @out: plaintext data buffer - output
 * @outlen: length of out buffer - input
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * Return: number of bytes decrypted upon success; < 0 in case of error with
 *	   errno set
 */
ssize_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	return _kcapi_common_decrypt(handle, in, inlen, out, outlen);
}

/**
 * kcapi_cipher_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size; 0 on error
 */
int kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);
}

/**
 * kcapi_cipher_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_BLOCKSIZE);
}

/**
 * DOC: AEAD Cipher API
 *
 * The following API calls allow using the Authenticated Encryption with
 * Associated Data.
 *
 * IMORTANT NOTE Please read the description of @kcapi_aead_encrypt and
 * @kcapi_aead_decrypt for the expected memory layout regarding the tag and
 * the plaintext / ciphertext when using aligned data requests. For
 * non-aligned cipher requests, no specific memory layout needs to be
 * observed.
 */

/**
 * kcapi_aead_init() - initialization of cipher handle
 * @handle: cipher handle filled during the call - output
 * @ciphername: kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * This function initializes an AEAD cipher handle and establishes the
 * connection to the kernel.
 *
 * Return: 0 upon success; -ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 */
int kcapi_aead_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "aead", ciphername);
}

/**
 * kcapi_aead_destroy() - close the AEAD handle and release resources
 * @handle: cipher handle to release - input
 *
 * Return: 0 upon success
 */
int kcapi_aead_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * kcapi_aead_setkey() - set the key for the AEAD handle
 * @handle: cipher handle - input
 * @key: key buffer - input
 * @keylen: length of key buffer - input
 *
 * Return: 0 upon success; < 0 in case of error
 */
int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * kcapi_aead_setiv() - set IV for the AEAD operation
 * @handle: cipher handle - input
 * @iv: buffer holding the IV (may be NULL if IV is not needed) - input
 * @ivlen: length of iv (should be zero if iv is NULL) - input
 *
 * Return: 0 upon success; < 0 in case of an error
 *
 * This function requires IV to be exactly IV size. The function verifies
 * the IV size to avoid unnecessary kernel round trips.
 */
int kcapi_aead_setiv(struct kcapi_handle *handle,
		     const unsigned char *iv, size_t ivlen)
{
	int cipher_ivlen = _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);

	if (cipher_ivlen < 0)
		return cipher_ivlen;
	if (!iv || ivlen != (size_t)cipher_ivlen)
		return -EINVAL;

	handle->skdata.iv = iv;
	handle->skdata.ivlen = ivlen;

	return 0;
}

/**
 * kcapi_aead_setassoc() - set associated data for AEAD operation
 * @handle: cipher handle - input
 * @assoc: buffer holding the IV (may be NULL if associated data is not
 *	  needed) - input
 * @assoclen: length of assoc (should be zero if assoc is NULL) - input
 */
void kcapi_aead_setassoc(struct kcapi_handle *handle,
			 const unsigned char *assoc, size_t assoclen)
{
	handle->aead.assoc = assoc;
	handle->aead.assoclen = assoc ? assoclen : 0;
}

/**
 * kcapi_aead_settaglen() - Set tag size / authentication data size
 * @handle: cipher handle - input
 * @taglen: length of tag - input
 *
 * Note, for decryption, the tag must be appended to the ciphertext memory. For
 * encryption, the tag will be appended to the ciphertext.
 */
void kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen)
{
	handle->aead.taglen = taglen;
}

/**
 * kcapi_aead_encrypt() - encrypt aligned data
 * @handle: cipher handle - input
 * @in: plaintext data buffer - input
 * @inlen: length of in buffer - input
 * @out: ciphertext data buffer - output
 * @outlen: length of out buffer - input
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * When using this function, the caller must align the input and output
 * data buffers. The ciphertext buffer must hold the tag as follows:
 * 	ciphertext || tag
 * The caller must ensure that the ciphertext buffer is large enough to hold
 * the ciphertext together with the tag of the size set by the caller using
 * the kcapi_cipher_settaglen() function.
 *
 * Return: number of bytes encrypted upon success; < 0 in case of error with
 *	   errno set
 */
ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen)
{
	return _kcapi_common_encrypt(handle, in, inlen, out, outlen);
}

/**
 * kcapi_aead_enc_nonalign() - encrypt nonaligned data
 * @handle: cipher handle - input
 * @pt: plaintext data buffer - input
 * @ptlen: length of plaintext buffer - input
 * @taglen: length of the authentication tag to be created - input
 *
 * The caller does not need to know anything about the memory structure
 * of the input / output data. The ciphertext buffer is allocated for the
 * caller.
 *
 * After invoking this function the caller should use kcapi_aead_enc_getdata()
 * to obtain the resulting ciphertext and authentication tag references.
 *
 * Caller must invoke kcapi_aead_enc_free() to release the buffer allocated with
 * this function.
 */
ssize_t kcapi_aead_enc_nonalign(struct kcapi_handle *handle,
				unsigned char *pt, size_t ptlen, size_t taglen)
{
	unsigned char *ctbuf = NULL;

	if (!ptlen || !taglen)
		return -EINVAL;

	ctbuf = calloc(1, ptlen + taglen);
	if (!ctbuf)
		return -ENOMEM;

	handle->skdata.in = pt;
	handle->skdata.inlen = ptlen;
	handle->skdata.out = ctbuf;
	handle->skdata.outlen = ptlen + taglen;
	handle->aead.taglen = taglen;

	return _kcapi_common_crypt(handle, ALG_OP_ENCRYPT);
}

/**
 * kcapi_aead_enc_getdata() - Get the resulting data from encryption
 * @handle: cipher handle - input
 * @ct: pointer to ciphertext - output
 * @ctlen: length of ciphertext - output
 * @tag: tag buffer pointer - output
 * @taglen: length of tag - output
 *
 * This function is a service function to the consumer to locate the right
 * ciphertext buffer offset holding the authentication tag. In addition, it
 * provides the consumer with the length of the tag and the length of the
 * ciphertext.
 *
 * This call supplements kcapi_aead_enc_nonalign() where the caller does not
 * need to know about the memory structure of ciphertext and tag.
 */
void kcapi_aead_enc_getdata(struct kcapi_handle *handle,
			    unsigned char **ct, size_t *ctlen,
			    unsigned char **tag, size_t *taglen)
{
	*ct = handle->skdata.out;
	*ctlen = handle->aead.retlen;
	*tag = handle->aead.tag;
	*taglen = handle->aead.taglen;
}

/**
 * kcapi_aead_enc_free() - free buffers allocated with kcapi_aead_enc_nonalign()
 * @handle: cipher handle - input
 */
void kcapi_aead_enc_free(struct kcapi_handle *handle)
{
	unsigned char *buf = handle->skdata.out;
	memset(handle->skdata.out, 0, handle->skdata.outlen);
	/* magic to convince GCC to memset the buffer */
	buf = memchr(buf, 1, handle->skdata.outlen);
	if (buf)
		buf = '\0';
	free(handle->skdata.out);
}

/**
 * kcapi_aead_decrypt() - decrypt data
 * @handle: cipher handle - input
 * @in: ciphertext data buffer - input
 * @inlen: length of in buffer - input
 * @out: plaintext data buffer - output
 * @outlen: length of out buffer - input
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * When using this function, the caller must align the input and output
 * data buffers. The ciphertext buffer must contain the tag as follows:
 * 	ciphertext || tag
 * The plaintext buffer will not hold the tag which means the caller only needs
 * to allocate memory sufficient to hold the plaintext.
 *
 * To catch authentication errors (i.e. integrity violations) during the
 * decryption operation, the errno of this call shall be checked for EBADMSG.
 * If this function returns < 0 and errno is set to EBADMSG, an authentication
 * error is detected.
 *
 * Return: number of bytes decrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   unsigned char *out, size_t outlen)
{
	return _kcapi_common_decrypt(handle, in, inlen, out, outlen);
}

/**
 * kcapi_aead_dec_nonalign() - decrypt nonaligned data
 * @handle: cipher handle - input
 * @ct: ciphertext data buffer - input
 * @ctlen: length of ciphertext buffer - input
 * @tag: authentication tag buffer - input
 * @taglen: length of the authentication tag - input
 *
 * The caller does not need to know anything about the memory structure
 * of the input / output data. The plaintext buffer is allocated for the
 * caller.
 *
 * After invoking this function the caller should use kcapi_aead_dec_getdata()
 * to obtain the resulting plaintext buffer.
 *
 * Caller must invoke kcapi_aead_dec_free() to release the buffer allocated with
 * this function.
 */
ssize_t kcapi_aead_dec_nonalign(struct kcapi_handle *handle,
				unsigned char *ct, size_t ctlen,
				unsigned char *tag, size_t taglen)
{
	unsigned char *input = NULL;

	if (!ctlen || !taglen)
		return -EINVAL;

	/* Format input data by concatenating ciphertext and tag */
	input = calloc(1, ctlen + taglen);
	if (!input)
		return -ENOMEM;
	memcpy(input, ct, ctlen);
	memcpy(input + ctlen, tag, taglen);

	/*
	 * in-place decryption as ciphertext buffer is larger than plaintext
	 * buffer
	 */
	handle->skdata.in = input;
	handle->skdata.inlen = ctlen + taglen;
	handle->skdata.out = input;
	handle->skdata.outlen = ctlen;
	handle->aead.taglen = taglen;
	return _kcapi_common_crypt(handle, ALG_OP_DECRYPT);
}

/**
 * kcapi_aead_dec_getdata() - Get the resulting data from decryption
 * @handle: cipher handle - input
 * @pt: pointer to plaintext - output
 * @ptlen: length of plaintext - output
 *
 * This function is a service function to the consumer to obtain the
 * plaintext buffer and its length.
 *
 * This call supplements kcapi_aead_dec_nonalign() where the caller does not
 * need to know about the memory structure created by this function.
 */
void kcapi_aead_dec_getdata(struct kcapi_handle *handle,
			    unsigned char **pt, size_t *ptlen)
{
	*pt = handle->skdata.out;
	*ptlen = handle->aead.retlen;
}

/**
 * kcapi_aead_dec_free() - free buffers allocated with kcapi_aead_dec_nonalign()
 * @handle: cipher handle - input
 */
void kcapi_aead_dec_free(struct kcapi_handle *handle)
{
	/*
	 * handle->skdata.in is the same memory as handle->skdata.out
	 * but skdata.in is const -- thus we use skdata.out; though,
	 * the buffer is still skdata.inlen in size!
	 */
	unsigned char *buf = handle->skdata.out;
	memset(handle->skdata.out, 0, handle->skdata.inlen);
	/* magic to convince GCC to memset the buffer */
	buf = memchr(buf, 1, handle->skdata.inlen);
	if (buf)
		buf = '\0';
	free(handle->skdata.out);
}

/**
 * kcapi_aead_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size; 0 on error
 */
int kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_IVSIZE);
}

/**
 * kcapi_aead_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_BLOCKSIZE);
}

/**
 * kcapi_aead_authsize() - return the maximum size of the tag
 * @handle: cipher handle - input
 *
 * The returned maximum is the largest size of the authenticaation tag that can
 * be produced by the AEAD cipher. Smaller tag sizes may be chosen depending on
 * the AEAD cipher type.
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_aead_authsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_AEAD_AUTHSIZE);
}

/**
 * kcapi_aead_ccm_nonce_to_iv() - convert CCM nonce into IV
 * @nonce: buffer with nonce - input
 * @noncelen: length of nonce - input
 * @iv: newly allocated buffer with IV - output
 * @ivlen: length of IV - output
 *
 * This service function converts a CCM nonce value into an IV usable by
 * the kernel crypto API.
 *
 * Caller must free iv.
 *
 * Return: 0 upon success; < 0 upon failure
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

/**
 * DOC: Message Digest Cipher API
 */

/**
 * kcapi_md_init() - initialize cipher handle
 * @handle: cipher handle filled during the call - output
 * @ciphername: kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * This function provides the initialization of a (keyed) message digest handle
 * and establishes the connection to the kernel.
 *
 * Return: 0 upon success; ENOENT - algorithm not available;
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 */
int kcapi_md_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "hash", ciphername);
}

/**
 * kcapi_md_destroy() - close the message digest handle and release resources
 * @handle: cipher handle to release - input
 *
 * Return: 0 upon success
 */
int kcapi_md_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * kcapi_md_setkey() - set the key for the message digest handle
 * @handle: cipher handle - input
 * @key: key buffer - input
 * @keylen: length of key buffer - input
 *
 * This call is applicable for keyed message digests.
 *
 *
 * Return: 0 upon success; < 0 in case of error
 */
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

/**
 * kcapi_md_update() - message digest update function
 * @handle: cipher handle - input
 * @buffer: holding the data to add to the message digest - input
 * @len: buffer length - input
 *
 * Return: 0 upon success; < 0 in case of error
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
 * kcapi_md_final() - message digest finalization function
 * @handle: cipher handle - input
 * @buffer: filled with the message digest - output
 * @len: buffer length - input
 *
 * Return: size of message digest upon success; -EIO - data cannot be obtained
 * 	   -ENOMEM - buffer is too small for the complete message digest,
 * 	   the buffer is filled with the truncated message digest
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

/**
 * kcapi_md_digestsize() - return the size of the message digest
 * @handle: cipher handle - input
 *
 * The returned message digest size can be used before the @kcapi_md_final
 * function invocation to determine the right memory size to be allocated for
 * this call.
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_md_digestsize(struct kcapi_handle *handle)
{
	return _kcapi_common_getinfo(handle, ALG_GET_DIGESTSIZE);
}

/**
 * DOC: Random Number API
 */

/**
 * kcapi_rng_init() - initialize cipher handle
 * @handle: cipher handle filled during the call - output
 * @ciphername: kernel crypto API cipher name as specified in
 *	       /proc/crypto - input
 *
 * This function provides the initialization of a random number generator handle
 * and establishes the connection to the kernel.
 *
 * Return: 0 upon success; ENOENT - algorithm not available; 
 *	   -EOPNOTSUPP - AF_ALG family not available;
 *	   -EINVAL - accept syscall failed
 */
int kcapi_rng_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "rng", ciphername);
}

/**
 * kcapi_rng_destroy() - Close the RNG handle and release resources
 * @handle: cipher handle to release - input
 *
 * Return: 0 upon success
 */
int kcapi_rng_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

/**
 * kcapi_rng_generate() - generate a random number
 * @handle: cipher handle - input
 * @buffer: filled with the random number - output
 * @len: buffer length - input
 *
 * Return: size of random number generated upon success; -EIO - data cannot be
 *	   obtained
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
