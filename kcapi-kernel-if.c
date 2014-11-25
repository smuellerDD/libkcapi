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
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include "cryptouser.h"

#include "kcapi.h"

#define MAJVERSION 0 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated */
#define MINVERSION 4 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 0 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/* remove once in if_alg.h */
#define ALG_SET_AEAD_ASSOCLEN		4
#define ALG_SET_AEAD_AUTHSIZE		5

#define ALG_GET_BLOCKSIZE		1
#define ALG_GET_IVSIZE			2
#define ALG_GET_AEAD_AUTHSIZE		3
#define ALG_GET_DIGESTSIZE		4

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
				   const unsigned char *in, size_t inlen,
				   unsigned char *out, size_t outlen,
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
	size_t iv_msg_size = handle->cipher.iv ?
			  CMSG_SPACE(sizeof(*alg_iv) + handle->cipher.ivlen) :
			  0;

	/* AEAD data */
	uint32_t *taglen = NULL;
	uint32_t *assoclen = NULL;
	size_t taglen_msg_size = handle->aead.taglen ?
				 CMSG_SPACE(sizeof(*taglen)) : 0;
	size_t assoc_msg_size = handle->aead.assoclen ?
				CMSG_SPACE(sizeof(*assoclen)) : 0;

	size_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + 	/* Encryption / Decryption */
		iv_msg_size +			/* IV */
		taglen_msg_size +		/* AEAD tag length */
		assoc_msg_size;			/* AEAD associated data size */

	memset(&msg, 0, sizeof(msg));

	buffer = calloc(1, bufferlen);
	if (!buffer)
		return -ENOMEM;

	iov.iov_base = (void*)(uintptr_t)in;
	iov.iov_len = inlen;
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
	if (handle->cipher.iv) {
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = handle->cipher.ivlen;
		memcpy(alg_iv->iv, handle->cipher.iv, handle->cipher.ivlen);
	}

	/* set AEAD information */
	if (handle->aead.taglen) {
		if (enc &&
		    ((inlen + handle->aead.taglen) < outlen)) {
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
		header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
		assoclen = (void*)CMSG_DATA(header);
		*assoclen = handle->aead.assoclen;
	}

	ret = sendmsg(handle->opfd, &msg, 0);
	if (ret != (ssize_t)inlen)
		goto bad;

	/* TODO: EINTR and ERESTARTSYS */
	ret = read(handle->opfd, out, outlen);
	if (0 > ret)
		goto bad;
	if ((enc && ret < (ssize_t)handle->aead.taglen)) {
		ret = -E2BIG;
		goto bad;
	}
	if (handle->aead.taglen) {
		handle->aead.retlen = ret;
		if (enc)
			handle->aead.retlen -= handle->aead.taglen;
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

static inline int _kcapi_common_setkey(struct kcapi_handle *handle,
				       const unsigned char *key, size_t keylen)
{
	if (setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_KEY,
		       key, keylen) == -1)
		return -EINVAL;

	return 0;
}

static inline int _kcapi_common_setiv(struct kcapi_handle *handle,
				      const unsigned char *iv, size_t ivlen)
{
	int cipher_ivlen = handle->info.ivsize;

	if (cipher_ivlen < 0)
		return cipher_ivlen;
	if (!iv || ivlen != (size_t)cipher_ivlen)
		return -EINVAL;

	handle->cipher.iv = iv;
	handle->cipher.ivlen = ivlen;

	return 0;
}

#if 0
static int __kcapi_common_getinfo(struct kcapi_handle *handle,
				  const char *ciphername,
				  int drivername)
{
	int ret = -EFAULT;

	/* NETLINK_CRYPTO specific */
	char buf[4096];
	struct nlmsghdr *res_n = (struct nlmsghdr *)buf;
	struct {
		struct nlmsghdr n;
		struct crypto_user_alg cru;
	} req;
	struct crypto_user_alg *cru_res;
	int res_len = 0;
	struct rtattr *tb[CRYPTOCFGA_MAX+1];
	struct rtattr *rta;

	/* AunsignedF_NETLINK specific */
	struct sockaddr_nl nl;
	int sd = 0;
	socklen_t addr_len;
	struct iovec iov;
	struct msghdr msg;

	memset(&req, 0, sizeof(req));
	memset(&buf, 0, sizeof(buf));
	memset(&msg, 0, sizeof(msg));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(req.cru));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = CRYPTO_MSG_GETALG;

	if (drivername)
		strncpy(req.cru.cru_driver_name, ciphername,
			strlen(ciphername));
	else
		strncpy(req.cru.cru_name, ciphername, strlen(ciphername));


	/* talk to netlink socket */
	sd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
	if (sd < 0) {
		perror("Netlink error: cannot open netlink socket");
		return -EFAULT;
	}
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
		perror("Netlink error: cannot bind netlink socket");
		goto out;
	}
	/* sanity check that netlink socket was successfully opened */
	addr_len = sizeof(nl);
	if (getsockname(sd, (struct sockaddr*)&nl, &addr_len) < 0) {
		perror("Netlink error: cannot getsockname");
		goto out;
	}
	if (addr_len != sizeof(nl)) {
		fprintf(stderr, "Netlink error: wrong address length %d\n",
			addr_len);
		goto out;
	}
	if (nl.nl_family != AF_NETLINK) {
		fprintf(stderr, "Netlink error: wrong address family %d\n",
			nl.nl_family);
		goto out;
	}

	/* sending data */
	iov.iov_base = (void*) &req.n;
	iov.iov_len = req.n.nlmsg_len;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (sendmsg(sd, &msg, 0) < 0) {
		perror("Netlink error: sendmsg failed");
		goto out;
	}
	memset(buf,0,sizeof(buf));
	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		ret = recvmsg(sd, &msg, 0);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			perror("Netlink error: netlink receive error");
			ret = -EFAULT;
			goto out;
		}
		if (ret == 0) {
			fprintf(stderr, "Netlink error: no data\n");
			ret = -EFAULT;
			goto out;
		}
		if ((size_t)ret > sizeof(buf)) {
			perror("Netlink error: received too much data\n");
			ret = -EFAULT;
			goto out;
		}
		break;
	}

	ret = -EFAULT;
	res_len = res_n->nlmsg_len;
	if (res_n->nlmsg_type == NLMSG_ERROR) {
		/*
		 * return -EAGAIN -- this error will occur if we received a
		 * driver name, but used it for a generic name. Allow caller
		 * to invoke function again where driver name is looked up
		 */
		ret = -EAGAIN;
		goto out;
	}

	if (res_n->nlmsg_type == CRYPTO_MSG_GETALG) {
		cru_res = NLMSG_DATA(res_n);
		res_len -= NLMSG_SPACE(sizeof(*cru_res));
	}
	if (res_len < 0) {
		fprintf(stderr, "Netlink error: nlmsg len %d\n", res_len);
		goto out;
	}

	/* parse data */
	rta = CR_RTA(cru_res);
	memset(tb, 0, sizeof(struct rtattr *) * (CRYPTOCFGA_MAX + 1));
	while (RTA_OK(rta, res_len)) {
		if ((rta->rta_type <= CRYPTOCFGA_MAX) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, res_len);
	}
	if (res_len) {
		fprintf(stderr, "Netlink error: unprocessed data %d\n",
			res_len);
		goto out;
	}

	if (tb[CRYPTOCFGA_REPORT_HASH]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_HASH];
		struct crypto_report_hash *rsh =
			(struct crypto_report_hash *) RTA_DATA(rta);
		handle->info.hash_digestsize = rsh->digestsize;
		handle->info.blocksize = rsh->blocksize;
	}
	if (tb[CRYPTOCFGA_REPORT_BLKCIPHER]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_BLKCIPHER];
		struct crypto_report_blkcipher *rblk =
			(struct crypto_report_blkcipher *) RTA_DATA(rta);
		handle->info.blocksize = rblk->blocksize;
		handle->info.ivsize = rblk->ivsize;
		handle->info.blk_min_keysize = rblk->min_keysize;
		handle->info.blk_max_keysize = rblk->max_keysize;
	}
	if (tb[CRYPTOCFGA_REPORT_AEAD]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_AEAD];
		struct crypto_report_aead *raead =
			(struct crypto_report_aead *) RTA_DATA(rta);
		handle->info.blocksize = raead->blocksize;
		handle->info.ivsize = raead->ivsize;
		handle->info.aead_maxauthsize = raead->maxauthsize;
	}
	if (tb[CRYPTOCFGA_REPORT_RNG]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_RNG];
		struct crypto_report_rng *rrng =
			(struct crypto_report_rng *) RTA_DATA(rta);
		handle->info.rng_seedsize = rrng->seedsize;
	}

	ret = 0;

out:
	close(sd);
	return ret;
}
#endif

static int _kcapi_common_getinfo(struct kcapi_handle *handle,
				 const char *ciphername)
{
	(void)ciphername;
	handle->info.blocksize = 16;
	handle->info.ivsize = 16;
#if 0
	int ret = __kcapi_common_getinfo(handle, ciphername, 0);
	if (ret)
		return __kcapi_common_getinfo(handle, ciphername, 1);
#endif
	return 0;
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
		perror("AF_ALG: bind failed");
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -ENOENT;
	}

	handle->opfd = accept(handle->tfmfd, NULL, 0);
	if (handle->opfd == -1) {
		perror("AF_ALG: accept failed");
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -EINVAL;
	}

	return _kcapi_common_getinfo(handle, ciphername);
}

static inline int _kcapi_handle_destroy(struct kcapi_handle *handle)
{
	if (handle->tfmfd != -1)
		close(handle->tfmfd);
	if (handle->opfd != -1)
		close(handle->opfd);
	memset(handle, 0, sizeof(struct kcapi_handle));
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
	unsigned int nivlen = handle->info.ivsize;

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
	return _kcapi_common_setiv(handle, iv, ivlen);
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
	return _kcapi_common_crypt(handle, in, inlen, out, outlen,
				   ALG_OP_ENCRYPT);
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
	return _kcapi_common_crypt(handle, in, inlen, out, outlen,
				   ALG_OP_DECRYPT);
}

/**
 * kcapi_cipher_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size; 0 on error
 */
int kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

/**
 * kcapi_cipher_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}

/**
 * DOC: AEAD Cipher API
 *
 * The following API calls allow using the Authenticated Encryption with
 * Associated Data. The API is segmented into two parts:
 *
 *	* API for aligned data: the data is aligned to the memory constraints
 *	  required by the API. With these API calls there is no memcpy
 *	  performed by the API. Please read the description of
 *	  kcapi_aead_encrypt() and kcapi_aead_decrypt() for the expected memory
 *	  layout regarding the tag and the plaintext / ciphertext when using
 *	  aligned data requests. For non-aligned cipher requests, no specific
 *	  memory layout needs to be observed.
 *
 *	* API for nonaligned data: The API uses memcpy to align the data into
 *	  the right memory format. See all *_nonaligned function calls.
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
	return _kcapi_common_setiv(handle, iv, ivlen);
}

/**
 * kcapi_aead_setassoclen() - set associated data for AEAD operation (aligned)
 * @handle: cipher handle - input
 * @assoclen: length of assoc (should be zero if assoc is NULL) - input
 */
void kcapi_aead_setassoclen(struct kcapi_handle *handle, size_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

/**
 * kcapi_aead_settaglen() - Set tag size / authentication data size (aligned)
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
 * data buffers. The input buffer must hold the following information:
 * 	associated authentication data || plaintext
 * The caller must use kcapi_aead_setassoclen() to specify the size of the
 * associated data buffer.
 *
 * The output ciphertext buffer must hold the tag as follows:
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
	return _kcapi_common_crypt(handle, in, inlen, out, outlen,
				   ALG_OP_ENCRYPT);
}

/**
 * kcapi_aead_decrypt() - decrypt aligned data
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
 * 	associated data || ciphertext || tag
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
	return _kcapi_common_crypt(handle, in, inlen, out, outlen,
				   ALG_OP_DECRYPT);
}

/**
 * kcapi_aead_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size; 0 on error
 */
int kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

/**
 * kcapi_aead_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size; 0 on error
 */
int kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
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
	return handle->info.aead_maxauthsize;
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
 * kcapi_aead_alloc_nonalign() - allocate memory for nonaligned requests
 * @handle: cipher handle - input
 * @datalen: length of plaintext or ciphertext; the length is rounded up to
 *	     a block length chunks to ensure sufficient memory for ciphertext
 *	     - input
 * @assoclen: length of associated authentication data - input
 * @taglen: length of authentication tag - input
 *
 * Return: 0 upon succes; < 0 in case of error
 */
int kcapi_aead_alloc_nonalign(struct kcapi_handle *handle, size_t datalen,
			      size_t assoclen, size_t taglen)
{
	size_t allocdatalen = datalen;
	if (allocdatalen % handle->info.blocksize)
		allocdatalen = (allocdatalen + handle->info.blocksize) /
				handle->info.blocksize * handle->info.blocksize;

	handle->aead.assoc = calloc(1, allocdatalen + assoclen + taglen);
	if (!handle->aead.assoc) {
		perror ("Fail to allocate input memory");
		return -ENOMEM;
	}

	handle->aead.assoclen = assoclen;
	handle->aead.data = handle->aead.assoc + assoclen;
	handle->aead.datalen = datalen;
	handle->aead.tag = handle->aead.data + datalen;
	handle->aead.taglen = taglen;

	return 0;
}

/**
 * kcapi_aead_setassoc_nonalign - set associated data
 * @handle: cipher handle - input
 * @assoc: data buffer for associated data whose length was defined with
 *	   kcapi_aead_alloc_nonalign() - input
 *
 * Return: 0 upon succes; < 0 in case of error
 */
int kcapi_aead_setassoc_nonalign(struct kcapi_handle *handle,
				 unsigned char *assoc)
{
	if (!assoc)
		return -EINVAL;
	memcpy(handle->aead.assoc, assoc, handle->aead.assoclen);
	return 0;
}

/**
 * kcapi_aead_settag_nonalign - set authentidation tag (for decryption)
 * @handle: cipher handle - input
 * @tag: data buffer for authentication tag data whose length was defined with
 *	 kcapi_aead_alloc_nonalign() - input
 *
 * Return: 0 upon succes; < 0 in case of error
 */
int kcapi_aead_settag_nonalign(struct kcapi_handle *handle,
				 unsigned char *tag)
{
	if (!tag)
		return -EINVAL;
	memcpy(handle->aead.tag, tag, handle->aead.taglen);
	return 0;
}

/**
 * kcapi_aead_setdata_nonalign - set associated data
 * @handle: cipher handle - input
 * @data: data buffer for plaintext (when performing encryption) or ciphertext
 *	  whose length was defined with kcapi_aead_alloc_nonalign() - input
 *
 * Return: 0 upon succes; < 0 in case of error
 */
int kcapi_aead_setdata_nonalign(struct kcapi_handle *handle,
				unsigned char *data)
{
	if (!data)
		return -EINVAL;
	memcpy(handle->aead.data, data, handle->aead.datalen);
	return 0;
}

/**
 * kcapi_aead_enc_nonalign() - encrypt nonaligned data
 * @handle: cipher handle - input
 *
 * The caller does not need to know anything about the memory structure
 * of the input / output data.
 *
 * After invoking this function the caller should use
 * kcapi_aead_getdata_nonalign() to obtain the resulting ciphertext and
 * authentication tag references.
 *
 * Caller must invoke kcapi_aead_free_nonalign() to release the buffer allocated
 * with this function.
 *
 * Return: number of bytes encrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_enc_nonalign(struct kcapi_handle *handle)
{
	return _kcapi_common_crypt(handle,
				   handle->aead.assoc,
				   handle->aead.assoclen + handle->aead.datalen,
				   handle->aead.data,
				   handle->aead.datalen + handle->aead.taglen,
				   ALG_OP_ENCRYPT);
}

/**
 * kcapi_aead_dec_nonalign() - decrypt nonaligned data
 * @handle: cipher handle - input
 *
 * The caller does not need to know anything about the memory structure
 * of the input / output data.
 *
 * After invoking this function the caller should use
 * kcapi_aead_getdata_nonalign() to obtain the resulting plaintext buffer.
 *
 * Caller must invoke kcapi_aead_free_nonalign() to release the buffer allocated
 * with this function.
 *
 * Return: number of bytes decrypted upon success
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_dec_nonalign(struct kcapi_handle *handle)
{
	return _kcapi_common_crypt(handle,
				   handle->aead.assoc,
				   handle->aead.assoclen +
				   handle->aead.datalen + handle->aead.taglen,
				   handle->aead.data,
				   handle->aead.datalen,
				   ALG_OP_DECRYPT);
}

/**
 * kcapi_aead_enc_getdata() - Get the resulting data from encryption
 * @handle: cipher handle - input
 * @data: pointer to ciphertext (for preceding encryption call) or pointer to
 *	  plaintext (for preceding decryption call); when set to NULL, no data
 *	  pointer is returned - output
 * @datalen: length of data buffer; when @data was set to NULL, no information
 * 	     is returned - output
 * @tag: tag buffer pointer (when invked after ciphertext, tag used for
 * 	 decryption is returned);  when set to NULL, no data pointer is returned
 *	 - output
 * @taglen: length of tag; when @tag was set to NULL, no information is returned
 *	    - output
 *
 * This function is a service function to the consumer to locate the right
 * ciphertext buffer offset holding the authentication tag. In addition, it
 * provides the consumer with the length of the tag and the length of the
 * ciphertext.
 *
 * This call supplements kcapi_aead_enc_nonalign() and
 * kcapi_aead_dec_nonalign().
 */
void kcapi_aead_getdata_nonalign(struct kcapi_handle *handle,
				 unsigned char **data, size_t *datalen,
				 unsigned char **tag, size_t *taglen)
{
	if (data) {
		*data = handle->aead.data;
		*datalen = handle->aead.retlen;
	}
	if (tag) {
		*tag = handle->aead.tag;
		*taglen = handle->aead.taglen;
	}
}

/**
 * kcapi_aead_free_nonalign() - free buffers allocated with
 *				kcapi_aead_alloc_nonalign()
 * @handle: cipher handle - input
 */
void kcapi_aead_free_nonalign(struct kcapi_handle *handle)
{
	unsigned char *buf = handle->aead.assoc;

	size_t len = handle->aead.assoclen + handle->aead.datalen +
		     handle->aead.taglen;

	memset(handle->aead.assoc, 0, len);
	/* magic to convince GCC to memset the buffer */
	buf = memchr(buf, 1, len);
	if (buf)
		buf = '\0';
	free(handle->aead.assoc);
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
	return handle->info.hash_digestsize;
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
