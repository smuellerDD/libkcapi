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

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/uio.h>
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
#include <unistd.h>
#include <sys/user.h>
#include "cryptouser.h"

#include "kcapi.h"

#define MAJVERSION 0 /* API / ABI incompatible changes, functional changes that
		      * require consumer to be updated (as long as this number
		      * is zero, the API is not considered stable and can
		      * change without a bump of the major version) */
#define MINVERSION 6 /* API compatible, ABI may change, functional
		      * enhancements only, consumer can be left unchanged if
		      * enhancements are not considered */
#define PATCHLEVEL 2 /* API / ABI compatible, no functional changes, no
		      * enhancements, bug fixes only */

/* remove once in if_alg.h */
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN		4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE		5
#endif

/* remove once in socket.h */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define MAXPIPELEN (16 * PAGE_SIZE)

/************************************************************
 * Internal logic
 ************************************************************/

static ssize_t _kcapi_common_send_meta(struct kcapi_handle *handle,
				       struct iovec *iov, size_t iovlen,
				       uint32_t enc, unsigned int flags)
{
	ssize_t ret = -EINVAL;
	char *buffer = NULL;
	volatile void *_buffer = NULL;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	size_t iv_msg_size = handle->cipher.iv ?
			  CMSG_SPACE(sizeof(*alg_iv) + handle->cipher.ivlen) :
			  0;

	/* AEAD data */
	uint32_t *assoclen = NULL;
	size_t assoc_msg_size = handle->aead.assoclen ?
				CMSG_SPACE(sizeof(*assoclen)) : 0;

	size_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + 	/* Encryption / Decryption */
		iv_msg_size +			/* IV */
		assoc_msg_size;			/* AEAD associated data size */

	memset(&msg, 0, sizeof(msg));

	buffer = calloc(1, bufferlen);
	if (!buffer)
		return -ENOMEM;

	msg.msg_control = buffer;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

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
	if (handle->aead.assoclen) {
		/* Set associated data length */
		header = CMSG_NXTHDR(&msg, header);
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
		assoclen = (void*)CMSG_DATA(header);
		*assoclen = handle->aead.assoclen;
	}

	ret = sendmsg(handle->opfd, &msg, flags);

	memset(buffer, 0, bufferlen);
	/* magic to convince GCC to memset the buffer */
	_buffer = memchr(buffer, 1, bufferlen);
	if (_buffer)
		_buffer = '\0';
	free(buffer);
	return ret;
}

static inline ssize_t _kcapi_common_send_data(struct kcapi_handle *handle,
				       struct iovec *iov, size_t iovlen,
				       unsigned int flags)
{
	struct msghdr msg;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	return sendmsg(handle->opfd, &msg, flags);
}

static inline ssize_t _kcapi_common_vmsplice_data(struct kcapi_handle *handle,
						  struct iovec *iov,
						  size_t iovlen,
						  size_t inlen,
						  unsigned int flags)
{
	ssize_t ret = 0;

	ret = vmsplice(handle->pipes[1], iov, iovlen, SPLICE_F_GIFT|flags);
	if (0 > ret)
		return ret;
	return splice(handle->pipes[0], NULL, handle->opfd, NULL, inlen, flags);
}

static inline ssize_t _kcapi_common_recv_data(struct kcapi_handle *handle,
					      struct iovec *iov, size_t iovlen)
{
	struct msghdr msg;
	ssize_t ret = 0;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = recvmsg(handle->opfd, &msg, 0);
	if (msg.msg_flags & MSG_TRUNC)
		return -ENOMEM;
	return ret;
}

static inline ssize_t _kcapi_common_read_data(struct kcapi_handle *handle,
					      unsigned char *out, size_t outlen)
{
	return read(handle->opfd, out, outlen);
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

	/* AF_NETLINK specific */
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

static int _kcapi_common_getinfo(struct kcapi_handle *handle,
				 const char *ciphername)
{
	int ret = __kcapi_common_getinfo(handle, ciphername, 0);
	if (ret)
		return __kcapi_common_getinfo(handle, ciphername, 1);
	return 0;
}

static int _kcapi_handle_init(struct kcapi_handle *handle,
			      const char *type, const char *ciphername)
{
	struct sockaddr_alg sa;
	int ret;

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

	ret = pipe(handle->pipes);
	if (ret) {
		close(handle->tfmfd);
		close(handle->opfd);
		return ret;
	}

	ret = _kcapi_common_getinfo(handle, ciphername);
	if(ret) {
		fprintf(stderr, "NETLINK_CRYPTO: cannot obtain cipher information for %s (is required crypto_user.c patch missing? see documentation)\n",
		       ciphername);
		close(handle->tfmfd);
		close(handle->opfd);
		close(handle->pipes[0]);
		close(handle->pipes[1]);
	}
	return ret;
}

static inline int _kcapi_handle_destroy(struct kcapi_handle *handle)
{
	if (handle->tfmfd != -1)
		close(handle->tfmfd);
	if (handle->opfd != -1)
		close(handle->opfd);
	if (handle->pipes[0] != -1)
		close(handle->pipes[0]);
	if (handle->pipes[1] != -1)
		close(handle->pipes[1]);
	memset(handle, 0, sizeof(struct kcapi_handle));
	return 0;
}

static inline size_t _kcapi_aead_encrypt_outlen(struct kcapi_handle *handle,
						size_t inlen, size_t taglen)
{
	int bs = handle->info.blocksize;

	return ((inlen + bs - 1) / bs * bs + taglen);
}

static inline size_t _kcapi_aead_decrypt_outlen(struct kcapi_handle *handle,
						size_t inlen)
{
	int bs = handle->info.blocksize;

	return ((inlen + bs - 1) / bs * bs);
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
 * kcapi_version() - Return machine-usable version number of kcapi library
 *
 * The function returns a version number that is monotonic increasing
 * for newer versions. The version numbers are multiples of 100. For example,
 * version 1.2.3 is converted to 1020300 -- the last two digits are reserved
 * for future use.
 *
 * The result of this function can be used in comparing the version number
 * in a calling program if version-specific calls need to be make.
 *
 * Return: Version number of kcapi library
 */
unsigned int kcapi_version(void)
{
	unsigned int version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
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
 * Return: 0 for success;
 *	   -ERANGE when the provided IV already satisfies the
 *	   the alignment requirement;
 *	   < 0 for any other errors
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
 * Return: 0 upon success;
 *	   < 0 in case of error
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
 * This function requires IV to be exactly IV size. The function verifies
 * the IV size to avoid unnecessary kernel round trips.
 *
 * Return: 0 upon success;
 *	   < 0 in case of an error
 *
 */
int kcapi_cipher_setiv(struct kcapi_handle *handle,
		       const unsigned char *iv, size_t ivlen)
{
	return _kcapi_common_setiv(handle, iv, ivlen);
}

/**
 * kcapi_cipher_encrypt() - encrypt data (one shot)
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
 * Return: number of bytes encrypted upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	struct iovec iov;
	ssize_t ret = 0;
	size_t processed = 0;
	unsigned int bs = handle->info.blocksize;

	if (!in || !inlen || !out || !outlen) {
		fprintf(stderr,
			"Symmetric Encryption: Empty plaintext or ciphertext buffer provided\n");
		return -EINVAL;
	}

	/* require properly sized output data size */
	if (outlen < ((inlen + bs - 1) / bs * bs)) {
		fprintf(stderr,
			"Symmetric Encryption: Ciphertext buffer (%lu) is not plaintext buffer (%lu) rounded up to multiple of block size %u\n",
			(unsigned long) outlen, (unsigned long)inlen, bs);
		return -EINVAL;
	}

	iov.iov_base = (void*)(uintptr_t)in;
#if 0
	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	/* TODO make heuristic when one syscall is slower than four syscalls */
	if (inlen < (1<<15)) {
		iov.iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov, 1, ALG_OP_ENCRYPT,
					      0);
		iov.iov_base = (void*)(uintptr_t)out;
		iov.iov_len = outlen;
		return _kcapi_common_recv_data(handle, &iov, 1);
}
#endif

	ret = _kcapi_common_send_meta(handle, NULL, 0, ALG_OP_ENCRYPT, 0);
	if (0 > ret)
		return ret;

	while (inlen) {
		size_t datalen = (inlen > MAXPIPELEN) ? MAXPIPELEN : inlen;

		iov.iov_len = datalen;
		ret = _kcapi_common_vmsplice_data(handle, &iov, 1, datalen,
						  SPLICE_F_MORE);
		if (0 > ret)
			return ret;
		processed += ret;
		iov.iov_base = (void*)(uintptr_t)(in + processed);
		inlen -= ret;
	}

	return _kcapi_common_read_data(handle, out, outlen);
}

/**
 * kcapi_cipher_decrypt() - decrypt data (one shot)
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
 * Return: number of bytes decrypted upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     unsigned char *out, size_t outlen)
{
	struct iovec iov;
	ssize_t ret = 0;
	size_t processed = 0;

	if (!in || !inlen || !out || !outlen) {
		fprintf(stderr,
			"Symmetric Decryption: Empty plaintext or ciphertext buffer provided\n");
		return -EINVAL;
	}

	/* require properly sized output data size */
	if (inlen % handle->info.blocksize) {
		fprintf(stderr,
			"Symmetric Decryption: Ciphertext buffer is not multiple of block size %u\n",
			handle->info.blocksize);
		return -EINVAL;
	}

	if (outlen < inlen) {
		fprintf(stderr,
			"Symmetric Decryption: Plaintext buffer (%lu) is smaller as ciphertext buffer (%lu)\n",
			(unsigned long)outlen, (unsigned long)inlen);
		return -EINVAL;
	}

	iov.iov_base = (void*)(uintptr_t)in;
#if 0
	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	/* TODO make heuristic when one syscall is slower than four syscalls */
	if (inlen < (1<<15)) {
		iov.iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov, 1, ALG_OP_DECRYPT,
					      0);
		iov.iov_base = (void*)(uintptr_t)out;
		iov.iov_len = outlen;
		return _kcapi_common_recv_data(handle, &iov, 1);
	}
#endif

	ret = _kcapi_common_send_meta(handle, NULL, 0, ALG_OP_DECRYPT, 0);
	if (0 > ret)
		return ret;

	while (inlen) {
		size_t datalen = (inlen > MAXPIPELEN) ? MAXPIPELEN : inlen;

		iov.iov_len = datalen;
		ret = _kcapi_common_vmsplice_data(handle, &iov, 1, datalen,
						  SPLICE_F_MORE);
		if (0 > ret)
			return ret;
		processed += ret;
		iov.iov_base = (void*)(uintptr_t)(in + processed);
		inlen -= ret;
	}

	return _kcapi_common_read_data(handle, out, outlen);
}

/**
 * kcapi_cipher_stream_init_enc() - start an encryption operation (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be encrypted. This is the pointer to
 *	 the first @iov entry if an array of @iov entries is supplied. See
 *	 sendmsg(2) for details on how @iov is to be used. This pointer may be
 *	 NULL if no data to be encrypted is available at the point of the call.
 *	  - input
 * @iovlen: number of scatter/gather list elements. If @iov is NULL, this value
 *	    must be zero. - input
 *
 * A stream encryption operation is started with this call. Multiple
 * successive kcapi_cipher_stream_update() function calls can be invoked to
 * send more plaintext data to be encrypted. The kernel buffers the input
 * until kcapi_cipher_stream_op() picks up the encrypted data. Once plaintext
 * is encrypted during the kcapi_cipher_stream_op() it is removed from the
 * kernel buffer.
 *
 * The function calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_stream_init_enc(struct kcapi_handle *handle,
				     struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

/**
 * kcapi_cipher_stream_init_dec() - start a decryption operation (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be decrypted. This is the pointer to
 *	 the first @iov entry if an array of @iov entries is supplied. See
 *	 sendmsg(2) for details on how @iov is to be used. This pointer may be
 *	 NULL if no data to be decrypted is available at the point of the call.
 *	 - input
 * @iovlen: number of scatter/gather list elements. If @iov is NULL, this value
 *	    must be zero. - input
 *
 * A stream decryption operation is started with this call. Multiple
 * successive kcapi_cipher_stream_update() function calls can be invoked to
 * send more ciphertext data to be decrypted. The kernel buffers the input
 * until kcapi_cipher_stream_op() picks up the decrypted data. Once ciphertext
 * is decrypted during the kcapi_cipher_stream_op() it is removed from the
 * kernel buffer.
 *
 * The function calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() can be mixed, even by multiple threads of an
 * application.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_stream_init_dec(struct kcapi_handle *handle,
				     struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

/**
 * kcapi_cipher_stream_update() - send more data for processing (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be processed by the cipher operation.
 *	 - input
 * @iovlen: number of scatter/gather list elements. - input
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is getting full. The process will be woken up once more buffer
 * space becomes available by calling kcapi_cipher_stream_op().
 *
 * Note: with the separate API calls of kcapi_cipher_stream_update() and
 * kcapi_cipher_stream_op() a multi-threaded application can be implemented
 * where one thread sends data to be processed and one thread picks up data
 * processed by the cipher operation.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_stream_update(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

/**
 * kcapi_cipher_stream_op() - obtain processed data (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list pointing to buffers to be filled with the resulting
 *	 data from a cipher operation. - output
 * @iovlen: number of scatter/gather list elements. - input
 *
 * This call can be called interleaved with kcapi_cipher_stream_update() to
 * fetch the processed data.
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is empty. The process will be woken up once more data is sent
 * by calling kcapi_cipher_stream_update().
 *
 * Note, when supplying buffers that are not multiple of block size, the buffers
 * will only be filled up to the maximum number of full block sizes that fit
 * into the buffer.
 *
 * Return: number of bytes obtained from the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_cipher_stream_op(struct kcapi_handle *handle,
			       struct iovec *iov, size_t iovlen)
{
	if (!iov || !iovlen) {
		fprintf(stderr,
			"Symmetric operation: No buffer for output data provided\n");
		return -EINVAL;
	}
	return _kcapi_common_recv_data(handle, iov, iovlen);
}

/**
 * kcapi_cipher_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size;
 *	   0 on error
 */
unsigned int kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

/**
 * kcapi_cipher_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size;
 *	   0 on error
 */
unsigned int kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}

/**
 * DOC: AEAD Cipher API
 *
 * The following API calls allow using the Authenticated Encryption with
 * Associated Data.
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
 * Return: 0 upon success;
 *	   -ENOENT - algorithm not available;
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
 * Return: 0 upon success;
 *	   < 0 in case of error
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
 * kcapi_aead_settaglen() - Set authentication tag size
 * @handle: cipher handle - input
 * @taglen: length of authentication tag - input
 *
 * Set the authentication tag size needed for encryption operation. The tag is
 * created during encryption operation with the size provided with this call.
 *
 * Return: 0 upon success;
 *	   < 0 in case of error with errno set
 */
int kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen)
{
	handle->aead.tag = NULL;
	handle->aead.taglen = taglen;
	if (setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       NULL, taglen) == -1)
		return -EINVAL;

	return 0;
}

/**
 * kcapi_aead_setassoclen() - Set authentication data size
 * @handle: cipher handle - input
 * @assoclen: length of associated data length
 */
void kcapi_aead_setassoclen(struct kcapi_handle *handle, size_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

/**
 * kcapi_aead_encrypt() - encrypt AEAD data (one shot)
 * @handle: cipher handle - input
 * @in: plaintext data buffer - input
 * @inlen: length of plaintext buffer - input
 * @assoc: associated data of size set with kcapi_aead_setassoclen() - input
 * @out: data buffer holding cipher text and authentication tag - output
 * @outlen: length of out buffer - input
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the plaintext is overwritten with the ciphertext.
 *
 * After invoking this function the caller should use
 * kcapi_aead_getdata() to obtain the resulting ciphertext and authentication
 * tag references.
 *
 * Return: number of bytes encrypted upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *assoc, unsigned char *out,
			   size_t outlen)
{
	struct iovec iov[2];
	ssize_t ret = 0;
	size_t len = 0;

	if (!in || !inlen || !out || !outlen || !handle->aead.taglen) {
		fprintf(stderr,
			"AEAD Encryption: Empty plaintext buffer, ciphertext buffer or zero tag length provided\n");
		return -EINVAL;
	}

	/* require properly sized output data size */
	if (outlen < _kcapi_aead_encrypt_outlen(handle, inlen,
						handle->aead.taglen) ) {
		fprintf(stderr,
			"AEAD Encryption: Ciphertext buffer (%lu) is not plaintext buffer (%lu) rounded up to multiple of block size %d plus tag length %lu\n",
			(unsigned long)outlen, (unsigned long)inlen,
			handle->info.blocksize,
			(unsigned long)handle->aead.taglen);
		return -EINVAL;
	}

#if 0
	/* using two syscall */
	/* TODO make heuristic when one syscall is slower than four syscalls */
	if (assoc && handle->aead.assoclen) {
		iov[0].iov_base = (void*)(uintptr_t)assoc;
		iov[0].iov_len = handle->aead.assoclen;
		iov[1].iov_base = (void*)(uintptr_t)in;
		iov[1].iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov[0], 2,
					      ALG_OP_ENCRYPT, 0);
	} else {
		iov[0].iov_base = (void*)(uintptr_t)in;
		iov[0].iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov[0], 1,
					      ALG_OP_ENCRYPT, 0);
	}
	if (0 > ret)
		return ret;

	iov[0].iov_base = (void*)(uintptr_t)out;
	iov[0].iov_len = outlen;
	ret = _kcapi_common_recv_data(handle, &iov[0], 1);
#endif
	if (handle->aead.assoclen + inlen > MAXPIPELEN) {
		fprintf(stderr, "AEAD Decryption: input data exceeds maximum allowed size of %lu\n",
			MAXPIPELEN);
		return -E2BIG;
	}
	ret = _kcapi_common_send_meta(handle, NULL, 0, ALG_OP_ENCRYPT,
				      MSG_MORE);
	if (0 > ret)
		return ret;
	if (assoc && handle->aead.assoclen) {
		iov[0].iov_base = (void*)(uintptr_t)assoc;
		iov[0].iov_len = handle->aead.assoclen;
		len = handle->aead.assoclen;
		iov[1].iov_base = (void*)(uintptr_t)in;
		iov[1].iov_len = inlen;
		len += inlen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 2, len, 0);
	} else {
		iov[0].iov_base = (void*)(uintptr_t)in;
		iov[0].iov_len = inlen;
		len = inlen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 1, len, 0);
	}
	if (0 > ret)
		return ret;

	ret = _kcapi_common_read_data(handle, out, outlen);
	if ((ret < (ssize_t)handle->aead.taglen))
		return -E2BIG;

	return ret;
}

/**
 * kcapi_aead_getdata() - Get the resulting data from encryption
 * @handle: cipher handle - input
 * @encdata: data buffer returned by the encryption operation - input
 * @encdatalen: size of the encryption data buffer - input
 * @data: pointer to output buffer from AEAD encryption operation when set to
 *	  NULL, no data pointer is returned - output
 * @datalen: length of data buffer; when @data was set to NULL, no information
 * 	     is returned - output
 * @tag: tag buffer pointer;  when set to NULL, no data pointer is returned
 *	 - output
 * @taglen: length of tag; when @tag was set to NULL, no information is returned
 *	    - output
 *
 * This function is a service function to the consumer to locate the right
 * ciphertext buffer offset holding the authentication tag. In addition, it
 * provides the consumer with the length of the tag and the length of the
 * ciphertext.
 */
void kcapi_aead_getdata(struct kcapi_handle *handle,
			unsigned char *encdata, size_t encdatalen,
			unsigned char **data, size_t *datalen,
			unsigned char **tag, size_t *taglen)
{
	if (encdatalen <  handle->aead.taglen) {
		fprintf(stderr, "Result of encryption operation (%lu) is smaller than tag length (%lu)\n",
			(unsigned long)encdatalen,
			(unsigned long)handle->aead.taglen);
		return;
	}
	if (data) {
		*data = encdata;
		*datalen = encdatalen - handle->aead.taglen;
	}
	if (tag) {
		*tag = encdata + encdatalen - handle->aead.taglen;
		*taglen = handle->aead.taglen;
	}
}

/**
 * kcapi_aead_decrypt() - decrypt AEAD data (one shot)
 * @handle: cipher handle - input
 * @in: ciphertext data buffer - input
 * @inlen: length of in buffer - input
 * @assoc: associated data of size set with kcapi_aead_setassoclen() - input
 * @tag: authentication tag data of size set with kcapi_aead_settaglen() - input
 * @out: plaintext data buffer - output
 * @outlen: length of out buffer - input
 *
 * The AEAD cipher operation requires the furnishing of the associated
 * authentication data. In case such data is not required, it can be set to
 * NULL and length value must be set to zero.
 *
 * It is perfectly legal to use the same buffer as the plaintext and
 * ciphertext pointers. That would mean that after the encryption operation,
 * the ciphertext is overwritten with the plaintext.
 *
 * To catch authentication errors (i.e. integrity violations) during the
 * decryption operation, the errno of this call shall be checked for EBADMSG.
 * If this function returns < 0 and errno is set to EBADMSG, an authentication
 * error is detected.
 *
 * Return: number of bytes decrypted upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *assoc, const unsigned char *tag,
			   unsigned char *out, size_t outlen)
{
	struct iovec iov[3];
	ssize_t ret = 0;
	size_t len = 0;
	unsigned int bs = handle->info.blocksize;

	if (!in || !inlen || !out || !outlen || !tag || !handle->aead.taglen) {
		fprintf(stderr,
			"AEAD Decryption: Empty plaintext buffer, ciphertext buffer, or tag buffer provided\n");
		return -EINVAL;
	}

	/* require properly sized output data size */
	if (outlen < _kcapi_aead_decrypt_outlen(handle, inlen)) {
		fprintf(stderr,
			"AEAD Decryption: Plaintext buffer (%lu) is not ciphertext buffer (%lu) reduced by tag length (%lu) routed up to multiple of block size %u\n",
			(unsigned long)outlen, (unsigned long) inlen,
			(unsigned long)handle->aead.taglen, bs);
		return -EINVAL;
	}

#if 0
	/* using two syscall */
	/* TODO make heuristic when one syscall is slower than four syscalls */
	if (assoc && handle->aead.assoclen) {
		iov[0].iov_base = (void*)(uintptr_t)assoc;
		iov[0].iov_len = handle->aead.assoclen;
		iov[1].iov_base = (void*)(uintptr_t)in;
		iov[1].iov_len = inlen;
		iov[2].iov_base = (void*)(uintptr_t)tag;
		iov[2].iov_len = handle->aead.taglen;
		ret = _kcapi_common_send_meta(handle, &iov[0], 3,
					      ALG_OP_DECRYPT, 0);
	} else {
		iov[0].iov_base = (void*)(uintptr_t)in;
		iov[0].iov_len = inlen;
		iov[1].iov_base = (void*)(uintptr_t)tag;
		iov[1].iov_len = handle->aead.taglen;
		ret = _kcapi_common_send_meta(handle, &iov[0], 2,
					      ALG_OP_DECRYPT, 0);
	}
	if (0 > ret)
		return ret;

	iov[0].iov_base = (void*)(uintptr_t)out;
	iov[0].iov_len = outlen;
	ret = _kcapi_common_recv_data(handle, &iov[0], 1);
#endif
	if (handle->aead.assoclen + inlen + handle->aead.taglen > MAXPIPELEN) {
		fprintf(stderr, "AEAD Decryption: input data exceeds maximum allowed size of %lu\n",
			MAXPIPELEN);
		return -E2BIG;
	}
	ret = _kcapi_common_send_meta(handle, NULL, 0, ALG_OP_DECRYPT,
				      MSG_MORE);
	if (0 > ret)
		return ret;
	if (assoc && handle->aead.assoclen) {
		iov[0].iov_base = (void*)(uintptr_t)assoc;
		iov[0].iov_len = handle->aead.assoclen;
		len = handle->aead.assoclen;
		iov[1].iov_base = (void*)(uintptr_t)in;
		iov[1].iov_len = inlen;
		len += inlen;
		iov[2].iov_base = (void*)(uintptr_t)tag;
		iov[2].iov_len = handle->aead.taglen;
		len += handle->aead.taglen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 3, len, 0);
	} else {
		iov[0].iov_base = (void*)(uintptr_t)in;
		iov[0].iov_len = inlen;
		len = inlen;
		iov[1].iov_base = (void*)(uintptr_t)tag;
		iov[1].iov_len = handle->aead.taglen;
		len += handle->aead.taglen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 2, len, 0);
	}
	if (0 > ret)
		return ret;

	return _kcapi_common_read_data(handle, out, outlen);
}

/**
 * kcapi_aead_stream_init_enc() - start an encryption operation (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be encrypted. This is the pointer to
 *	 the first @iov entry if an array of @iov entries is supplied. See
 *	 sendmsg(2) for details on how @iov is to be used. This pointer may be
 *	 NULL if no data to be encrypted is available at the point of the call.
 *	  - input
 * @iovlen: number of scatter/gather list elements. If @iov is NULL, this value
 *	    must be zero. - input
 *
 * A stream encryption operation is started with this call. Multiple
 * successive kcapi_aead_stream_update() function calls can be invoked to
 * send more plaintext data to be encrypted. The kernel buffers the input
 * until kcapi_aead_stream_op() picks up the encrypted data. Once plaintext
 * is encrypted during the kcapi_aead_stream_op() it is removed from the
 * kernel buffer.
 *
 * Note, unlike the corresponding symmetric cipher API, the function calls of
 * kcapi_aead_stream_update() and kcapi_aead_stream_op() cannot be mixed! This
 * due to the nature of AEAD where the cipher operation ensures the integrity
 * of the entire data (decryption) or calculates a message digest over the
 * entire data (encryption).
 *
 * When using the stream API, the caller must ensure that data is sent
 * in the correct order (regardless whether data is sent in multiple chunks
 * using kcapi_aead_stream_init_enc() or kcapi_cipher_stream_update()): (i)
 * the complete associated data must be provided, followed by (ii) the
 * plaintext.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_stream_init_enc(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

/**
 * kcapi_aead_stream_init_dec() - start a decryption operation (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be encrypted. This is the pointer to
 *	 the first @iov entry if an array of @iov entries is supplied. See
 *	 sendmsg(2) for details on how @iov is to be used. This pointer may be
 *	 NULL if no data to be encrypted is available at the point of the call.
 *	  - input
 * @iovlen: number of scatter/gather list elements. If @iov is NULL, this value
 *	    must be zero. - input
 *
 * A stream decryption operation is started with this call. Multiple
 * successive kcapi_aead_stream_update() function calls can be invoked to
 * send more ciphertext data to be encrypted. The kernel buffers the input
 * until kcapi_aead_stream_op() picks up the decrypted data. Once ciphertext
 * is decrypted during the kcapi_aead_stream_op() it is removed from the
 * kernel buffer.
 *
 * Note, unlike the corresponding symmetric cipher API, the function calls of
 * kcapi_aead_stream_update() and kcapi_aead_stream_op() cannot be mixed! This
 * due to the nature of AEAD where the cipher operation ensures the integrity
 * of the entire data (decryption) or calculates a message digest over the
 * entire data (encryption).
 *
 * When using the stream API, the caller must ensure that data is sent
 * in the correct order (regardless whether data is sent in multiple chunks
 * using kcapi_aead_stream_init_enc() or kcapi_cipher_stream_update()): (i)
 * the complete associated data must be provided, followed by (ii) the
 * plaintext. For decryption, also (iii) the tag value must be sent.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_stream_init_dec(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

/**
 * kcapi_aead_stream_update() - send more data for processing (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be processed by the cipher operation.
 *	 - input
 * @iovlen: number of scatter/gather list elements. - input
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * Note, see the order of input data as outlined in
 * kcapi_aead_stream_init_dec().
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is getting full. The process will be woken up once more buffer
 * space becomes available by calling kcapi_aead_stream_op().
 *
 * Note: The last block of input data MUST be provided with
 * kcapi_aead_stream_update_last() as the kernel must be informed about the
 * completion of the input data.
 *
 * With the separate API calls of kcapi_aead_stream_update() and
 * kcapi_aead_stream_op() a multi-threaded application can be implemented
 * where one thread sends data to be processed and one thread picks up data
 * processed by the cipher operation.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_stream_update(struct kcapi_handle *handle,
				 struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

/**
 * kcapi_aead_stream_update_last() - send last data for processing (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list with data to be processed by the cipher operation.
 *	 - input
 * @iovlen: number of scatter/gather list elements. - input
 *
 * Using this function call, more plaintext for encryption or ciphertext for
 * decryption can be submitted to the kernel.
 *
 * This call is identical to the kcapi_aead_stream_update() call with the
 * exception that it marks the last data buffer before the cipher operation
 * is triggered. Typically, the tag value is provided with this call.
 *
 * Return: number of bytes sent to the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_stream_update_last(struct kcapi_handle *handle,
				      struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, 0);
}

/**
 * kcapi_aead_stream_op() - obtain processed data (stream)
 * @handle: cipher handle - input
 * @iov: scatter/gather list pointing to buffers to be filled with the
 *	 resulting data from a cipher operation. - output
 * @iovlen: number of @outiov scatter/gather list elements. - input
 *
 * This function may cause the caller to sleep if the kernel buffer holding
 * the data is empty. The process will be woken up once more data is sent
 * by calling kcapi_cipher_stream_update().
 *
 * Note, when supplying buffers that are not multiple of block size, the buffers
 * will only be filled up to the maximum number of full block sizes that fit
 * into the buffer.
 *
 * Return: number of bytes obtained from the kernel upon success;
 *	   < 0 in case of error with errno set
 */
ssize_t kcapi_aead_stream_op(struct kcapi_handle *handle,
			     struct iovec *iov, size_t iovlen)
{
	if (!iov) {
		fprintf(stderr,
			"AEAD operation: No buffer for output data provided\n");
		return -EINVAL;
	}
	if (iovlen != 1) {
		fprintf(stderr,
			"AEAD operation: Output IOV must contain only one entry\n");
		return -EINVAL;
	}
	return _kcapi_common_recv_data(handle, iov, iovlen);
}

/**
 * kcapi_aead_ivsize() - return size of IV required for cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the IV size;
 *	   0 on error
 */
unsigned int kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

/**
 * kcapi_aead_blocksize() - return size of one block of the cipher
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size;
 *	   0 on error
 */
unsigned int kcapi_aead_blocksize(struct kcapi_handle *handle)
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
 * Return: > 0 specifying the block size;
 *	   0 on error
 */
unsigned int kcapi_aead_authsize(struct kcapi_handle *handle)
{
	return handle->info.aead_maxauthsize;
}

/**
 * kcapi_aead_outbuflen() - return minimum output buffer length
 * @handle: cipher handle - input
 * @inlen: size of plaintext (if @enc is one) or size of ciphertext (if @enc
 * 	   is zero)
 * @taglen: size of authentication tag
 * @enc: type of cipher operation (1 == encryption, 0 == decryption)
 *
 * Return: minimum size of output data length in bytes
 */
size_t kcapi_aead_outbuflen(struct kcapi_handle *handle,
			    size_t inlen, size_t taglen, int enc)
{
	if (enc)
		return _kcapi_aead_encrypt_outlen(handle, inlen, taglen);
	else
		return _kcapi_aead_decrypt_outlen(handle, inlen);
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
 * Return: 0 upon success;
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
 * Return: 0 upon success;
 *	   < 0 in case of error
 */
int kcapi_md_setkey(struct kcapi_handle *handle,
		    const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

static ssize_t _kcapi_md_update(struct kcapi_handle *handle,
				const unsigned char *buffer, size_t len)
{
	ssize_t r;

	r = send(handle->opfd, buffer, len, MSG_MORE);
	if (r < 0 || (size_t)r < len)
		return -EIO;

	return 0;
}

/**
 * kcapi_md_update() - message digest update function (stream)
 * @handle: cipher handle - input
 * @buffer: holding the data to add to the message digest - input
 * @len: buffer length - input
 *
 * Return: 0 upon success;
 *	   < 0 in case of error
 */
ssize_t kcapi_md_update(struct kcapi_handle *handle,
		    const unsigned char *buffer, size_t len)
{
	return _kcapi_md_update(handle, buffer, len);
}

static ssize_t _kcapi_md_final(struct kcapi_handle *handle,
			       unsigned char *buffer, size_t len)
{
	struct iovec iov;

	if (len < (unsigned long)handle->info.hash_digestsize) {
		fprintf(stderr,
			"Message digest: output buffer too small (seen %lu - required %u)\n",
			(unsigned long)len,
			handle->info.hash_digestsize);
		return -EINVAL;
	}

	iov.iov_base = (void*)(uintptr_t)buffer;
	iov.iov_len = len;
	return _kcapi_common_recv_data(handle, &iov, 1);
}

/**
 * kcapi_md_final() - message digest finalization function (stream)
 * @handle: cipher handle - input
 * @buffer: filled with the message digest - output
 * @len: buffer length - input
 *
 * Return: size of message digest upon success;
 *	   -EIO - data cannot be obtained;
 * 	   -ENOMEM - buffer is too small for the complete message digest,
 * 	   the buffer is filled with the truncated message digest
 */

ssize_t kcapi_md_final(struct kcapi_handle *handle,
		       unsigned char *buffer, size_t len)
{
	return _kcapi_md_final(handle, buffer, len);
}

/**
 * kcapi_md_digest() - calculate message digest on buffer (one-shot)
 * @handle: cipher handle - input
 * @in: buffer with input data - input
 * @inlen: length of input buffer
 * @out: buffer for message digest - output
 * @outlen: length of @out
 *
 * With this one-shot function, a message digest of the given buffer is
 * generated. The output buffer must be allocated by the caller and have at
 * least the length of the message digest size for the chosen message digest.
 *
 * The message digest handle must have been initialized, potentially by also
 * setting the key using the generic message digest API functions.
 *
 * Return: size of message digest upon success;
 *	   -EIO - data cannot be obtained;
 * 	   -ENOMEM - buffer is too small for the complete message digest,
 * 	   the buffer is filled with the truncated message digest
 */
ssize_t kcapi_md_digest(struct kcapi_handle *handle,
		       const unsigned char *in, size_t inlen,
		       unsigned char *out, size_t outlen)
{
	struct iovec iov;
	ssize_t ret = 0;
	size_t processed = 0;

	if (!out || !outlen) {
		fprintf(stderr,
			"Message digest: Empty plaintext or message digest buffer provided\n");
		return -EINVAL;
	}

	if (outlen < (unsigned int)handle->info.hash_digestsize) {
		fprintf(stderr,
			"Message digest: output buffer too small (seen %lu - required %u)\n",
			(unsigned long)outlen,
			handle->info.hash_digestsize);
		return -EINVAL;
	}

	/* zero buffer length cannot be handled via splice */
	/* TODO check that heuristic for sendmsg is appropriate */
	if(inlen == 0 /* < (1<<15) */) {
		if (_kcapi_md_update(handle, in, inlen))
			return -EIO;
		return _kcapi_md_final(handle, out, outlen);
	}

	/* normal zero copy */
	iov.iov_base = (void*)(uintptr_t)in;

	while (inlen) {
		size_t datalen = (inlen > MAXPIPELEN) ? MAXPIPELEN : inlen;

		iov.iov_len = datalen;
		ret = _kcapi_common_vmsplice_data(handle, &iov, 1, datalen,
						  SPLICE_F_MORE);
		if (0 > ret)
			return ret;
		processed += ret;
		iov.iov_base = (void*)(uintptr_t)(in + processed);
		inlen -= ret;
	}
	return _kcapi_common_read_data(handle, out, outlen);
}
/**
 * kcapi_md_digestsize() - return the size of the message digest
 * @handle: cipher handle - input
 *
 * The returned message digest size can be used before the @kcapi_md_final
 * function invocation to determine the right memory size to be allocated for
 * this call.
 *
 * Return: > 0 specifying the block size;
 *	   0 on error
 */
unsigned int kcapi_md_digestsize(struct kcapi_handle *handle)
{
	return handle->info.hash_digestsize;
}

/**
 * kcapi_md_blocksize() - return size of one block of the message digest
 * @handle: cipher handle - input
 *
 * Return: > 0 specifying the block size;
 *	   0 on error
 */
unsigned int kcapi_md_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
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
 * kcapi_rng_seed() - Seed the RNG
 * @handle: cipher handle - input
 * @seed: seed data - input
 * @seedlen: size of @seed
 *
 * Return: 0 upon success;
 * 	   < 0 upon error
 */
int kcapi_rng_seed(struct kcapi_handle *handle, unsigned char *seed,
		   size_t seedlen)
{
	return _kcapi_common_setkey(handle, seed, seedlen);
}

/**
 * kcapi_rng_generate() - generate a random number
 * @handle: cipher handle - input
 * @buffer: filled with the random number - output
 * @len: buffer length - input
 *
 * Return: size of random number generated upon success;
 *	   -EIO - data cannot be obtained
 */
ssize_t kcapi_rng_generate(struct kcapi_handle *handle,
			   unsigned char *buffer, size_t len)
{
	ssize_t out = 0;
	struct iovec iov;

	while (len) {
		ssize_t r = 0;

		iov.iov_base = (void*)(uintptr_t)buffer;
		iov.iov_len = len;
		r = _kcapi_common_recv_data(handle, &iov, 1);
		if (0 >= r)
			return r;
		len -= r;
		out += r;

		buffer += r;
	}

	return out;
}
