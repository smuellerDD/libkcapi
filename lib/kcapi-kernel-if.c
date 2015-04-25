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
#define MINVERSION 7 /* API compatible, ABI may change, functional
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
	int errsv = 0;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	size_t iv_msg_size = handle->cipher.iv ?
			  CMSG_SPACE(sizeof(*alg_iv) + handle->info.ivsize) :
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
		alg_iv->ivlen = handle->info.ivsize;
		memcpy(alg_iv->iv, handle->cipher.iv, handle->info.ivsize);
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
	errsv = errno;

	memset(buffer, 0, bufferlen);
	/* magic to convince GCC to memset the buffer */
	_buffer = memchr(buffer, 1, bufferlen);
	if (_buffer)
		_buffer = '\0';
	free(buffer);
	return (ret >= 0) ? ret : -errsv;
}

static inline ssize_t _kcapi_common_send_data(struct kcapi_handle *handle,
				       struct iovec *iov, size_t iovlen,
				       unsigned int flags)
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

	ret = sendmsg(handle->opfd, &msg, flags);
	return (ret >= 0) ? ret : -errno;
}

static inline ssize_t _kcapi_common_vmsplice_data(struct kcapi_handle *handle,
						  struct iovec *iov,
						  size_t iovlen,
						  size_t inlen,
						  unsigned int flags)
{
	ssize_t ret = 0;

	if (inlen > MAXPIPELEN) {
		fprintf(stderr, "Splice operation: input data exceeds maximum allowed size of %lu\n",
			MAXPIPELEN);
		return -E2BIG;
	}

	ret = vmsplice(handle->pipes[1], iov, iovlen, SPLICE_F_GIFT|flags);
	if (0 > ret)
		return ret;
	if ((size_t)ret != inlen)
		fprintf(stderr, "vmsplice: not all data received by kernel (data recieved: %ld -- data sent: %lu)\n",
			(long)ret, (unsigned long)inlen);
	ret = splice(handle->pipes[0], NULL, handle->opfd, NULL, ret, flags);
	return (ret >= 0) ? ret : -errno;
}

static inline ssize_t _kcapi_common_recv_data(struct kcapi_handle *handle,
					      struct iovec *iov, size_t iovlen)
{
	struct msghdr msg;
	ssize_t ret = 0;
	int errsv = 0;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = recvmsg(handle->opfd, &msg, 0);
	errsv = errno;
	if (msg.msg_flags & MSG_TRUNC) {
		fprintf(stderr, "recvmsg: processed data was truncated by kernel (only %lu bytes processed)\n", (unsigned long)ret);
		return -EMSGSIZE;
	}
	return (ret >= 0) ? ret : -errsv;
}

static inline ssize_t _kcapi_common_read_data(struct kcapi_handle *handle,
					      unsigned char *out, size_t outlen)
{
	ssize_t ret = 0;

	ret = read(handle->opfd, out, outlen);
	return (ret >= 0) ? ret : -errno;
}

static inline int _kcapi_common_setkey(struct kcapi_handle *handle,
				       const unsigned char *key, size_t keylen)
{
	int ret = 0;

	ret = setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen);
	return (ret >= 0) ? ret : -errno;
}

static int __kcapi_common_getinfo(struct kcapi_handle *handle,
				  const char *ciphername,
				  int drivername)
{
	int ret = -EFAULT;
	int errsv = 0;

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
		return -errno;
	}
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
		errsv = errno;
		perror("Netlink error: cannot bind netlink socket");
		goto out;
	}
	/* sanity check that netlink socket was successfully opened */
	addr_len = sizeof(nl);
	if (getsockname(sd, (struct sockaddr*)&nl, &addr_len) < 0) {
		errsv = errno;
		perror("Netlink error: cannot getsockname");
		goto out;
	}
	if (addr_len != sizeof(nl)) {
		errsv = errno;
		fprintf(stderr, "Netlink error: wrong address length %d\n",
			addr_len);
		goto out;
	}
	if (nl.nl_family != AF_NETLINK) {
		errsv = errno;
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
		errsv = errno;
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
			errsv = errno;
			perror("Netlink error: netlink receive error");
			goto out;
		}
		if (ret == 0) {
			errsv = errno;
			fprintf(stderr, "Netlink error: no data\n");
			goto out;
		}
		if ((size_t)ret > sizeof(buf)) {
			errsv = errno;
			perror("Netlink error: received too much data\n");
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
	return (errsv) ? -errsv : ret;
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
	int errsv = 0;

	memset(handle, 0, sizeof(struct kcapi_handle));

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type),"%s", type);
	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),"%s", ciphername);

	handle->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (handle->tfmfd == -1)
		return -EOPNOTSUPP;

	if (bind(handle->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		errsv = errno;
		perror("AF_ALG: bind failed");
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -errsv;
	}

	handle->opfd = accept(handle->tfmfd, NULL, 0);
	if (handle->opfd == -1) {
		errsv = errno;
		perror("AF_ALG: accept failed");
		close(handle->tfmfd);
		handle->tfmfd = -1;
		return -errsv;
	}

	ret = pipe(handle->pipes);
	if (ret) {
		errsv = errno;
		close(handle->tfmfd);
		close(handle->opfd);
		return -errsv;
	}

	ret = _kcapi_common_getinfo(handle, ciphername);
	if(ret) {
		errsv = errno;
		fprintf(stderr, "NETLINK_CRYPTO: cannot obtain cipher information for %s (is required crypto_user.c patch missing? see documentation)\n",
		       ciphername);
		close(handle->tfmfd);
		close(handle->opfd);
		close(handle->pipes[0]);
		close(handle->pipes[1]);
	}
	return (errsv) ? -errsv : ret;
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

void kcapi_versionstring(char *buf, size_t buflen)
{
	snprintf(buf, buflen, "libkcapi %d.%d.%d", MAJVERSION, MINVERSION,
		 PATCHLEVEL);
}

unsigned int kcapi_version(void)
{
	unsigned int version = 0;

	version =  MAJVERSION * 1000000;
	version += MINVERSION * 10000;
	version += PATCHLEVEL * 100;

	return version;
}

int kcapi_pad_iv(struct kcapi_handle *handle,
		 const unsigned char *iv, size_t ivlen,
		 unsigned char **newiv, size_t *newivlen)
{
	unsigned char *niv = NULL;
	unsigned int nivlen = handle->info.ivsize;
	unsigned int copylen = (ivlen > nivlen) ? nivlen : ivlen;
	int ret = 0;

	ret = posix_memalign((void *)&niv, 16, nivlen);
	if (ret)
		return -ret;
	memset(niv, 0, nivlen);
	memcpy(niv, iv, copylen);

	*newiv = niv;
	*newivlen = nivlen;

	return 0;
}

int kcapi_cipher_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "skcipher", ciphername);
}

int kcapi_cipher_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

int kcapi_cipher_setkey(struct kcapi_handle *handle,
			const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

ssize_t kcapi_cipher_encrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     const unsigned char *iv,
			     unsigned char *out, size_t outlen, int access)
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

	handle->cipher.iv = iv;

	iov.iov_base = (void*)(uintptr_t)in;
	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	if ((access == KCAPI_ACCESS_HEURISTIC && inlen <= (1<<13)) ||
	    access == KCAPI_ACCESS_SENDMSG) {
		iov.iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov, 1, ALG_OP_ENCRYPT,
					      0);
		if (0 > ret)
			return ret;
		iov.iov_base = (void*)(uintptr_t)out;
		iov.iov_len = outlen;
		return _kcapi_common_recv_data(handle, &iov, 1);
	}

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

ssize_t kcapi_cipher_decrypt(struct kcapi_handle *handle,
			     const unsigned char *in, size_t inlen,
			     const unsigned char *iv,
			     unsigned char *out, size_t outlen, int access)
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

	handle->cipher.iv = iv;

	iov.iov_base = (void*)(uintptr_t)in;

	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	if ((access == KCAPI_ACCESS_HEURISTIC && inlen <= (1<<13)) ||
	    access == KCAPI_ACCESS_SENDMSG) {
		iov.iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov, 1, ALG_OP_DECRYPT,
					      0);
		iov.iov_base = (void*)(uintptr_t)out;
		iov.iov_len = outlen;
		return _kcapi_common_recv_data(handle, &iov, 1);
	}

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

ssize_t kcapi_cipher_stream_init_enc(struct kcapi_handle *handle,
				     const unsigned char *iv,
				     struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

ssize_t kcapi_cipher_stream_init_dec(struct kcapi_handle *handle,
				     const unsigned char *iv,
				     struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

ssize_t kcapi_cipher_stream_update(struct kcapi_handle *handle,
				   struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

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

unsigned int kcapi_cipher_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

unsigned int kcapi_cipher_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}

int kcapi_aead_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "aead", ciphername);
}

int kcapi_aead_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

int kcapi_aead_setkey(struct kcapi_handle *handle,
		      const unsigned char *key, size_t keylen)
{
	return _kcapi_common_setkey(handle, key, keylen);
}

int kcapi_aead_settaglen(struct kcapi_handle *handle, size_t taglen)
{
	handle->aead.tag = NULL;
	handle->aead.taglen = taglen;
	if (setsockopt(handle->tfmfd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE,
		       NULL, taglen) == -1)
		return -EINVAL;

	return 0;
}

void kcapi_aead_setassoclen(struct kcapi_handle *handle, size_t assoclen)
{
	handle->aead.assoclen = assoclen;
}

ssize_t kcapi_aead_encrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *iv,
			   const unsigned char *assoc, unsigned char *out,
			   size_t outlen, int access)
{
	struct iovec iov[2];
	ssize_t ret = 0;

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

	handle->cipher.iv = iv;

	if (access == KCAPI_ACCESS_HEURISTIC ||
	    access == KCAPI_ACCESS_SENDMSG) {
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
		ret = _kcapi_common_read_data(handle, out, outlen);
		if (ret < 0)
			return ret;
		if ((ret < (ssize_t)handle->aead.taglen))
			return -E2BIG;
		return ret;
	}

	ret = _kcapi_common_send_meta(handle, NULL, 0, ALG_OP_ENCRYPT,
				      MSG_MORE);
	if (0 > ret)
		return ret;
	if (assoc && handle->aead.assoclen) {
		size_t len = 0;

		iov[0].iov_base = (void*)(uintptr_t)assoc;
		iov[0].iov_len = handle->aead.assoclen;
		len = handle->aead.assoclen;
		iov[1].iov_base = (void*)(uintptr_t)in;
		iov[1].iov_len = inlen;
		len += inlen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 2, len, 0);
	} else {
		size_t len = 0;

		iov[0].iov_base = (void*)(uintptr_t)in;
		iov[0].iov_len = inlen;
		len = inlen;
		ret = _kcapi_common_vmsplice_data(handle, &iov[0], 1, len, 0);
	}
	if (0 > ret)
		return ret;

	ret = _kcapi_common_read_data(handle, out, outlen);
	if (ret < 0)
		return ret;
	if ((ret < (ssize_t)handle->aead.taglen))
		return -E2BIG;

	return ret;
}

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

ssize_t kcapi_aead_decrypt(struct kcapi_handle *handle,
			   const unsigned char *in, size_t inlen,
			   const unsigned char *iv,
			   const unsigned char *assoc, const unsigned char *tag,
			   unsigned char *out, size_t outlen, int access)
{
	struct iovec iov[3];
	ssize_t ret = 0;
	unsigned int bs = handle->info.blocksize;

	/* require properly sized output data size */
	if (outlen < _kcapi_aead_decrypt_outlen(handle, inlen)) {
		fprintf(stderr,
			"AEAD Decryption: Plaintext buffer (%lu) is not ciphertext buffer (%lu) reduced by tag length (%lu) routed up to multiple of block size %u\n",
			(unsigned long)outlen, (unsigned long) inlen,
			(unsigned long)handle->aead.taglen, bs);
		return -EINVAL;
	}

	handle->cipher.iv = iv;

	if (access == KCAPI_ACCESS_HEURISTIC ||
	    access == KCAPI_ACCESS_SENDMSG) {
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
	} else {
		size_t len = 0;

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
			ret = _kcapi_common_vmsplice_data(handle, &iov[0], 3,
							  len, 0);
		} else {
			iov[0].iov_base = (void*)(uintptr_t)in;
			iov[0].iov_len = inlen;
			len = inlen;
			iov[1].iov_base = (void*)(uintptr_t)tag;
			iov[1].iov_len = handle->aead.taglen;
			len += handle->aead.taglen;
			ret = _kcapi_common_vmsplice_data(handle, &iov[0], 2,
							  len, 0);
		}
		if (0 > ret)
			return ret;
	}

	return _kcapi_common_read_data(handle, out, outlen);
}

ssize_t kcapi_aead_stream_init_enc(struct kcapi_handle *handle,
				   const unsigned char *iv,
				   struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_ENCRYPT,
				       MSG_MORE);
}

ssize_t kcapi_aead_stream_init_dec(struct kcapi_handle *handle,
				   const unsigned char *iv,
				   struct iovec *iov, size_t iovlen)
{
	handle->cipher.iv = iv;
	return _kcapi_common_send_meta(handle, iov, iovlen, ALG_OP_DECRYPT,
				       MSG_MORE);
}

ssize_t kcapi_aead_stream_update(struct kcapi_handle *handle,
				 struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, MSG_MORE);
}

ssize_t kcapi_aead_stream_update_last(struct kcapi_handle *handle,
				      struct iovec *iov, size_t iovlen)
{
	return _kcapi_common_send_data(handle, iov, iovlen, 0);
}

ssize_t kcapi_aead_stream_op(struct kcapi_handle *handle,
			     struct iovec *iov, size_t iovlen)
{
	if (!iov) {
		fprintf(stderr,
			"AEAD operation: No buffer for output data provided\n");
		return -EINVAL;
	}
#if 0
	if (iovlen != 1) {
		fprintf(stderr,
			"AEAD operation: Output IOV must contain only one entry\n");
		return -EINVAL;
	}
#endif
	return _kcapi_common_recv_data(handle, iov, iovlen);
}

unsigned int kcapi_aead_ivsize(struct kcapi_handle *handle)
{
	return handle->info.ivsize;
}

unsigned int kcapi_aead_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}

unsigned int kcapi_aead_authsize(struct kcapi_handle *handle)
{
	return handle->info.aead_maxauthsize;
}

size_t kcapi_aead_outbuflen(struct kcapi_handle *handle,
			    size_t inlen, size_t taglen, int enc)
{
	if (enc)
		return _kcapi_aead_encrypt_outlen(handle, inlen, taglen);
	else
		return _kcapi_aead_decrypt_outlen(handle, inlen);
}

int kcapi_aead_ccm_nonce_to_iv(const unsigned char *nonce, size_t noncelen,
			       unsigned char **iv, size_t *ivlen)
{
	unsigned char *newiv = NULL;
	unsigned char l = 16 - 2 - noncelen;
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

int kcapi_md_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "hash", ciphername);
}

int kcapi_md_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

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

ssize_t kcapi_md_final(struct kcapi_handle *handle,
		       unsigned char *buffer, size_t len)
{
	return _kcapi_md_final(handle, buffer, len);
}

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

unsigned int kcapi_md_digestsize(struct kcapi_handle *handle)
{
	return handle->info.hash_digestsize;
}

unsigned int kcapi_md_blocksize(struct kcapi_handle *handle)
{
	return handle->info.blocksize;
}

int kcapi_rng_init(struct kcapi_handle *handle, const char *ciphername)
{
	return _kcapi_handle_init(handle, "rng", ciphername);
}

int kcapi_rng_destroy(struct kcapi_handle *handle)
{
	return _kcapi_handle_destroy(handle);
}

int kcapi_rng_seed(struct kcapi_handle *handle, unsigned char *seed,
		   size_t seedlen)
{
	return _kcapi_common_setkey(handle, seed, seedlen);
}

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
