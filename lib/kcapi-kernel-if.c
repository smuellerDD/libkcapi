/* Kernel crypto API AF_ALG interface code
 *
 * Copyright (C) 2015 - 2020, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <stdarg.h>
#include <unistd.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/eventfd.h>
#include <time.h>
#include <sys/select.h>
#include <sys/utsname.h>
#include <sys/prctl.h>

#include "cryptouser.h"
#include "kcapi.h"
#include "internal.h"

/************************************************************
 * Common helper used within the lib and as an API
 ************************************************************/
DSO_PUBLIC
void kcapi_memset_secure(void *s, int c, uint32_t n)
{
	memset(s, c, n);
	__asm__ __volatile__("" : : "r" (s) : "memory");
}

/************************************************************
 * Logging logic
 ************************************************************/
int kcapi_verbosity_level = KCAPI_LOG_ERR;

void kcapi_dolog(int severity, const char *fmt, ...)
{
	va_list args;
	char msg[128];
	char sev[16];

	if (severity > kcapi_verbosity_level)
		return;

	memset(sev, 0, sizeof(sev));
	memset(msg, 0, sizeof(msg));

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, args);
	va_end(args);

	switch (severity) {
	case KCAPI_LOG_DEBUG:
		snprintf(sev, sizeof(sev), "Debug");
		break;
	case KCAPI_LOG_VERBOSE:
		snprintf(sev, sizeof(sev), "Verbose");
		break;
	case KCAPI_LOG_WARN:
		snprintf(sev, sizeof(sev), "Warning");
		break;
	case KCAPI_LOG_ERR:
		snprintf(sev, sizeof(sev), "Error");
		break;
	default:
		snprintf(sev, sizeof(sev), "Unknown");
	}
	fprintf(stderr, "libkcapi - %s: %s\n", sev, msg);
}

/************************************************************
 * Internal logic
 ************************************************************/

int _kcapi_common_accept(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int fd;

	if (*_kcapi_get_opfd(handle) != -1)
		return 0;

	fd = accept(tfm->tfmfd, NULL, 0);
	if (fd == -1) {
		int errsv;

		errsv = errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: accept failed");
		return -errsv;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: accept syscall successful");

	*_kcapi_get_opfd(handle) = fd;

	return 0;
}

int32_t _kcapi_common_send_meta(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen,
				uint32_t enc, uint32_t flags)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int32_t ret;
	char buffer_static[80] = { 0 };
	char *buffer_p = buffer_static;
	char *buffer_alloc = NULL;

	/* plaintext / ciphertext data */
	struct cmsghdr *header = NULL;
	uint32_t *type = NULL;
	struct msghdr msg;

	/* IV data */
	struct af_alg_iv *alg_iv = NULL;
	uint32_t iv_msg_size = handle->cipher.iv ?
			  CMSG_SPACE(sizeof(*alg_iv) + tfm->info.ivsize) :
			  0;

	/* AEAD data */
	uint32_t *assoclen = NULL;
	uint32_t assoc_msg_size = handle->aead.assoclen ?
				CMSG_SPACE(sizeof(*assoclen)) : 0;

	uint32_t bufferlen =
		CMSG_SPACE(sizeof(*type)) + 	/* Encryption / Decryption */
		iv_msg_size +			/* IV */
		assoc_msg_size;			/* AEAD associated data size */

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	memset(&msg, 0, sizeof(msg));

	/* allocate buffer, if static buffer is too small */
	if (bufferlen > sizeof(buffer_static)) {
		buffer_alloc = calloc(1, bufferlen);
		if (!buffer_alloc)
			return -ENOMEM;
		buffer_p = buffer_alloc;
		kcapi_dolog(KCAPI_LOG_VERBOSE,
			    "_kcapi_common_send_meta_fd: submission buffer of size %u allocated",
			    bufferlen);
	}

	msg.msg_control = buffer_p;
	msg.msg_controllen = bufferlen;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	/* encrypt/decrypt operation */
	header = CMSG_FIRSTHDR(&msg);
	if (!header) {
		ret = -EFAULT;
		goto out;
	}
	header->cmsg_level = SOL_ALG;
	header->cmsg_type = ALG_SET_OP;
	header->cmsg_len = CMSG_LEN(sizeof(*type));
	type = (void*)CMSG_DATA(header);
	*type = enc;

	/* set IV */
	if (handle->cipher.iv) {
		header = CMSG_NXTHDR(&msg, header);
		if (!header) {
			ret = -EFAULT;
			goto out;
		}
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_IV;
		header->cmsg_len = iv_msg_size;
		alg_iv = (void*)CMSG_DATA(header);
		alg_iv->ivlen = tfm->info.ivsize;
		memcpy(alg_iv->iv, handle->cipher.iv, tfm->info.ivsize);
	}

	/* set AEAD information */
	if (handle->aead.assoclen) {
		/* Set associated data length */
		header = CMSG_NXTHDR(&msg, header);
		if (!header) {
			ret = -EFAULT;
			goto out;
		}
		header->cmsg_level = SOL_ALG;
		header->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
		header->cmsg_len = CMSG_LEN(sizeof(*assoclen));
		assoclen = (void*)CMSG_DATA(header);
		*assoclen = handle->aead.assoclen;
	}

	ret = sendmsg(*_kcapi_get_opfd(handle), &msg, flags);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG,
		    "AF_ALG: sendmsg syscall returned %d", ret);

out:
	kcapi_memset_secure(buffer_p, 0, bufferlen);
	if (buffer_alloc)
		free(buffer_alloc);
	return ret;
}

int32_t _kcapi_common_send_data(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen,
				uint32_t flags)
{
	struct msghdr msg;
	int32_t ret;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = sendmsg(*_kcapi_get_opfd(handle), &msg, flags);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: sendmsg syscall returned %d",
		    ret);

	return ret;
}

int32_t _kcapi_common_vmsplice_iov(struct kcapi_handle *handle,
				   struct iovec *iov, unsigned long iovlen,
				   uint32_t flags)
{
	int32_t ret = 0;
	uint32_t inlen = 0;
	unsigned long i;

	if (iovlen && !iov)
		return -EINVAL;

	for (i = 0; i < iovlen; i++)
		inlen += iov[i].iov_len;

	/* kernel processes input data with max size of one page */
	handle->processed_sg += ((inlen + sysconf(_SC_PAGESIZE) - 1) /
				 sysconf(_SC_PAGESIZE));
	if (handle->processed_sg > handle->flags.alg_max_pages || !inlen)
		return _kcapi_common_send_data(handle, iov, iovlen,
					       (flags & SPLICE_F_MORE) ?
					        MSG_MORE : 0);

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	ret = vmsplice(handle->pipes[1], iov, iovlen, SPLICE_F_GIFT|flags);
	if (ret < 0) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "AF_ALG: vmsplice syscall returned %d", ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: vmsplice syscall returned %d",
		    ret);

	if ((uint32_t)ret != inlen) {
		kcapi_dolog(KCAPI_LOG_ERR, "vmsplice: not all data received by kernel (data received: %ld -- data sent: %lu)",
			(long)ret, (unsigned long)inlen);
		return -EFAULT;
	}

	ret = splice(handle->pipes[0], NULL, *_kcapi_get_opfd(handle), NULL,
		     ret, flags);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: splice syscall returned %d", ret);

	return ret;
}

static uint32_t vmsplice_limit;

int32_t _kcapi_common_vmsplice_chunk(struct kcapi_handle *handle,
				     const uint8_t *in, uint32_t inlen,
				     uint32_t flags)
{
	struct iovec iov;
	uint32_t processed = 0;
	int32_t ret = 0;
	uint32_t sflags = (flags & SPLICE_F_MORE) ? MSG_MORE : 0;

	if (inlen > INT_MAX)
		return -EMSGSIZE;

	if (!inlen)
		return _kcapi_common_send_data(handle, NULL, 0, sflags);

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	while (inlen) {
		iov.iov_base = (void*)(uintptr_t)(in + processed);
		iov.iov_len = inlen;

		/*
		 * vmsplice will only process 16 pages in one go. sendmsg
		 * will process much more. Thus, if we have much larger
		 * requests than 16 pages, the overhead of system calls
		 * is higher than the memory copy operation. Thus we use
		 * sendmsg if we have more than 16 pages to process.
		 */
		if ((handle->processed_sg++) > handle->flags.alg_max_pages ||
		    inlen > vmsplice_limit) {
			ret = _kcapi_common_send_data(handle, &iov, 1, sflags);
			if (ret < 0)
				return ret;
		} else {
			ret = vmsplice(handle->pipes[1], &iov, 1,
				       SPLICE_F_GIFT|flags);
			if (ret < 0) {
				ret = -errno;
				kcapi_dolog(KCAPI_LOG_DEBUG,
					    "AF_ALG: vmsplice syscall returned %d",
					    ret);
				return ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG,
				    "AF_ALG: vmsplice syscall returned %d",
				    ret);

			ret = splice(handle->pipes[0], NULL,
				     *_kcapi_get_opfd(handle), NULL, ret,
				     flags);
			if (ret < 0) {
				ret = -errno;
				kcapi_dolog(KCAPI_LOG_DEBUG,
					    "AF_ALG: splice syscall returned %d",
					    ret);
				return ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG,
				    "AF_ALG: splice syscall returned %d", ret);
		}

		processed += ret;
		inlen -= ret;
	}

	return processed;
}

/* Wrapper for io_getevents -- returns < 0 on error, or processed bytes */
int _kcapi_aio_read_all(struct kcapi_handle *handle, uint32_t toread,
			struct timespec *timeout)
{
	if (toread > KCAPI_AIO_CONCURRENT)
		return -EINVAL;

	while (toread) {
		int i;
		struct io_event events[KCAPI_AIO_CONCURRENT];
		int rc = io_getevents(handle->aio.aio_ctx, 1, toread,
				      events, timeout);

		if (rc < 0)
			return rc;

		for (i = 0; i < rc; i++) {
			struct iocb *cb;

			/*
			 * If one cipher operation fails, so will the entire
			 * AIO operation
			 */
			if (events[i].res < 0) {
				handle->aio.iocb_ret[events[i].data] =
							events[i].res;
				return (int)events[i].res;
			}

			cb = (struct iocb *)(uintptr_t)events[i].obj;

			/*
			 * Older symmetric AIO implementations used a wrong
			 * return code.
			 */
			if (events[i].res > 0) {
				handle->aio.iocb_ret[events[i].data] =
								events[i].res;
			} else {
				handle->aio.iocb_ret[events[i].data] =
								cb->aio_nbytes;
			}

			cb->aio_fildes = 0;
		}
		toread -= rc;
	}

	return 0;
}

int _kcapi_aio_send_iov(struct kcapi_handle *handle, struct iovec *iov,
			uint32_t iovlen, int access, int enc)
{
	int ret;
	size_t len = iov ? iov->iov_len : 0;

	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	if ((access == KCAPI_ACCESS_HEURISTIC && len <= (1<<13)) ||
	    access == KCAPI_ACCESS_SENDMSG) {
		ret = _kcapi_common_send_meta(handle, iov, iovlen, enc, 0);
		if (0 > ret)
			return ret;
	} else {
		ret = _kcapi_common_send_meta(handle, NULL, 0, enc,
					      len ? MSG_MORE : 0);
		if (0 > ret)
			return ret;
		ret = _kcapi_common_vmsplice_iov(handle, iov, iovlen, 0);
		if (0 > ret)
			return ret;
	}

	return 0;
}

int _kcapi_aio_read_iov(struct kcapi_handle *handle,
			   struct iovec *iov, uint32_t iovlen)
{
	struct iocb *cb = handle->aio.cio;
	uint32_t i;
	int32_t ret;

	if (iovlen > KCAPI_AIO_CONCURRENT)
		return -EFAULT;

	for (i = 0; i < iovlen; i++) {
		while (cb->aio_fildes) {
			struct timespec timeout;

			timeout.tv_sec = 0;
			timeout.tv_nsec = 10000;
			ret = _kcapi_aio_read_all(handle, iovlen, &timeout);
			if (ret < 0)
				return ret;
		}

		memset(cb, 0, sizeof(*cb));
		cb->aio_fildes = *_kcapi_get_opfd(handle);
		cb->aio_lio_opcode = IOCB_CMD_PREAD;
		cb->aio_buf = (unsigned long)iov->iov_base;
		cb->aio_offset = 0;
		cb->aio_data = i;
		cb->aio_nbytes = iov->iov_len;
		cb->aio_flags = IOCB_FLAG_RESFD;
		cb->aio_resfd = handle->aio.efd;

		handle->aio.iocb_ret[i] = AIO_OUTSTANDING;

		cb++;
		iov++;
	}

	ret = io_submit(handle->aio.aio_ctx, iovlen, handle->aio.ciopp);
	if ((uint32_t)ret != iovlen) {
		if (ret < 0) {
			ret = -errno;
			kcapi_dolog(KCAPI_LOG_ERR, "io_read Error: %d\n", ret);
			return ret;
		} else {
			kcapi_dolog(KCAPI_LOG_ERR,
				    "Could not sumbit AIO read\n");
			return -EIO;
		}
	}

	return _kcapi_aio_read_all(handle, iovlen, NULL);
}

int32_t _kcapi_common_recv_data(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen)
{
	struct msghdr msg;
	int32_t ret;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;
	msg.msg_iov = iov;
	msg.msg_iovlen = iovlen;

	ret = recvmsg(*_kcapi_get_opfd(handle), &msg, 0);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: recvmsg syscall returned %d",
		    ret);

	/*
	 * As the iovecs are processed and removed from the list in the kernel
	 * we can also reset the list of processed iovecs here.
	 *
	 * Note, if there is an error, the kernel keeps the list unless it is
	 * a "valid" error of EBADMSG indicating an integrity error of the
	 * crypto operation.
	 */
	if (ret >= 0 || ret == -EBADMSG)
		handle->processed_sg = 0;

#if 0
	/*
	 * Truncated message digests can be identified with this check.
	 */
	if (msg.msg_flags & MSG_TRUNC) {
		fprintf(stderr, "recvmsg: processed data was truncated by kernel (only %lu bytes processed)\n", (unsigned long)ret);
		return -EMSGSIZE;
	}
#endif

	return ret;
}

int32_t _kcapi_common_read_data(struct kcapi_handle *handle,
				   uint8_t *out, uint32_t outlen)
{
	int ret;
	int32_t totallen = 0;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	ret = _kcapi_common_accept(handle);
	if (ret)
		return ret;


	if (outlen) {
		do {
			ret = read(*_kcapi_get_opfd(handle), out, outlen);
			if (ret > 0) {
				out += ret;
				outlen -= ret;
				totallen += ret;
			}
			kcapi_dolog(KCAPI_LOG_DEBUG,
				    "AF_ALG: read syscall returned %d", ret);
		} while ((ret > 0 || errno == EINTR) && outlen);

		if (ret < 0)
			return -errno;
	}

	return totallen;
}

int _kcapi_common_setkey(struct kcapi_handle *handle,
			 const uint8_t *key, uint32_t keylen)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int ret;

	ret = setsockopt(tfm->tfmfd, SOL_ALG, ALG_SET_KEY, key, keylen);
	if (ret < 0)
		ret = -errno;
	kcapi_dolog(KCAPI_LOG_DEBUG,
		    "AF_ALG setkey: setsockopt syscall returned %d", ret);

	return ret;
}

static int __kcapi_common_getinfo(struct kcapi_handle *handle,
				  const char *ciphername,
				  int drivername)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	int ret = -EFAULT;

	/* NETLINK_CRYPTO specific */
	char buf[4096];
	struct nlmsghdr *res_n = (struct nlmsghdr *)buf;
	struct {
		struct nlmsghdr n;
		struct crypto_user_alg cru;
	} req;
	struct crypto_user_alg *cru_res = NULL;
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
	req.n.nlmsg_seq = time(NULL);

	if (drivername)
		strncpy(req.cru.cru_driver_name, ciphername,
			sizeof(req.cru.cru_driver_name) - 1);
	else
		strncpy(req.cru.cru_name, ciphername, sizeof(req.cru.cru_name) - 1);

	/* talk to netlink socket */
	sd =  socket(AF_NETLINK, SOCK_RAW, NETLINK_CRYPTO);
	if (sd < 0) {
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Netlink error: cannot open netlink socket");
		return -errno;
	}
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	if (bind(sd, (struct sockaddr*)&nl, sizeof(nl)) < 0) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Netlink error: cannot bind netlink socket");
		goto out;
	}
	/* sanity check that netlink socket was successfully opened */
	addr_len = sizeof(nl);
	if (getsockname(sd, (struct sockaddr*)&nl, &addr_len) < 0) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "Netlink error: cannot getsockname");
		goto out;
	}
	if (addr_len != sizeof(nl)) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Netlink error: wrong address length %d", addr_len);
		goto out;
	}
	if (nl.nl_family != AF_NETLINK) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Netlink error: wrong address family %d",
			    nl.nl_family);
		goto out;
	}

	/* sending data */
	memset(&nl, 0, sizeof(nl));
	nl.nl_family = AF_NETLINK;
	iov.iov_base = (void*) &req.n;
	iov.iov_len = req.n.nlmsg_len;
	msg.msg_name = &nl;
	msg.msg_namelen = sizeof(nl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	if (sendmsg(sd, &msg, 0) < 0) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "Netlink error: sendmsg failed");
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
			ret = -errno;
			kcapi_dolog(KCAPI_LOG_ERR,
				    "Netlink error: netlink receive error");
			goto out;
		}
		if (ret == 0) {
			ret = -errno;
			kcapi_dolog(KCAPI_LOG_ERR, "Netlink error: no data");
			goto out;
		}
		if ((uint32_t)ret > sizeof(buf)) {
			ret = -errno;
			kcapi_dolog(KCAPI_LOG_ERR,
				    "Netlink error: received too much data");
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
		kcapi_dolog(KCAPI_LOG_ERR, "Netlink error: nlmsg len %d",
			    res_len);
		goto out;
	}

	/* parse data */
	if (!cru_res) {
		ret = -EFAULT;
		goto out;
	}
	rta = CR_RTA(cru_res);
	memset(tb, 0, sizeof(struct rtattr *) * (CRYPTOCFGA_MAX + 1));
	while (RTA_OK(rta, res_len)) {
		if ((rta->rta_type <= CRYPTOCFGA_MAX) && (!tb[rta->rta_type]))
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, res_len);
	}
	if (res_len) {
		kcapi_dolog(KCAPI_LOG_ERR, "Netlink error: unprocessed data %d",
			    res_len);
		goto out;
	}

	if (tb[CRYPTOCFGA_REPORT_HASH]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_HASH];
		struct crypto_report_hash *rsh =
			(struct crypto_report_hash *) RTA_DATA(rta);
		tfm->info.hash_digestsize = rsh->digestsize;
		tfm->info.blocksize = rsh->blocksize;
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: hash with digestsize %u,  blocksize %u",
			    rsh->digestsize, rsh->blocksize);

		tfm->info.cipher_type = KCAPI_CIPHER_MD;
	}
	if (tb[CRYPTOCFGA_REPORT_BLKCIPHER]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_BLKCIPHER];
		struct crypto_report_blkcipher *rblk =
			(struct crypto_report_blkcipher *) RTA_DATA(rta);
		tfm->info.blocksize = rblk->blocksize;
		tfm->info.ivsize = rblk->ivsize;
		tfm->info.blk_min_keysize = rblk->min_keysize;
		tfm->info.blk_max_keysize = rblk->max_keysize;
		kcapi_dolog(KCAPI_LOG_DEBUG, "Get cipher info: block cipher with blocksize %u, ivsize %u, minimum keysize %u, maximum keysize %u",
			    rblk->blocksize, rblk->ivsize, rblk->min_keysize,
			    rblk->max_keysize);

		tfm->info.cipher_type = KCAPI_CIPHER_SKCIPHER;
	}
	if (tb[CRYPTOCFGA_REPORT_AEAD]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_AEAD];
		struct crypto_report_aead *raead =
			(struct crypto_report_aead *) RTA_DATA(rta);
		tfm->info.blocksize = raead->blocksize;
		tfm->info.ivsize = raead->ivsize;
		tfm->info.aead_maxauthsize = raead->maxauthsize;
		kcapi_dolog(KCAPI_LOG_DEBUG, "Get cipher info: AEAD block cipher with blocksize %u, ivsize %u, maximum authentication size %u",
			    raead->blocksize, raead->ivsize,
			    raead->maxauthsize);

		tfm->info.cipher_type = KCAPI_CIPHER_AEAD;
	}
	if (tb[CRYPTOCFGA_REPORT_RNG]) {
		struct rtattr *rta = tb[CRYPTOCFGA_REPORT_RNG];
		struct crypto_report_rng *rrng =
			(struct crypto_report_rng *) RTA_DATA(rta);
		tfm->info.rng_seedsize = rrng->seedsize;
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: RNG cipher with seedsize %u",
			    rrng->seedsize);

		tfm->info.cipher_type = KCAPI_CIPHER_RNG;
	}
	if (tb[CRYPTOCFGA_UNSPEC])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: unspecified data received");
	if (tb[CRYPTOCFGA_PRIORITY_VAL])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: u32 value received");
	if (tb[CRYPTOCFGA_REPORT_LARVAL])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: larval value received");
	if (tb[CRYPTOCFGA_REPORT_COMPRESS])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: compression algorithm type received");
	if (tb[CRYPTOCFGA_REPORT_CIPHER])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: simple cipher algorithm type received");
	if (tb[CRYPTOCFGA_REPORT_AKCIPHER]) {
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: asymmetric cipher algorithm type received");

		tfm->info.cipher_type = KCAPI_CIPHER_AKCIPHER;
	}
	if (tb[CRYPTOCFGA_REPORT_KPP]) {
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: kpp cipher algorithm type received");

		tfm->info.cipher_type = KCAPI_CIPHER_KPP;
	}
	if (tb[CRYPTOCFGA_REPORT_ACOMP])
		kcapi_dolog(KCAPI_LOG_DEBUG,
			    "Get cipher info: asymmetric compression algorithm type received");
	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "Get cipher info: all information for %s received from kernel",
		    ciphername);

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

static inline void _kcapi_aio_destroy(struct kcapi_handle *handle)
{
	if (handle->aio.efd != -1)
		close(handle->aio.efd);
	handle->aio.efd = -1;
	if (handle->aio.aio_ctx)
		io_destroy(handle->aio.aio_ctx);
	handle->aio.aio_ctx = 0;
	if (handle->aio.cio)
		free(handle->aio.cio);
	handle->aio.cio = NULL;
	if (handle->aio.ciopp)
		free(handle->aio.ciopp);
	handle->aio.ciopp = NULL;
	if (handle->aio.iocb_ret)
		free(handle->aio.iocb_ret);
	handle->aio.iocb_ret = NULL;
}

static void _kcapi_handle_destroy_tfm(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm;
	if (!handle || !handle->tfm)
		return;

	tfm = handle->tfm;
	if (atomic_dec_and_test(&tfm->refcnt)) {
		if (tfm->tfmfd != -1)
			close(tfm->tfmfd);
		kcapi_memset_secure(tfm, 0, sizeof(*tfm));
		free(tfm);
		handle->tfm = NULL;
	}
}

void _kcapi_handle_destroy(struct kcapi_handle *handle)
{
	if (!handle)
		return;
	if (*_kcapi_get_opfd(handle) != -1)
		close(*_kcapi_get_opfd(handle));
	if (handle->pipes[0] != -1)
		close(handle->pipes[0]);
	if (handle->pipes[1] != -1)
		close(handle->pipes[1]);
	_kcapi_aio_destroy(handle);
	_kcapi_handle_destroy_tfm(handle);
	kcapi_memset_secure(handle, 0, sizeof(struct kcapi_handle));
	free(handle);
}

static int _kcapi_get_kernver(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	struct utsname kernel;
	char *saveptr = NULL;
	char *res = NULL;

	if (uname(&kernel))
		return -errno;

	/* 3.15.0 */
	res = strtok_r(kernel.release, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	tfm->sysinfo.kernel_maj = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	tfm->sysinfo.kernel_minor = strtoul(res, NULL, 10);
	res = strtok_r(NULL, ".", &saveptr);
	if (!res) {
		printf("Could not parse kernel version");
		return -EFAULT;
	}
	tfm->sysinfo.kernel_patchlevel = strtoul(res, NULL, 10);

	return 0;
}

/* return true if kernel is greater or equal to given values, otherwise false */
static bool _kcapi_kernver_ge(struct kcapi_handle *handle, unsigned int maj,
			      unsigned int minor, unsigned int patchlevel)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;

	if (maj < tfm->sysinfo.kernel_maj)
		return true;
	if (maj == tfm->sysinfo.kernel_maj) {
		if (minor < tfm->sysinfo.kernel_minor)
			return true;
		if (minor == tfm->sysinfo.kernel_minor) {
			if (patchlevel <= tfm->sysinfo.kernel_patchlevel)
				return true;
		}
	}
	return false;
}

static int _kcapi_aio_init(struct kcapi_handle *handle)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t i;
	int err;

	if (tfm->info.cipher_type == KCAPI_CIPHER_AEAD) {
		if (!_kcapi_kernver_ge(handle, 4, 7, 0)) {
			kcapi_dolog(KCAPI_LOG_VERBOSE, "AIO support for AEAD cipher not present on current kernel");
			err = -EOPNOTSUPP;
			goto err;
		}
	}
	if (tfm->info.cipher_type == KCAPI_CIPHER_SKCIPHER) {
		if (!_kcapi_kernver_ge(handle, 4, 1, 0)) {
			kcapi_dolog(KCAPI_LOG_VERBOSE, "AIO support for symmetric ciphers not present on current kernel");
			err = -EOPNOTSUPP;
			goto err;
		}
	}

	handle->aio.cio = calloc(KCAPI_AIO_CONCURRENT, sizeof(struct iocb));
	if (!handle->aio.cio) {
		err = -ENOMEM;
		goto err;
	}

	handle->aio.ciopp = calloc(KCAPI_AIO_CONCURRENT, sizeof(void *));
	if (!handle->aio.ciopp) {
		err = -ENOMEM;
		goto err;
	}

	handle->aio.iocb_ret = calloc(KCAPI_AIO_CONCURRENT, sizeof(__s64));
	if (!handle->aio.iocb_ret) {
		err = -ENOMEM;
		goto err;
	}

	/*
	 * Set up the pointers to pointers array that is required by
	 * io_submit. Please do not ask me why the kernel wants this. :-)
	 */
	for (i = 0; i < KCAPI_AIO_CONCURRENT; i++)
		*(handle->aio.ciopp + i) = handle->aio.cio + i;

	handle->aio.efd = eventfd(0, EFD_CLOEXEC);
	if (handle->aio.efd < 0) {
		err = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "Event FD cannot be initialized: %d\n",
			    err);
		goto err;
	}

	err = io_setup(KCAPI_AIO_CONCURRENT, &handle->aio.aio_ctx);
	if (err < 0) {
		err = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "io_setup error %d\n", err);
		goto err;
	}

	handle->aio.disable = false;
	kcapi_dolog(KCAPI_LOG_VERBOSE, "asynchronous I/O initialized");

	return 0;

err:
	_kcapi_aio_destroy(handle);

	return err;
}

static void _kcapi_handle_flags(struct kcapi_handle *handle)
{
	/* new memory structure for AF_ALG AEAD interface + fixed hashing empty input */
	handle->flags.ge_v4_9 = _kcapi_kernver_ge(handle, 4, 9, 0);

	/* older interfaces only processed 16 pages in a row */
	handle->flags.alg_max_pages = _kcapi_kernver_ge(handle, 4, 11, 0) ?
				      UINT_MAX : ALG_MAX_PAGES;
}

static int _kcapi_handle_alloc(struct kcapi_handle **caller)
{
	struct kcapi_handle *handle = calloc(1, sizeof(struct kcapi_handle));

	if (!handle)
		return -ENOMEM;

	*_kcapi_get_opfd(handle) = -1;
	handle->pipes[0] = -1;
	handle->pipes[1] = -1;
	handle->aio.efd = -1;

	*caller = handle;

	return 0;
}

static int _kcapi_handle_init_op(struct kcapi_handle *handle, uint32_t flags)
{
	int ret;

	ret = pipe(handle->pipes);
	if (ret) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR,
			    "AF_ALG: pipe syscall failed (errno: %d)",
			    ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: pipe syscall passed");

	if (flags & KCAPI_INIT_AIO) {
		ret = _kcapi_aio_init(handle);

		/*
		 * We complain about kernels without AIO support, but allow
		 * the allocation nonetheless as we have synchronous fallbacks
		 * for all AIO implementations. This allows the use of
		 * libkcapi AIO API even though the kernel does not support it.
		 * This allows compatibility for applications.
		 */
		if (ret && ret != -EOPNOTSUPP)
			return ret;
		ret = 0;
	} else
		handle->aio.disable = true;

	_kcapi_handle_flags(handle);

	return ret;
}

static int _kcapi_handle_init_tfm(struct kcapi_handle *handle, const char *type,
				  const char *ciphername)
{
	struct kcapi_handle_tfm *tfm = handle->tfm;
	struct sockaddr_alg sa;
	int ret;
	char versionbuffer[50];

	kcapi_versionstring(versionbuffer, sizeof(versionbuffer));
	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "%s - initializing cipher operation with kernel",
		    versionbuffer);

	tfm->tfmfd = -1;
	atomic_set(1, &tfm->refcnt);

	ret = _kcapi_get_kernver(handle);
	if (ret)
		return ret;

	memset(&sa, 0, sizeof(sa));
	sa.salg_family = AF_ALG;
	snprintf((char *)sa.salg_type, sizeof(sa.salg_type),"%s", type);
	snprintf((char *)sa.salg_name, sizeof(sa.salg_name),"%s", ciphername);

	tfm->tfmfd = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (tfm->tfmfd == -1) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR,
			    "AF_ALG: socket syscall failed (errno: %d)",
			    ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: socket syscall passed");

	if (bind(tfm->tfmfd, (struct sockaddr *)&sa, sizeof(sa)) == -1) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "AF_ALG: bind failed (errno: %d)",
			    ret);
		return ret;
	}
	kcapi_dolog(KCAPI_LOG_DEBUG, "AF_ALG: bind syscall passed");

	ret = _kcapi_common_getinfo(handle, ciphername);
	if (ret) {
		ret = -errno;
		kcapi_dolog(KCAPI_LOG_ERR, "NETLINK_CRYPTO: cannot obtain cipher information for %s (is required crypto_user.c patch missing? see documentation)",
			    ciphername);
		return ret;
	}

	return 0;
}

int _kcapi_handle_init(struct kcapi_handle **caller, const char *type,
		       const char *ciphername, uint32_t flags)
{
	struct kcapi_handle *handle;
	struct kcapi_handle_tfm *tfm;
	int ret;

	ret = _kcapi_handle_alloc(&handle);
	if (ret)
		return ret;

	tfm = calloc(1, sizeof(struct kcapi_handle_tfm));
	if (!tfm) {
		free(handle);
		return -ENOMEM;
	}

	handle->tfm = tfm;

	ret = _kcapi_handle_init_tfm(handle, type, ciphername);
	if (ret)
		goto err;

	ret = _kcapi_handle_init_op(handle, flags);
	if (ret)
		goto err;

	*caller = handle;

	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "communication for %s with kernel initialized",
		    ciphername);

	return 0;

err:
	_kcapi_handle_destroy(handle);
	return ret;
}

DSO_PUBLIC
int kcapi_handle_reinit(struct kcapi_handle **newhandle,
			struct kcapi_handle *existing, uint32_t flags)
{
	struct kcapi_handle *handle;
	int ret;

	ret = _kcapi_handle_alloc(&handle);
	if (ret)
		return ret;

	if (!existing || !existing->tfm) {
		ret = -EINVAL;
		goto err;
	}

	atomic_inc(&existing->tfm->refcnt);
	handle->tfm = existing->tfm;

	ret = _kcapi_handle_init_op(handle, flags);
	if (ret)
		goto err;

	*newhandle = handle;

	kcapi_dolog(KCAPI_LOG_VERBOSE,
		    "new cipher handle from existing handle initialized");

	return 0;

err:
	_kcapi_handle_destroy(handle);
	return ret;
}

int32_t _kcapi_cipher_crypt(struct kcapi_handle *handle, const uint8_t *in,
			    uint32_t inlen, uint8_t *out, uint32_t outlen,
			    int access, int enc)
{
	struct iovec iov;
	int32_t ret = 0;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	/*
	 * Using two syscalls with memcpy is faster than four syscalls
	 * without memcpy below the given threshold.
	 */
	if ((access == KCAPI_ACCESS_HEURISTIC && inlen <= (1<<13)) ||
	    access == KCAPI_ACCESS_SENDMSG) {
		iov.iov_base = (void*)(uintptr_t)in;
		iov.iov_len = inlen;
		ret = _kcapi_common_send_meta(handle, &iov, 1, enc, 0);
		if (0 > ret)
			return ret;
	} else {
		ret = _kcapi_common_send_meta(handle, NULL, 0, enc,
					      inlen ? MSG_MORE : 0);
		if (0 > ret)
			return ret;
		ret = _kcapi_common_vmsplice_chunk(handle, in, inlen, 0);
		if (0 > ret)
			return ret;
	}

	return _kcapi_common_read_data(handle, out, outlen);
}

int32_t _kcapi_cipher_crypt_chunk(struct kcapi_handle *handle,
				  const uint8_t *in, uint32_t inlen,
				  uint8_t *out, uint32_t outlen,
				  int access, int enc)
{
	int32_t totallen = 0;
	uint32_t maxprocess = sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES;
	int32_t ret;

	if (outlen > INT_MAX)
		return -EMSGSIZE;

	while (inlen && outlen) {
		uint32_t inprocess = inlen;
		uint32_t outprocess = outlen;

		/*
		 * We do not check that sysconf(_SC_PAGESIZE) * ALG_MAX_PAGES is
		 * a multiple of blocksize, because we assume that this is
		 * always the case.
		 */
		if (inlen > maxprocess)
			inprocess = maxprocess;
		if (outlen > maxprocess)
			outprocess = maxprocess;

		ret = _kcapi_cipher_crypt(handle, in, inprocess, out,
					  outprocess, access, enc);
		if (ret < 0)
			return ret;

		totallen += inprocess;
		in += inprocess;
		inlen -= inprocess;
		out += ret;
		outlen -= ret;
	}

	return totallen;
}

int32_t _kcapi_cipher_crypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				uint32_t iovlen, int access, int enc)
{
	uint32_t i, outstanding = 0, processed = 0, inflight = 0;
	int32_t ret;

	if (handle->aio.disable == true) {
		kcapi_dolog(KCAPI_LOG_WARN, "AIO support disabled\n");
		return -EOPNOTSUPP;
	}

	/* Every IOVEC is processed as its individual cipher operation. */
	while (iovlen) {
		uint32_t max_process = KCAPI_AIO_CONCURRENT - inflight;
		uint32_t process = (max_process < iovlen) ?
							max_process : iovlen;

		ret = _kcapi_aio_send_iov(handle, iniov, process, access, enc);
		if (ret < 0)
			return ret;

		ret = _kcapi_aio_read_iov(handle, outiov, process);
		if (ret < 0)
			return ret;

		iniov += process;
		outiov += process;
		iovlen -= process;

		inflight = 0;
		for (i = 0; i < KCAPI_AIO_CONCURRENT; i++) {
			if (handle->aio.iocb_ret[i] == AIO_OUTSTANDING) {
				inflight++;
			} else if (handle->aio.iocb_ret[i] < 0) {
				return handle->aio.iocb_ret[i];
			} else {
				if (handle->aio.iocb_ret[i] > INT_MAX)
					return -EOVERFLOW;

				processed += (uint32_t)handle->aio.iocb_ret[i];
				if (processed > INT_MAX)
					return -EOVERFLOW;
				handle->aio.iocb_ret[i] = 0;
			}
		}
	}

	/*
	 * If a multi-staged AIO operation shall be designed, the following
	 * loop needs to be moved to a closing API call. If done so, the
	 * current function could be invoked multiple times to send more data
	 * to the kernel before the closing call requires that all outstanding
	 * requests are to be completed.
	 *
	 * If a multi-staged AIO operation is to be implemented, the issue
	 * is that when submitting a number of requests, the caller is not
	 * able to detect which particular request is completed. Thus, an
	 * "open-ended" multi-staged AIO operation could not be implemented.
	 */
	for (i = 0; i < KCAPI_AIO_CONCURRENT; i++) {
		if (handle->aio.iocb_ret[i] == AIO_OUTSTANDING)
			outstanding++;
	}

	ret = _kcapi_aio_read_all(handle, outstanding, NULL);
	if (ret < 0)
		return ret;

	for (i = 0; i < KCAPI_AIO_CONCURRENT; i++) {
		if (handle->aio.iocb_ret[i] == AIO_OUTSTANDING) {
			return -EBADMSG;
		} else if (handle->aio.iocb_ret[i] < 0) {
			return handle->aio.iocb_ret[i];
		} else {
			if (handle->aio.iocb_ret[i] > INT_MAX)
				return -EOVERFLOW;

			processed += (uint32_t)handle->aio.iocb_ret[i];
			if (processed > INT_MAX)
				return -EOVERFLOW;
			handle->aio.iocb_ret[i] = 0;
		}
	}
	return processed;
}

void __attribute__ ((constructor)) kcapi_library_init(void)
{
	vmsplice_limit = getpagesize() * 16;

	/* Disable the dumping of this process as we handle with keys */
	if (prctl(PR_SET_DUMPABLE, 0) < 0)
		kcapi_dolog(KCAPI_LOG_ERR,
			    "Cannot set prctl(PR_SET_DUMPABLE)");
}
