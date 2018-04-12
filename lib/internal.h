/*
 * Copyright (C) 2016 - 2018, Stephan Mueller <smueller@chronox.de>
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

#ifndef INTERNAL_H
#define INTERNAL_H

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdio.h>

#include <linux/if_alg.h>

#include "atomic.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* remove once in if_alg.h */
#ifndef ALG_SET_AEAD_ASSOCLEN
#define ALG_SET_AEAD_ASSOCLEN		4
#endif
#ifndef ALG_SET_AEAD_AUTHSIZE
#define ALG_SET_AEAD_AUTHSIZE		5
#endif
#ifndef ALG_SET_PUBKEY
#define ALG_SET_PUBKEY			6
#endif
#ifndef ALG_SET_DH_PARAMETERS
#define ALG_SET_DH_PARAMETERS		7
#endif
#ifndef ALG_SET_ECDH_CURVE
#define ALG_SET_ECDH_CURVE		8
#endif


#ifndef ALG_OP_SIGN
#define ALG_OP_SIGN			2
#endif
#ifndef ALG_OP_VERIFY
#define ALG_OP_VERIFY			3
#endif

#ifndef ALG_OP_KEYGEN
#define ALG_OP_KEYGEN			4
#endif
#ifndef ALG_OP_SSGEN
#define ALG_OP_SSGEN			5
#endif

/* remove once in socket.h */
#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif

/* make sure that is equal to include/crypto/if_alg.h */
#ifndef ALG_MAX_PAGES
#define ALG_MAX_PAGES 16
#endif

/************************************************************
 * Declarations for opaque data structures
 ************************************************************/

/* Boolean variable */
enum { false, true };
typedef _Bool bool;

enum kcapi_cipher_type {
	KCAPI_CIPHER_SKCIPHER,
	KCAPI_CIPHER_AEAD,
	KCAPI_CIPHER_KDF,
	KCAPI_CIPHER_RNG,
	KCAPI_CIPHER_MD,
	KCAPI_CIPHER_KPP,
	KCAPI_CIPHER_AKCIPHER,
};

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
	enum kcapi_cipher_type cipher_type;
	/* generic */
	uint32_t blocksize;
	uint32_t ivsize;
	/* hash */
	uint32_t hash_digestsize;
	/* blkcipher */
	uint32_t blk_min_keysize;
	uint32_t blk_max_keysize;
	/* aead */
	uint32_t aead_maxauthsize;
	/* rng */
	uint32_t rng_seedsize;
};

/**
 * Common data required for symmetric and AEAD ciphers
 * @iv: IV with length of kcapi_cipher_info->ivsize - input
 */
struct kcapi_cipher_data {
	const uint8_t *iv;
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
	uint32_t datalen;
	uint32_t assoclen;
	uint32_t taglen;
	uint8_t *data;
	uint8_t *assoc;
	uint8_t *tag;
};

/*
 * This value sets the maximum number of concurrent AIO operations we support.
 * This value can be changed as needed. However, note that the memory
 * consumption of one cipher handle increases proportionally to this value. This
 * means that during the _init API call processing, memory corresponding with
 * this number must be allocated regardless whether it is used later on or not.
 *
 * If the caller supplies more IOVECs to be processed in parallel than this
 * value, the libkcapi code below segments the the provided input data
 * into IOVEC chunks of KCAPI_AIO_CONCURRENT size. Thus, the calling user
 * will not see any difference when this value changes other than the
 * performance impact during _init (the larger the value, the slower the
 * _init processing) and later on during the cipher operations (the larger
 * the value, the more parallel cipher operations are supported).
 */
#define KCAPI_AIO_CONCURRENT	64

/**
 * AIO related data structure to hold all information for AIO
 * @skcipher_aio_disable: AIO support for symmetric ciphers not present
 * @efd: event file descriptor
 * @aio_ctx: AIO context to use for AIO syscalls
 * @iocb_ret: return code of each iocb request - set to AIO_OUTSTANDING until
 *	      a return code is obtained
 * @cio: Active concurrent IOCBs
 */
#define AIO_OUTSTANDING	((__s64)-(1<<13))
struct kcapi_aio {
	bool disable;
	int efd;
	aio_context_t aio_ctx;
	__s64 *iocb_ret;
	struct iocb *cio;
	struct iocb **ciopp;
};

struct kcapi_flags {
	/*
	 * A flag to distinguish the new AEAD interface introduced with 4.9.0 to
	 * only require a tag if it is required as input or output.
	 *
	 * Also, kernels before 4.9.0 misbehave when no data is sent for hashing.
	 */
	bool ge_v4_9;

	/* AF_ALG interfaces changed to process more pages concurrently. */
	uint32_t alg_max_pages;
};

struct kcapi_sys {
	unsigned long kernel_maj, kernel_minor, kernel_patchlevel;
};

/**
 * Kernel crypto API TFM representation - The entries are static after
 * initialization.
 * @tfmfd: Socket descriptor for AF_ALG
 * @sysinfo: System information
 * @info: properties of ciphers
 * @refcnt: reference counter of data structure
 */
struct kcapi_handle_tfm {
	int tfmfd;
	struct kcapi_sys sysinfo;
	struct kcapi_cipher_info info;
	atomic_t refcnt;
};

/**
 * Cipher handle
 * @tfm: kernel crypto API TFM
 * @opfd: FD to open kernel crypto API TFM
 * @pipes: vmplice/splice pipe pair
 * @processed_sg: number of scatter/gather entries sent to the kernel
 * @ciper: Common data for all ciphers
 * @aead: AEAD cipher specific data
 * @aio: AIO information
 */
struct kcapi_handle {
	struct kcapi_handle_tfm *tfm;
	int pipes[2];
	int opfd;
	uint32_t processed_sg;
	struct kcapi_cipher_data cipher;
	struct kcapi_aead_data aead;
	struct kcapi_aio aio;
	struct kcapi_flags flags;
};

/************************************************************
 * Declarations for internal functions
 ************************************************************/

extern int kcapi_verbosity_level;
void kcapi_dolog(int severity, const char *fmt, ...);

static inline int *_kcapi_get_opfd(struct kcapi_handle *handle)
{
	return &handle->opfd;
}

int32_t _kcapi_common_send_meta(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen,
				uint32_t enc, uint32_t flags);
int32_t _kcapi_common_vmsplice_iov(struct kcapi_handle *handle,
				   struct iovec *iov, unsigned long iovlen,
				   uint32_t flags);
int32_t _kcapi_common_send_data(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen,
				uint32_t flags);
int32_t _kcapi_common_recv_data(struct kcapi_handle *handle,
				struct iovec *iov, uint32_t iovlen);
int32_t _kcapi_common_read_data(struct kcapi_handle *handle,
				uint8_t *out, uint32_t outlen);
int _kcapi_common_accept(struct kcapi_handle *handle);
int _kcapi_common_close(struct kcapi_handle *handle);
int32_t _kcapi_common_vmsplice_chunk(struct kcapi_handle *handle,
				     const uint8_t *in, uint32_t inlen,
				     uint32_t flags);
int _kcapi_handle_init(struct kcapi_handle **caller, const char *type,
		       const char *ciphername, uint32_t flags);
void _kcapi_handle_destroy(struct kcapi_handle *handle);
int _kcapi_common_setkey(struct kcapi_handle *handle, const uint8_t *key,
			 uint32_t keylen);
int32_t _kcapi_cipher_crypt(struct kcapi_handle *handle, const uint8_t *in,
			    uint32_t inlen, uint8_t *out, uint32_t outlen,
			    int access, int enc);
int32_t _kcapi_cipher_crypt_chunk(struct kcapi_handle *handle,
				  const uint8_t *in, uint32_t inlen,
				  uint8_t *out, uint32_t outlen,
				  int access, int enc);
int32_t _kcapi_cipher_crypt_aio(struct kcapi_handle *handle,
				struct iovec *iniov, struct iovec *outiov,
				uint32_t iovlen, int access, int enc);
int _kcapi_aio_send_iov(struct kcapi_handle *handle, struct iovec *iov,
			uint32_t iovlen, int access, int enc);

int _kcapi_aio_read_iov(struct kcapi_handle *handle,
			struct iovec *iov, uint32_t iovlen);
int32_t _kcapi_aio_read_all(struct kcapi_handle *handle, uint32_t toread,
			    struct timespec *timeout);

/************************************************************
 * Declarations for system calls
 ************************************************************/

static inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static inline int io_submit(aio_context_t ctx, long n,  struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}

static inline int io_getevents(aio_context_t ctx, long min, long max,
            struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
}

/************************************************************
 * Auxiliary macros
 ************************************************************/

#if __GNUC__ >= 4
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
#else
# define DSO_PUBLIC
#endif

#ifdef __cplusplus
}
#endif

#endif /* INTERNAL_H */
