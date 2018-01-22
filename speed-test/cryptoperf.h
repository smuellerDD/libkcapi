/*
 * Copyright (C) 2015 - 2017, Stephan Mueller <smueller@chronox.de>
 *
 * License: see LICENSE file in root directory
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

#ifndef CRYPTOPERF_H
#define CRYPTOPERF_H

#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "kcapi.h"

#define DRIVER_NAME "cryptoperf"

#if 0
#define dbg(fmt, ...) printf(DRIVER_NAME": " fmt, ##__VA_ARGS__)
#else
#define dbg(fmt, ...)
#endif

/* default execution time for a test in seconds */
#define DFLT_EXECTIME 10

#define SUCCESS 1
#define FAILURE 0

/*
 * Cipher-specific test data
 */
struct rng_def {
	unsigned int blocksize;
	unsigned char *scratchpad;
	size_t inputlen;
	struct kcapi_handle *handle;
};

struct hash_def {
	unsigned int hmac;	/* config option */
	unsigned char *scratchpad;
	size_t inputlen;
	struct kcapi_handle *handle;
};

struct skcipher_def {
	unsigned int keysize;	/* config option */
	unsigned char *scratchpad;
	unsigned char *iv;
	size_t inputlen;
	unsigned int aio, iiv;
	struct iovec *iovec;
	struct iovec *iviovec;
	struct kcapi_handle *handle;
};

struct aead_def {
	unsigned int keysize;	/* config option */
	unsigned char *input;
	unsigned char *output;
	unsigned char *iv;
	size_t indatalen;
	size_t outdatalen;
	size_t assoclen;
	unsigned int aio;
	struct iovec *iniov;
	struct iovec *outiov;
	struct kcapi_handle *handle;
};

/*
 * Test result data
 */
struct cp_res {
	uint64_t rounds;
	uint64_t processed_bytes;
	uint64_t totaltime;
	unsigned int byteperop;
	size_t chunksize;
};

/*
 * Test case definition
 */
struct cp_test;
struct cp_test {
	char *testname;
	char *driver_name;
	char *type;
	int accesstype;
	int enc;
	unsigned int exectime;
	struct cp_res results;
	int (*init_test)(struct cp_test *test, size_t len, unsigned int aio,
			 unsigned int iiv);
	unsigned int (*exec_test)(struct cp_test *test);
	void (*fini_test)(struct cp_test *test);

	/* information not to be set by user */
	union {
		struct rng_def rng;
		struct skcipher_def skcipher;
		struct aead_def aead;
		struct hash_def hash;
	} u;
};

static inline uint64_t cp_ts2u64(struct timespec *ts)
{
	uint64_t upper = ts->tv_sec;

	upper = upper << 32;
	return (upper | ts->tv_nsec);
}

/*
 * This is x86 specific to reduce the CPU jitter
 */
static inline void cp_cpusetup(void)
{
#ifdef __X8664___
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
	asm volatile("cpuid"::"a" (0), "c" (0): "memory");
#endif
}

static inline void cp_get_nstime(struct timespec *ts)
{
	clock_gettime(CLOCK_REALTIME, ts);
}

static inline void cp_start_time(struct timespec *ts)
{
	cp_cpusetup();
	cp_get_nstime(ts);
}

static inline void cp_end_time(struct timespec *ts)
{
	cp_get_nstime(ts);
}

static inline void *cp_zalloc(size_t len)
{
	return calloc(1, len);
}
static inline void cp_zfree(void *ptr, unsigned int len)
{
	memset(ptr, 0, len);
	free(ptr);
}

/*
 * general functions
 */
char *cp_print_status(struct cp_test *test, int raw);
int cp_exec_test(struct cp_test *test, unsigned int exectime, size_t len,
		 unsigned int aio, unsigned int iiv);
int cp_read_random(unsigned char *buf, size_t buflen);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/* test invocations */
void cp_hash_register(struct cp_test **hash_test, size_t *entries);
void cp_rng_register(struct cp_test **rng_test, size_t *entries);
void cp_skcipher_register(struct cp_test **skcipher_test, size_t *entries);
void cp_aead_register(struct cp_test **aead_test, size_t *entries);
#endif /* CRYPTOPERF_H */
