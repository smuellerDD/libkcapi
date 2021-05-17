/*
 * Copyright (C) 2014 - 2021, Stephan Mueller <smueller@chronox.de>
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

/* includes for vmsplice tests */
#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <stdint.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <sys/user.h>
#include <time.h>
#include <sys/utsname.h>
#include <linux/random.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif
#include <sys/syscall.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "kcapi.h"

enum type {
	SYM = 1,
	AEAD,
	HASH,
	ASYM,
	KDF_CTR,
	KDF_FB,
	KDF_DPI,
	PBKDF,
	SYM_AIO,
	AEAD_AIO,
	ASYM_AIO,
	KDF_HKDF,
	KPP,
	KPP_AIO,
};

struct kcapi_cavs {
#define CIPHERMAXNAME 63
	char cipher[CIPHERMAXNAME];
	int aligned;
	int timing;
	int enc;
	int type;
	uint8_t *pt;
	size_t ptlen;
	uint8_t *ct;
	size_t ctlen;
	uint8_t *iv;
	uint32_t ivlen;
	uint8_t *key;
	uint32_t keylen;
	uint8_t *pubkey;
	uint32_t pubkeylen;
	uint8_t *assoc;
	size_t assoclen;
	uint8_t *tag;
	uint32_t taglen;
	size_t outlen;
};

static size_t pagesize;

static char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(uint32_t bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/**
 * Convert binary string into hex representation
 * @bin input buffer with binary data
 * @binlen length of bin
 * @hex output buffer to store hex data
 * @hexlen length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const uint8_t *bin, size_t binlen,
		    char *hex, size_t hexlen, int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

/**
 * Allocate sufficient space for hex representation of bin
 * and convert bin into hex
 *
 * Caller must free hex
 * @bin [in] input buffer with bin representation
 * @binlen [in] length of bin
 * @hex [out] return value holding the pointer to the newly allocated buffer
 * @hexlen [out] return value holding the allocated size of hex
 *
 * return: 0 on success, !0 otherwise
 */
int bin2hex_alloc(const uint8_t *bin, uint32_t binlen,
		  char **hex, uint32_t *hexlen)
{
	char *out = NULL;
	uint32_t outlen = 0;

	if (!binlen)
		return -EINVAL;

	outlen = (binlen) * 2;

	out = calloc(1, outlen + 1);
	if (!out)
		return -errno;

	bin2hex(bin, binlen, out, outlen, 0);
	*hex = out;
	*hexlen = outlen;
	return 0;
}

static void bin2print(const uint8_t *bin, size_t binlen)
{
	char *hex;
	size_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	fprintf(stdout, "%s", hex);
	free(hex);
}

static int bin_char(uint8_t hex)
{
	if (48 <= hex && 57 >= hex)
		return (hex - 48);
	if (65 <= hex && 70 >= hex)
		return (hex - 55);
	if (97 <= hex && 102 >= hex)
		return (hex - 87);
	return 0;
}

/**
 * Convert hex representation into binary string
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin output buffer with binary data
 * @binlen length of already allocated bin buffer (should be at least
 *	   half of hexlen -- if not, only a fraction of hexlen is converted)
 */
static void hex2bin(const char *hex, size_t hexlen,
		    uint8_t *bin, size_t binlen)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		bin[i] = (uint8_t)(bin_char((uint8_t)hex[(i*2)]) << 4);
		bin[i] |= (uint8_t)bin_char((uint8_t)hex[((i*2)+1)]);
	}
}

static int hex2bin_m(const char *hex, size_t hexlen,
		     uint8_t **bin, size_t binlen)
{
	uint8_t *buf = NULL;

	if(1 == hexlen) {
		*bin = NULL;
		return 0;
	}

	buf = calloc(1, binlen);
	if (!buf)
		return -ENOMEM;

	hex2bin(hex, hexlen, buf, binlen);
	*bin = buf;
	return 0;
}

static inline void  _get_time(struct timespec *time)
{
	clock_gettime(CLOCK_REALTIME, time);
}

static inline uint64_t _time_delta(struct timespec *start, struct timespec *end)
{
	uint64_t diff;

	if ((end->tv_nsec - start->tv_nsec) < 0) {
		diff = (uint64_t)(end->tv_sec - start->tv_sec - 1) * 1000000000;
		diff += 1000000000 + (uint64_t)(end->tv_nsec - start->tv_nsec);
	} else {
		diff = (uint64_t)(end->tv_sec - start->tv_sec) * 1000000000;
		diff += (uint64_t)(end->tv_nsec - start->tv_nsec);
	}
	return diff;
}

static ssize_t get_random(uint8_t *buf, size_t buflen, unsigned int flags)
{
	ssize_t ret = 0;

	if (buflen > INT_MAX)
		return 1;

	do {
#ifdef HAVE_GETRANDOM
		ret = getrandom(buf, buflen, flags);
#else
# ifdef __NR_getrandom
		ret = (int)syscall(__NR_getrandom, buf, buflen, flags);
# else
		printf("getrandom not available on this platform\n");
		(void)flags; /* avoid unused arg warning */
		return 1;
# endif
#endif
		if (0 < ret) {
			buflen -= (unsigned int)ret;
			buf += ret;
		}
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

	if (buflen == 0)
		return 0;

	return 1;
}

static int fuzz_init_test(unsigned int size)
{
	struct kcapi_handle *handle;
	int ret = 0;
	uint8_t *name = calloc(1, size + 1);

	kcapi_set_verbosity(KCAPI_LOG_NONE);

	if (!name) {
		printf("Allocation of %u bytes failed", size + 1);
		return 1;
	}

	if (get_random(name, size, 0)) {
		printf("get_random call failed\n");
		free(name);
		return 1;
	}

	ret = kcapi_cipher_init(&handle, (char *)name, 0);
	if (!ret) {
		fprintf(stdout, "kcapi_cipher_init: ");
		kcapi_cipher_destroy(handle);
		goto fail;
	}
	ret = kcapi_aead_init(&handle, (char *)name, 0);
	if (!ret) {
		fprintf(stdout, "kcapi_aead_init: ");
		kcapi_cipher_destroy(handle);
		goto fail;
	}
	ret = kcapi_md_init(&handle, (char *)name, 0);
	if (!ret) {
		fprintf(stdout, "kcapi_md_init: ");
		kcapi_cipher_destroy(handle);
		goto fail;
	}
	ret = kcapi_rng_init(&handle, (char *)name, 0);
	if (!ret) {
		fprintf(stdout, "kcapi_rng_init: ");
		kcapi_cipher_destroy(handle);
		goto fail;
	}

	free(name);
	return 0;

fail:
	fprintf(stdout, "allocation success of nonsense string ");
	if (size)
		bin2print(name, size);
	else
		fprintf(stdout, "EMPTY\n");
	free(name);
	return 1;
}

static int fuzz_init(void)
{
	int ret = 0;
	unsigned int i = 0;

	for (i = 0; i < 128; i++)
		ret += fuzz_init_test(i);

	return ret;
}

#define FUZZ_NOKEY	(1<<0UL)
#define FUZZ_NOOUT	(1<<1UL)
#define FUZZ_LESSOUT	(1<<2UL)
#define FUZZ_NOIV	(1<<3UL)
#define FUZZ_NOIN	(1<<4UL)
#define FUZZ_NOAAD	(1<<5UL)
#define FUZZ_NOTAG	(1<<6UL)

/* kcapi -h -x 1 -c "cbc(aes)" -d 10000 */
static int fuzz_cipher(struct kcapi_cavs *cavs_test, unsigned long flags,
		       int enc, int splice)
{
	struct kcapi_handle *handle = NULL;
	uint8_t indata[4096];
	uint8_t outdata[4096];
	unsigned int i;
	int ret = 1;

	if (kcapi_cipher_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		return 1;
	}

	/* Set key */
	if (!(flags & FUZZ_NOKEY)) {
		uint8_t key[512];

		for (i = 0; i < sizeof(key); i++) {
			if (get_random(key, i, 0)) {
				printf("get_random call failed\n");
				goto out;
			}
			kcapi_cipher_setkey(handle, key, i);
		}

		/* Some idiotic value */
		kcapi_cipher_setkey(handle, NULL, 7890);

		if (kcapi_cipher_setkey(handle, key, 16)) {
			printf("Symmetric cipher setkey failed\n");
			goto out;
		}
	}

	for (i = 0; i < sizeof(indata); i++) {
		unsigned int outlen = i;
		uint8_t *out = outdata;
		uint8_t *iv = indata;
		uint8_t *in = indata;

		if (get_random(indata, i, 0)) {
			printf("get_random call failed\n");
			goto out;
		}

		if (flags & FUZZ_LESSOUT)
			outlen = i - 1;

		if (flags & FUZZ_NOOUT)
			out = NULL;

		if (flags & FUZZ_NOIV)
			iv = NULL;

		if (flags & FUZZ_NOIN)
			in = NULL;

		if (enc)
			kcapi_cipher_encrypt(handle, in, i, iv,
					     out, outlen, splice);
		else
			kcapi_cipher_decrypt(handle, in, i, iv,
					     out, outlen, splice);
	}

	ret = 0;

out:
	kcapi_cipher_destroy(handle);
	return ret;
}

/* 
 * kcapi -h -x 2 -c "authenc(hmac(sha1),cbc(aes))" -d 2
 * kcapi -h -x 2 -c "gcm(aes)" -d 100
 */
static int fuzz_aead(struct kcapi_cavs *cavs_test, unsigned long flags,
		     int enc, int splice)
{
	struct kcapi_handle *handle = NULL;
	uint8_t indata[4096];
	uint8_t outdata[4096];
	unsigned int i;
	int ret = 1;

	if (kcapi_aead_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		return 1;
	}

	/* Set key */
	if (!(flags & FUZZ_NOKEY)) {
		uint8_t key[512];

		for (i = 0; i < sizeof(key); i++) {
			if (get_random(key, i, 0)) {
				printf("get_random call failed\n");
				goto out;
			}
			kcapi_aead_setkey(handle, key, i);
		}

		/* Some idiotic value */
		kcapi_aead_setkey(handle, NULL, 5123);

		if (kcapi_aead_setkey(handle, key, 16)) {
			if (!strncmp(cavs_test->cipher, "authenc", 7)) {
				uint16_t k[44 / sizeof(uint16_t)];
				memcpy(k, "\x00\x00\x00\x00\x00\x00\x00\x10"
					  "\x00\x00\x00\x00\x00\x00\x00\x00"
					  "\x00\x00\x00\x00\x00\x00\x00\x00"
					  "\x00\x00\x00\x00\x06\xa9\x21\x40"
					  "\x36\xb8\xa1\x5b\x51\x2e\x03\xd5"
					  "\x34\x12\x00\x06", sizeof(k));
				/* These need to be in machine's endianity: */
				k[0] = 8;
				k[1] = 1;
				if (kcapi_aead_setkey(handle, (uint8_t *)k, sizeof(k))) {
					printf("AEAD setkey failed\n");
					goto out;
				}
			} else {
				printf("AEAD setkey failed\n");
				goto out;
			}
		}
	}

	for (i = 0; i < sizeof(indata); i++) {
		unsigned int outlen = i;
		uint8_t *out = outdata;
		uint8_t *iv = indata;
		uint8_t *in = indata;

		if (get_random(indata, i, 0)) {
			printf("get_random call failed\n");
			goto out;
		}

		if (flags & FUZZ_LESSOUT)
			outlen = i - 1;

		if (flags & FUZZ_NOOUT)
			out = NULL;

		if (flags & FUZZ_NOIV)
			iv = NULL;

		if (flags & FUZZ_NOIN)
			in = NULL;

		if (flags & FUZZ_NOAAD)
			kcapi_aead_setassoclen(handle, 0);
		else
			kcapi_aead_setassoclen(handle, i);

		if (flags & FUZZ_NOTAG)
			kcapi_aead_settaglen(handle, 0);
		else
			kcapi_aead_settaglen(handle, i);

		if (enc)
			kcapi_aead_encrypt(handle, in, i, iv,
					   out, outlen, splice);
		else
			kcapi_aead_decrypt(handle, in, i, iv,
					   out, outlen, splice);
	}

	ret = 0;

out:
	kcapi_aead_destroy(handle);
	return ret;
}

static int fuzz_tests(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	int ret = 0;
	uint32_t i;

	kcapi_set_verbosity(KCAPI_LOG_NONE);

	for (i = 0; i < loops; i++) {
		if (!cavs_test->type)
			ret += fuzz_init();
		else if (SYM == cavs_test->type) {
			ret += fuzz_cipher(cavs_test, 0, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, 0, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOKEY, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOKEY, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_LESSOUT, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_LESSOUT, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOOUT, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOOUT, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIV, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIV, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIN, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIN, 1, KCAPI_ACCESS_VMSPLICE);

			ret += fuzz_cipher(cavs_test, 0, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, 0, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOKEY, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOKEY, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_LESSOUT, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_LESSOUT, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOOUT, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOOUT, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIV, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIV, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIN, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_cipher(cavs_test, FUZZ_NOIN, 1, KCAPI_ACCESS_SENDMSG);
		} else if (AEAD == cavs_test->type) {
			ret += fuzz_aead(cavs_test, 0, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, 0, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOKEY, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOKEY, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_LESSOUT, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_LESSOUT, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOOUT, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOOUT, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOIV, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOIV, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOIN, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOIN, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOAAD, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOAAD, 1, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOTAG, 0, KCAPI_ACCESS_VMSPLICE);
			ret += fuzz_aead(cavs_test, FUZZ_NOTAG, 1, KCAPI_ACCESS_VMSPLICE);

			ret += fuzz_aead(cavs_test, 0, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, 0, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOKEY, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOKEY, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_LESSOUT, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_LESSOUT, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOOUT, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOOUT, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOIV, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOIV, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOIN, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOIN, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOAAD, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOAAD, 1, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOTAG, 0, KCAPI_ACCESS_SENDMSG);
			ret += fuzz_aead(cavs_test, FUZZ_NOTAG, 1, KCAPI_ACCESS_SENDMSG);
		}
	}

	return ret;
}

static int aux_test_rng(const char *name, uint8_t *seed, uint32_t seedlen)
{
	struct kcapi_handle *handle;
#define RNGOUTBUF 150
	uint8_t outbuf[RNGOUTBUF];
	char hex[RNGOUTBUF * 2 + 1];
	ssize_t ret = 0;

	if (kcapi_rng_init(&handle, name, 0)) {
                printf("Allocation of cipher %s failed\n", name);
                return 1;
        }

	/* invocation of seeding is mandatory even when seed is NuLL */
	ret = kcapi_rng_seed(handle, seed, seedlen);
	if (0 > ret) {
		printf("Failure to seed RNG %d\n", (int)ret);
		kcapi_rng_destroy(handle);
		return 1;
	}

	ret = kcapi_rng_generate(handle, outbuf, RNGOUTBUF);
	if (0 > ret) {
		printf("Failure to generate random numbers %d\n",
		       (int)ret);
		kcapi_rng_destroy(handle);
		return 1;
	}
	if (ret != RNGOUTBUF) {
		printf("RNG only returned %d bytes (requested %d)\n",
		       (int)ret, RNGOUTBUF);
	}
	memset(hex, 0, RNGOUTBUF * 2 + 1);
	bin2hex(outbuf, (size_t)ret, hex, RNGOUTBUF * 2 + 1, 0);
	printf("RNG %s returned: %s\n", name, hex);
	kcapi_rng_destroy(handle);

	return 0;
}

static int is_fips_mode(void)
{
	char c;
	FILE *f = fopen("/proc/sys/crypto/fips_enabled", "r");
	if (!f)
		return 0;
	if (fread(&c, 1, 1, f) < 1)
		c = '0';
	fclose(f);
	return c == '1';
}

static int auxiliary_tests(void)
{
	struct kcapi_handle *handle = NULL;
	const char *ansi_cprng_name = is_fips_mode() ? "fips(ansi_cprng)"
	                                             : "ansi_cprng";
	int ret = 0;

        if (kcapi_aead_init(&handle, "ccm(aes)", 0)) {
                printf("Allocation of ccm(aes) cipher failed\n");
                ret++;
        } else {
		uint32_t iv = kcapi_aead_ivsize(handle);
		uint32_t bs = kcapi_aead_blocksize(handle);
		uint32_t au = kcapi_aead_authsize(handle);
		if (iv == 16 && bs == 1 && au == 16) {
			printf("AEAD obtained information passed\n");
		} else {
			printf("AEAD obtained information failed -- sizes: IV %u BS %u AUTH %u\n", iv, bs, au);
			ret++;
		}
	}
	kcapi_aead_destroy(handle);
	handle = NULL;

        if (kcapi_cipher_init(&handle, "cbc(aes)", 0)) {
                printf("Allocation of cbc(aes) cipher failed\n");
                return 1;
        } else {
		uint32_t iv = kcapi_cipher_ivsize(handle);
		uint32_t bs = kcapi_cipher_blocksize(handle);
		if (iv == 16 && bs == 16) {
			printf("Symmetric cipher obtained information passed\n");
		} else {
			printf("Symmetric cipher obtained information failed --sizes: IV %u BS %u\n", iv, bs);
			ret++;
		}
	}
	kcapi_cipher_destroy(handle);
	handle = NULL;

	if (kcapi_md_init(&handle, "sha256", 0)) {
                printf("Allocation of sha256 cipher failed\n");
                return 1;
        } else {
		uint32_t ds = kcapi_md_digestsize(handle);
		if (ds == 32) {
			printf("Message digest obtained information passed\n");
		} else {
			printf("Message digest obtained information failed -- sizes: digestsize %u\n", ds);
			ret++;
		}
	}
	kcapi_md_destroy(handle);


	if (aux_test_rng("drbg_nopr_hmac_sha256", NULL, 0))
		ret++;
	if (aux_test_rng("drbg_nopr_sha1", NULL, 0))
		ret++;
	if (aux_test_rng("drbg_nopr_ctr_aes256", NULL, 0))
		ret++;

	/* X9.31 RNG must require seed */
	printf("X9.31 missing seeding: ");
	if (!aux_test_rng(ansi_cprng_name, NULL, 0))
		ret++;
	/* X9.31 seed too short */
	printf("X9.31 insufficient seeding: ");
	if (!aux_test_rng(ansi_cprng_name,
			  (uint8_t *)
			  "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
			  "\x00\x01\x02\x03\x04\x05\x06\x07\x08", 16))
		ret++;
	/* X9.31 seed right sized short */
	if (aux_test_rng(ansi_cprng_name,
			 (uint8_t *)
			 "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
			 "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
			 "\x00\x01\x02\x03\x04\x05\x06\x07\x08"
			 "\x00\x01\x02\x03\x04\x05\x06\x07\x08", 32)) {
		printf("Error for %s: kernel module ansi_cprng present?\n",
		       ansi_cprng_name);
		ret++;
	}

	return ret;
}

/************************************************************************
 * CAVS TESTING
 ************************************************************************/

static void usage(void)
{
	char version[30];
	uint32_t ver = kcapi_version();

	memset(version, 0, sizeof(version));
	kcapi_versionstring(version, sizeof(version));

	fprintf(stderr, "\nKernel Crypto API CAVS Test\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-m --aligned\tIf set, AEAD/sym cipher buffers are aligned at PAGE_SIZE\n");
	fprintf(stderr, "\t-e --enc\tIf set, encrypt otherwise decrypt\n");
	fprintf(stderr, "\t-o --operation\tAsymmetric operation:\n");
	fprintf(stderr, "\t\t0 for encryption\n");
	fprintf(stderr, "\t\t1 for decryption\n");
	fprintf(stderr, "\t\t2 for signing\n");
	fprintf(stderr, "\t\t3 for verification\n");
	fprintf(stderr, "\t-c --cipher\tKernel Crypto API cipher name to be used for operation\n");
	fprintf(stderr, "\t-p --pt\t\tPlaintext used during encryption / message digest\n");
	fprintf(stderr, "\t-q --ct\t\tCiphertext used during decryption\n");
	fprintf(stderr, "\t-i --iv\t\tIV used for operation\n");
	fprintf(stderr, "\t-n --nonce\tNonce used for CCM operation\n");
	fprintf(stderr, "\t-k --key\tSymmetric cipher key / HMAC key\n");
	fprintf(stderr, "\t-j --asymkey\tAsymmetric cipher key in BER format\n");
	fprintf(stderr, "\t-a --assoc\tAssociated data used for AEAD cipher\n");
	fprintf(stderr, "\t-l --taglen\tTag length to be produced with AEAD encryption\n");
	fprintf(stderr, "\t-t --tag\tTag to be used for decryption\n");
	fprintf(stderr, "\t-x --ciphertype\tCipher type with one out of the following\n");
	fprintf(stderr, "\t\t1 for symmetric cipher algorithm\n");
	fprintf(stderr, "\t\t2 for AEAD cipher algorithm\n");
	fprintf(stderr, "\t\t3 for message digest and keyed message digest\n");
	fprintf(stderr, "\t\t4 for asymmetric ciphers\n");
	fprintf(stderr, "\t\t5 for counter KDF\n");
	fprintf(stderr, "\t\t6 for feedback KDF\n");
	fprintf(stderr, "\t\t7 for double pipeline KDF\n");
	fprintf(stderr, "\t\t8 for PBKDF\n");
	fprintf(stderr, "\t\t9 for AIO symmetric cipher algorithm\n");
	fprintf(stderr, "\t\t10 for AIO AEAD cipher algorithm\n");
	fprintf(stderr, "\t\t11 for AIO asymmetric cipher algorithm\n");
	fprintf(stderr, "\t-z --aux\tAuxiliary tests of the API\n");
	fprintf(stderr, "\t-s --stream\tUse the stream API\n");
	fprintf(stderr, "\t-y --largeinput\tTest long AD with AEAD cipher\n");
	fprintf(stderr, "\t-d --execloops\tNumber of execution loops\n");
	fprintf(stderr, "\t-v --vmsplice\tUse vmsplice for AEAD oneshot\n");
	fprintf(stderr, "\t-b --outlen\tLength of the data to be generated\n");
	fprintf(stderr, "\t-f --timing\tStart timing measurements for execution duration\n");
	fprintf(stderr, "\t-g --aiofallback\tInvoke AIO fallback\n");
	fprintf(stderr, "\t-h --fuzztest\tInvoke fuzzing tests\n");
	fprintf(stderr, "\t-j --multithreaded\tMultithreaded test\n");
	fprintf(stderr, "\t-u --printaad\tPrint the AAD data after cipher op (AEAD only)\n");
}

/*
 * Encryption command line:
 * $ ./kcapi -x 1 -e -c "cbc(aes)" -k 8d7dd9b0170ce0b5f2f8e1aa768e01e91da8bfc67fd486d081b28254c99eb423 -i 7fbc02ebf5b93322329df9bfccb635af -p 48981da18e4bb9ef7e2e3162d16b1910
 * 8b19050f66582cb7f7e4b6c873819b71
 *
 * Decryption command line:
 * $ ./kcapi -x 1 -c "cbc(aes)" -k 3023b2418ea59a841757dcf07881b3a8def1c97b659a4dad  -i 95aa5b68130be6fcf5cabe7d9f898a41 -q c313c6b50145b69a77b33404cb422598
 * 836de0065f9d6f6a3dd2c53cd17e33a5
 */
static int cavs_sym(struct kcapi_cavs *cavs_test, uint32_t loops,
		    int splice)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	size_t outbuflen = 0;
	ssize_t ret = -EINVAL;
	uint32_t i = 0;
	struct timespec begin, end;
	uint64_t total = 0;

	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
		outbuflen = cavs_test->ptlen;
	} else {
		if (!cavs_test->ctlen)
			return -EINVAL;
		outbuflen = cavs_test->ctlen;
	}
	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, outbuflen))
			goto out;
		memset(outbuf, 0, outbuflen);
	} else {
		outbuf = calloc(1, outbuflen);
		if (!outbuf)
			goto out;
	}

	if (kcapi_cipher_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		goto out;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_cipher_setkey(handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	for (i = 0; i < loops; i++) {
		_get_time(&begin);
		if (cavs_test->enc) {
			ret = kcapi_cipher_encrypt(handle,
					cavs_test->pt, cavs_test->ptlen,
					cavs_test->iv,
					outbuf, outbuflen,
					splice);
		} else {
			ret = kcapi_cipher_decrypt(handle,
					cavs_test->ct, cavs_test->ctlen,
					cavs_test->iv,
					outbuf, outbuflen,
					splice);
		}
		_get_time(&end);

		total += _time_delta(&begin, &end);
		if (0 > ret)  {
			printf("En/Decryption of buffer failed\n");
			goto out;
		}

		bin2print(outbuf, outbuflen);
		printf("\n");
	}

	if (cavs_test->timing)
		printf("duration %lu\n", (unsigned long)total);

	ret = 0;

out:
	kcapi_cipher_destroy(handle);
	if (outbuf)
		free(outbuf);
	return (int)ret;
}

static void mt_sym_writer(struct kcapi_handle *handle, struct iovec *iov,
			  int forking, int last)
{
	ssize_t ret;

	if (forking) {
		pid_t pid;

		pid = fork();
		if (pid)
			/* parent - return and continue */
			return;
	}

	if (last)
		ret = kcapi_cipher_stream_update_last(handle, iov, 1);
	else
		ret = kcapi_cipher_stream_update(handle, iov, 1);
	if (0 > ret)
		printf("Sending of data failed\n");

	if (forking)
		_exit(0);
}

static int cavs_sym_stream(struct kcapi_cavs *cavs_test, uint32_t loops,
			   int forking)
{
	struct kcapi_handle *handle = NULL;
	struct kcapi_handle *handle2 = NULL;
	struct kcapi_handle *handle_ptr;
	ssize_t ret = -ENOMEM;
	uint8_t *outbuf = NULL;
	uint8_t *outbuf2 = NULL;
	uint8_t *outbuf_ptr;
	size_t outbuflen = 0;
	struct iovec outiov;
	struct iovec iov;
	size_t i = 0;
	int wstatus;

	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
		outbuflen = cavs_test->ptlen;
	} else {
		if (!cavs_test->ctlen)
			return -EINVAL;
		outbuflen = cavs_test->ctlen;
	}
	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, outbuflen))
			goto out;
		memset(outbuf, 0, outbuflen);
		if (posix_memalign((void *)&outbuf2, pagesize, outbuflen))
			goto out;
		memset(outbuf2, 0, outbuflen);
	} else {
		outbuf = calloc(1, outbuflen);
		if (!outbuf)
			goto out;
		outbuf2 = calloc(1, outbuflen);
		if (!outbuf2)
			goto out;
	}

	ret = -EINVAL;
	if (kcapi_cipher_init(&handle2, cavs_test->cipher, 0)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		ret = -EINVAL;
		goto out;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_cipher_setkey(handle2, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	/* Test multiple opfds. */
	ret = kcapi_handle_reinit(&handle, handle2, 0);
	if (ret < 0) {
		printf("Re-initialization of cipher failed\n");
		goto out;
	}

	if (cavs_test->enc)
		ret = kcapi_cipher_stream_init_enc(handle, cavs_test->iv,
						   NULL, 0);
	else
		ret = kcapi_cipher_stream_init_dec(handle, cavs_test->iv,
						   NULL, 0);
	if (0 > ret)  {
		printf("Initialization of cipher buffer failed\n");
		goto out;
	}

	if (cavs_test->enc)
		ret = kcapi_cipher_stream_init_enc(handle2, cavs_test->iv,
						   NULL, 0);
	else
		ret = kcapi_cipher_stream_init_dec(handle2, cavs_test->iv,
						   NULL, 0);
	if (0 > ret)  {
		printf("Initialization of cipher buffer failed\n");
		goto out;
	}

	handle_ptr = handle;
	outbuf_ptr = outbuf;
	for (i = 0; i < loops * 2; i++) {
		size_t outptr = 0;

		if (cavs_test->enc) {
			iov.iov_base = cavs_test->pt;
			iov.iov_len = cavs_test->ptlen;
		} else {
			iov.iov_base = cavs_test->ct;
			iov.iov_len = cavs_test->ctlen;
		}

		mt_sym_writer(handle_ptr, &iov, forking, i == (loops * 2 - 1));

		outiov.iov_base = outbuf_ptr;
		outiov.iov_len = outbuflen;
		while (outptr < outbuflen) {
			ret = kcapi_cipher_stream_op(handle_ptr, &outiov, 1);
			if (0 > ret) {
				printf("Finalization and cipher operation failed\n");
				goto out;
			}

			outiov.iov_base = (uint8_t *)outiov.iov_base + ret;
			outiov.iov_len -= (size_t)ret;
			outptr += (size_t)ret;
		}

		if (handle_ptr == handle) {
			bin2print(outbuf, outbuflen);
			printf("\n");
			handle_ptr = handle2;
			outbuf_ptr = outbuf2;
		} else {
			/* compare 2nd opfd results with first results */
			if (memcmp(outbuf, outbuf2, outbuflen)) {
				printf("Two concurrent opfd operations are not identical\n");
				printf("First opfd result: ");
				bin2print(outbuf, outbuflen);
				printf("\nSecond opfd result: ");
				bin2print(outbuf2, outbuflen);
				printf("\n");
			}
			handle_ptr = handle;
			outbuf_ptr = outbuf;
		}
	}

	if (forking)
		wait(&wstatus);

	ret = 0;
out:
	kcapi_cipher_destroy(handle);
	kcapi_cipher_destroy(handle2);
	if (outbuf)
		free(outbuf);
	if (outbuf2)
		free(outbuf2);

	return (int)ret;
}

static int cavs_sym_aio(struct kcapi_cavs *cavs_test, uint32_t loops,
			int splice, int aiofallback)
{
	struct kcapi_handle *handle = NULL;
	ssize_t ret = -ENOMEM;
	uint8_t *outbuf = NULL;
	size_t outbuflen = 0;
	struct iovec *iov = NULL;
	struct iovec *iov_p;
	size_t i;
	struct timespec begin, end;

	if (!loops)
		return -EINVAL;

	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
		outbuflen = cavs_test->ptlen * loops;
	} else {
		if (!cavs_test->ctlen)
			return -EINVAL;
		outbuflen = cavs_test->ctlen * loops;
	}

	iov = calloc(1, loops * sizeof(struct iovec));
	if (!iov)
		return -ENOMEM;

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, outbuflen))
			goto out;
		memset(outbuf, 0, outbuflen);
	} else {
		outbuf = calloc(1, outbuflen);
		if (!outbuf)
			goto out;
	}

	iov_p = iov;
	for (i = 0; i < loops; i++) {
		if (cavs_test->enc) {
			memcpy(outbuf + (i * cavs_test->ptlen), cavs_test->pt,
			       cavs_test->ptlen);
			iov_p->iov_base = outbuf + (i * cavs_test->ptlen);
			iov_p->iov_len = cavs_test->ptlen;
		} else {
			memcpy(outbuf + (i * cavs_test->ctlen), cavs_test->ct,
			       cavs_test->ctlen);
			iov_p->iov_base = outbuf + (i * cavs_test->ctlen);
			iov_p->iov_len = cavs_test->ctlen;
		}
		iov_p++;
	}

	ret = -EINVAL;
	if (kcapi_cipher_init(&handle, cavs_test->cipher,
			      aiofallback ? 0 : KCAPI_INIT_AIO)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		ret = -EINVAL;
		goto out;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_cipher_setkey(handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	_get_time(&begin);
	if (cavs_test->enc)
		ret = kcapi_cipher_encrypt_aio(handle, iov, iov, loops,
					       cavs_test->iv, splice);
	else
		ret = kcapi_cipher_decrypt_aio(handle, iov, iov, loops,
					       cavs_test->iv, splice);
	_get_time(&end);
	if (0 > ret)  {
		printf("En/Decryption of buffer failed\n");
		goto out;
	}

	bin2print(outbuf, outbuflen);
	printf("\n");

	if (cavs_test->timing)
		printf("duration %lu\n", (unsigned long)_time_delta(&begin, &end));

	ret = 0;
out:
	kcapi_cipher_destroy(handle);
	if (outbuf)
		free(outbuf);
	if (iov)
		free(iov);

	return (int)ret;
}

/*
 * Encryption command line:
 * $ ./kcapi -x 2 -e -c "gcm(aes)" -p 89154d0d4129d322e4487bafaa4f6b46 -k c0ece3e63198af382b5603331cc23fa8 -i 7e489b83622e7228314d878d -a afcd7202d621e06ca53b70c2bdff7fb2 -l 16
 * f4a3eacfbdadd3b1a17117b1d67ffc1f1e21efbbc6d83724a8c296e3bb8cda0c
 *
 * Decryption passed command line:
 * $ ./kcapi -x 2 -c "gcm(aes)" -q 0c14372e4567a02d23b58f0afc51a746 -t 04ae740ef1135ee596b7c91e2288eace -i 9fbd7193277f65600f7348ca -k 97de3c9d2b0676104decbd6e8cf6fe80 -a 1a02d783682f87300b9d342f3afbb31e
 * e8703b9b5ef5b454e295a4bae44c7e62
 *
 * ./kcapi -x 2 -c "ccm(aes)" -q 4edb58e8d5eb6bc711c43a6f3693daebde2e5524f1b55297abb29f003236e43d -t a7877c99 -n 674742abd0f5ba -k 2861fd0253705d7875c95ba8a53171b4 -a fb7bc304a3909e66e2e0c5ef952712dd884ce3e7324171369f2c5db1adc48c7d
 * 8dd351509dcf1df9c33987fb31cd708dd60d65d3d4e1baa53581d891d994d723
 *
 * Decryption EBADMSG command line:
 * $ ./kcapi -x 2 -c "gcm(aes)" -q 0fe37040e9b72b2dfc5e9191c2b15681 -t 273021cc6e39f0f8088f48d7ce70fef8 -i 917b8b25ad6e90b7f93b345f -k 8cc6fa539b219221c786b875aa89e4c1 -a 22584d1db91f9f3d3e7308da86228153
 * EBADMSG
 *
 * $ ./kcapi -x 2 -c "ccm(aes)" -q db5fce3f4ba0ac878b8f18733d7f1a6a1c8c8396667c5235c307e874f5783087 -t 38a263cd -n 99a789af090798 -k 2861fd0253705d7875c95ba8a53171b4 -a 34b7ab892c3f06e0305693ffc5ff9d1238e57241e091c584a3df51b9bbb3bff4
 * EBADMSG
 *
 * $ ./kcapi -x 2 -e -c "authenc(hmac(sha1),cbc(aes))" -p 53696e676c6520626c6f636b206d7367 -k  0800010000000010000000000000000000000000000000000000000006a9214036b8a15b512e03d534120006 -i 3dafba429d9eb430b422da802c9fac41 -a 3dafba429d9eb430b422da802c9fac41 -l 20
 * e353779c1079aeb82708942dbe77181a1b13cbaf895ee12c13c52ea3cceddcb50371a206
 */
static int cavs_aead(struct kcapi_cavs *cavs_test, uint32_t loops,
		     int splice, int printaad)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	size_t outbuflen = 0;
	uint8_t *inbuf = NULL;
	size_t inbuflen = 0;
	size_t fullbuflen = 0;
	ssize_t ret = -ENOMEM;
	uint8_t *newiv = NULL;
	uint32_t newivlen = 0;
	int errsv = 0;
	size_t i = 0;

	uint8_t *assoc = NULL, *data = NULL, *tag = NULL;
	size_t assoclen = 0, datalen = 0, taglen = 0;
	uint8_t *i_assoc = NULL, *i_data = NULL, *i_tag = NULL;
	size_t i_assoclen = 0, i_datalen = 0, i_taglen = 0;

	struct timespec begin, end;
	uint64_t total = 0;

	if (!cavs_test->ivlen || !cavs_test->iv)
		return -EINVAL;

	ret = -EINVAL;
	if (kcapi_aead_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of cipher failed\n");
		return -EFAULT;
	}

	/* Setting the tag length */
	if (kcapi_aead_settaglen(handle, cavs_test->taglen)) {
		printf("Setting of authentication tag length failed\n");
		goto out;
	}
	kcapi_aead_setassoclen(handle, cavs_test->assoclen);

	/* set IV */
	ret = kcapi_pad_iv(handle, cavs_test->iv, cavs_test->ivlen,
			   &newiv, &newivlen);
	if (ret)
		goto out;

	ret = -ENOMEM;
	if (cavs_test->enc)
		outbuflen = kcapi_aead_outbuflen_enc(handle, cavs_test->ptlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);
	else
		outbuflen = kcapi_aead_outbuflen_dec(handle, cavs_test->ctlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);

	if (cavs_test->enc)
		inbuflen = kcapi_aead_inbuflen_enc(handle, cavs_test->ptlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);
	else
		inbuflen = kcapi_aead_inbuflen_dec(handle, cavs_test->ctlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);

	/* 
	 * For the splice operation, this test performs a special memory
	 * structure test to invoke all kernel code paths available.
	 * This special handling is not needed for regular operation
	 * though.
	 */
	if (splice)
		fullbuflen = cavs_test->assoclen + cavs_test->taglen +
			     ((cavs_test->enc) ? cavs_test->ptlen : cavs_test->ctlen);
	else
		fullbuflen = (inbuflen > outbuflen) ? inbuflen : outbuflen;

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&inbuf, pagesize, fullbuflen))
			goto out;
		memset(inbuf, 0, fullbuflen);
	} else {
		inbuf = calloc(1, fullbuflen);
		if (!inbuf)
			goto out;
	}

	/* in-place cipher operation */
	outbuf = inbuf;

	kcapi_aead_getdata_output(handle, outbuf, outbuflen, cavs_test->enc,
				  &assoc, &assoclen, &data, &datalen,
				  &tag, &taglen);
	kcapi_aead_getdata_input(handle, inbuf, inbuflen, cavs_test->enc,
				 &i_assoc, &i_assoclen, &i_data, &i_datalen,
				 &i_tag, &i_taglen);

	/* 
	 * place CT where PT was: With the old kernel, AAD is seeked forward
	 * during output (assoclen != 0). With the new kernel, the AAD seek
	 * is removed (assoclen == 0) which is the indicator that the output
	 * buffer must be moved backwards.
	 */
	if (splice && !assoclen) {
		outbuf += i_assoclen;
		data += i_assoclen;
		tag += i_assoclen;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_aead_setkey(handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	for (i = 0; i < loops; i++) {
		memcpy(i_assoc, cavs_test->assoc, i_assoclen);
		if (cavs_test->enc) {
			memcpy(i_data, cavs_test->pt, i_datalen);
			_get_time(&begin);
			ret = kcapi_aead_encrypt(handle, inbuf, inbuflen,
						newiv,
						outbuf, outbuflen,
						splice);
			errsv = errno;
			_get_time(&end);
		} else {
			memcpy(i_data, cavs_test->ct, i_datalen);
			memcpy(i_tag, cavs_test->tag, i_taglen);
			_get_time(&begin);
			ret = kcapi_aead_decrypt(handle,
				 inbuf, inbuflen,
				 newiv,
				 outbuf, outbuflen,
				 splice);
			errsv = errno;
			_get_time(&end);
		}

		total += _time_delta(&begin, &end);
		if (0 > ret && EBADMSG != errsv) {
			printf("Cipher operation of buffer failed: %d %zd\n",
			       errno, ret);
			goto out;
		}

		if (EBADMSG == errsv) {
			printf("EBADMSG\n");
		} else if ((uint32_t)ret != outbuflen) {
			printf("Received data length %zd does not match expected length %zu\n", ret, outbuflen);
		} else {
			if (printaad && assoc && assoclen)
				bin2print(assoc, assoclen);
			bin2print(data, datalen);

			if (tag && taglen) 
				bin2print(tag, taglen);
			printf("\n");
		}
	}

	if (cavs_test->timing)
		printf("duration %lu\n", (unsigned long)total);

	ret = 0;

out:
	kcapi_aead_destroy(handle);
	if (newiv)
		free(newiv);
	if (inbuf)
		free(inbuf);
	return (int)ret;
}

static int cavs_aead_aio(struct kcapi_cavs *cavs_test, uint32_t loops,
			 int splice, int printaad, int aiofallback)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	size_t outbuflen = 0;
	uint8_t *inbuf = NULL;
	size_t inbuflen = 0;
	size_t maxbuflen = 0;
	ssize_t ret = -ENOMEM;
	uint8_t *newiv = NULL;
	uint32_t newivlen = 0;
	size_t i = 0;

	uint8_t *assoc = NULL, *data = NULL, *tag = NULL;
	size_t assoclen = 0, datalen = 0, taglen = 0;
	uint8_t *i_assoc = NULL, *i_data = NULL, *i_tag = NULL;
	size_t i_assoclen = 0, i_datalen = 0, i_taglen = 0;

	struct timespec begin, end;
	struct iovec *iniov = NULL;
	struct iovec *iniov_p;
	struct iovec *outiov = NULL;
	struct iovec *outiov_p;

	if (!cavs_test->ivlen || !cavs_test->iv)
		return -EINVAL;

	if (!loops)
		return -EINVAL;

	iniov = calloc(1, loops * sizeof(struct iovec));
	if (!iniov)
		return -ENOMEM;
	outiov = calloc(1, loops * sizeof(struct iovec));
	if (!outiov) {
		ret = -ENOMEM;
		goto out;
	}

	ret = -EINVAL;
	if (kcapi_aead_init(&handle, cavs_test->cipher,
			    aiofallback ? 0 :KCAPI_INIT_AIO)) {
		printf("Allocation of cipher failed\n");
		goto out;
	}

	/* Setting the tag length */
	if (kcapi_aead_settaglen(handle, cavs_test->taglen)) {
		printf("Setting of authentication tag length failed\n");
		goto out;
	}
	kcapi_aead_setassoclen(handle, cavs_test->assoclen);

	/* set IV */
	ret = kcapi_pad_iv(handle, cavs_test->iv, cavs_test->ivlen,
			   &newiv, &newivlen);
	if (ret)
		goto out;

	ret = -ENOMEM;
	if (cavs_test->enc)
		outbuflen = kcapi_aead_outbuflen_enc(handle, cavs_test->ptlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);
	else
		outbuflen = kcapi_aead_outbuflen_dec(handle, cavs_test->ctlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);

	if (cavs_test->enc)
		inbuflen = kcapi_aead_inbuflen_enc(handle, cavs_test->ptlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);
	else
		inbuflen = kcapi_aead_inbuflen_dec(handle, cavs_test->ctlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);

	if (splice)
		maxbuflen = cavs_test->assoclen + cavs_test->taglen +
			     ((cavs_test->enc) ? cavs_test->ptlen : cavs_test->ctlen);
	else
		maxbuflen = (inbuflen > outbuflen) ? inbuflen : outbuflen;

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&inbuf, pagesize, loops * maxbuflen))
			goto out;
		memset(inbuf, 0, loops * maxbuflen);
	} else {
		inbuf = calloc(loops, maxbuflen);
		if (!inbuf)
			goto out;
	}

	/* in-place cipher operation */
	outbuf = inbuf;

	kcapi_aead_getdata_output(handle, outbuf, outbuflen, cavs_test->enc,
				  &assoc, &assoclen, &data, &datalen,
				  &tag, &taglen);
	kcapi_aead_getdata_input(handle, inbuf, inbuflen, cavs_test->enc,
				 &i_assoc, &i_assoclen, &i_data, &i_datalen,
				 &i_tag, &i_taglen);

	if (splice && !assoclen) {
		outbuf += i_assoclen;
		data += i_assoclen;
		tag += i_assoclen;
	}

	iniov_p = iniov;
	outiov_p = outiov;
	for (i = 0; i < loops; i++) {
		memcpy(i_assoc + (i * maxbuflen), cavs_test->assoc, i_assoclen);
		if (cavs_test->enc) {
			memcpy(i_data + (i * maxbuflen), cavs_test->pt,
			       i_datalen);
		} else {
			memcpy(i_data + (i * maxbuflen), cavs_test->ct,
			       i_datalen);
			memcpy(i_tag + (i * maxbuflen), cavs_test->tag,
			       i_taglen);
		}
		iniov_p->iov_base = inbuf + (i * maxbuflen);
		iniov_p->iov_len = inbuflen;
		iniov_p++;
		outiov_p->iov_base = outbuf + (i * maxbuflen);
		outiov_p->iov_len = outbuflen;
		outiov_p++;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_aead_setkey(handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	_get_time(&begin);
	if (cavs_test->enc)
		ret = kcapi_aead_encrypt_aio(handle, iniov, outiov, loops,
					     newiv, splice);
	else
		ret = kcapi_aead_decrypt_aio(handle, iniov, outiov, loops,
					     newiv, splice);
	_get_time(&end);

	if (0 > ret && -EBADMSG != ret) {
		printf("Cipher operation of buffer failed: %d %zd\n",
		       errno, ret);
		goto out;
	}

	if (-EBADMSG == ret) {
		printf("EBADMSG\n");
	} else {
		for (i = 0; i < loops; i++) {
			if (printaad && assoc && assoclen)
				bin2print(assoc + (i * maxbuflen), assoclen);
			bin2print(data + (i * maxbuflen), datalen);

			if (tag && taglen) 
				bin2print(tag + (i * maxbuflen), taglen);
		}
		printf("\n");
	}

	if (cavs_test->timing)
		printf("duration %lu\n", (unsigned long)_time_delta(&begin, &end));

	ret = 0;

out:
	kcapi_aead_destroy(handle);
	if (newiv)
		free(newiv);
	if (inbuf)
		free(inbuf);
	if (iniov)
		free(iniov);
	if (outiov)
		free(outiov);
	return (int)ret;
}

static int cavs_aead_stream(struct kcapi_cavs *cavs_test, uint32_t loops,
			    int printaad)
{
	struct kcapi_handle *handle;
	uint8_t *outbuf = NULL;
	size_t outbuflen = 0;
	size_t inbuflen = 0;
	size_t maxbuflen = 0;
	ssize_t ret = -ENOMEM;
	uint8_t *newiv = NULL;
	uint32_t newivlen = 0;
	struct iovec iov;
	struct iovec outiov[16];
	size_t i = 0;

	uint8_t *assoc = NULL, *data = NULL, *tag = NULL;
	size_t assoclen = 0, datalen = 0, taglen = 0;
	size_t i_assoclen = 0, i_datalen = 0, i_taglen = 0;

#if 0
	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
	} else {
		if (!cavs_test->ctlen)
			return -EINVAL;
	}
	if (!cavs_test->taglen || (!cavs_test->enc && !cavs_test->tag)) {
		printf("Missing tag data\n");
		return -EINVAL;
	}
#endif

	if (!cavs_test->ivlen || !cavs_test->iv)
		return -EINVAL;

	ret = -EINVAL;
	if (kcapi_aead_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of cipher failed\n");
		return -EFAULT;
	}

	/* Setting the tag length */
	if (kcapi_aead_settaglen(handle, cavs_test->taglen)) {
		printf("Setting of authentication tag length failed\n");
		goto out;
	}
	kcapi_aead_setassoclen(handle, cavs_test->assoclen);

	ret = -ENOMEM;
	if (cavs_test->enc)
		outbuflen = kcapi_aead_outbuflen_enc(handle, cavs_test->ptlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);
	else
		outbuflen = kcapi_aead_outbuflen_dec(handle, cavs_test->ctlen,
						     cavs_test->assoclen,
						     cavs_test->taglen);

	if (cavs_test->enc)
		inbuflen = kcapi_aead_inbuflen_enc(handle, cavs_test->ptlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);
	else
		inbuflen = kcapi_aead_inbuflen_dec(handle, cavs_test->ctlen,
						   cavs_test->assoclen,
						   cavs_test->taglen);

	maxbuflen = (inbuflen > outbuflen) ? inbuflen : outbuflen;
	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, maxbuflen))
			goto out;
		memset(outbuf, 0, maxbuflen);
	} else {
		outbuf = calloc(1, maxbuflen);
		if (!outbuf)
			goto out;
	}
	kcapi_aead_getdata_output(handle, outbuf, outbuflen, cavs_test->enc,
				  &assoc, &assoclen, &data, &datalen,
				  &tag, &taglen);
	kcapi_aead_getdata_input(handle, NULL, inbuflen, cavs_test->enc,
				 NULL, &i_assoclen, NULL, &i_datalen,
				 NULL, &i_taglen);

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_aead_setkey(handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	/* set IV */
	ret = kcapi_pad_iv(handle, cavs_test->iv, cavs_test->ivlen,
			   &newiv, &newivlen);
	if (ret)
		goto out;

	for (i = 0; i < loops; i++) {
		int errsv = 0;

		memset(outbuf, 0, outbuflen);

		if (cavs_test->enc)
			ret = kcapi_aead_stream_init_enc(handle, newiv, NULL, 0);
		else
			ret = kcapi_aead_stream_init_dec(handle, newiv, NULL, 0);
		if (0 > ret) {
			printf("Initialization of cipher buffer failed\n");
			goto out;
		}


		iov.iov_base = cavs_test->assoc;
		iov.iov_len = cavs_test->assoclen;
		if (cavs_test->enc) {
			struct iovec pttag;

			/*
			 * usually we would send all in one call of
			 * update_last, but here we want to test
			 * the individual calls
			 */
			if (cavs_test->ptlen || i_taglen)
				ret = kcapi_aead_stream_update(handle, &iov, 1);
			else
				ret = kcapi_aead_stream_update_last
							(handle, &iov, 1);
			if (0 > ret) {
				printf("Sending update buffer failed\n");
				goto out;
			}

			if (cavs_test->ptlen) {
				pttag.iov_base = cavs_test->pt;
				pttag.iov_len = cavs_test->ptlen;
				/*
				 * usually we would send all in one call of
				 * update_last, but here we want to test
				 * the individual calls
				 */
				if (i_taglen)
					ret = kcapi_aead_stream_update
							(handle, &pttag, 1);
				else
					ret = kcapi_aead_stream_update_last
							(handle, &pttag, 1);
				if (0 > ret) {
					printf("Sending last update buffer failed\n");
					goto out;
				}
			}

			/* only set the tag if we need to */
			if (i_taglen) {
				pttag.iov_base = tag;
				pttag.iov_len = i_taglen;
				ret = kcapi_aead_stream_update_last(handle,
							            &pttag, 1);
				if (0 > ret) {
					printf("Sending last update buffer failed\n");
					goto out;
				}
			}

			if ((outbuflen - cavs_test->taglen) >= 16) {
				/* test of multiple iovecs */
				outiov[0].iov_base = outbuf;
				outiov[0].iov_len = 1;
				outiov[1].iov_base = outbuf + 1;
				outiov[1].iov_len = 1;
				outiov[2].iov_base = outbuf + 2;
				outiov[2].iov_len = 1;
				outiov[3].iov_base = outbuf + 3;
				outiov[3].iov_len = 1;
				outiov[4].iov_base = outbuf + 4;
				outiov[4].iov_len = 1;
				outiov[5].iov_base = outbuf + 5;
				outiov[5].iov_len = 1;
				outiov[6].iov_base = outbuf + 6;
				outiov[6].iov_len = 1;
				outiov[7].iov_base = outbuf + 7;
				outiov[7].iov_len = 1;
				outiov[8].iov_base = outbuf + 8;
				outiov[8].iov_len = 1;
				outiov[9].iov_base = outbuf + 9;
				outiov[9].iov_len = 1;
				outiov[10].iov_base = outbuf + 10;
				outiov[10].iov_len = 1;
				outiov[11].iov_base = outbuf + 11;
				outiov[11].iov_len = 1;
				outiov[12].iov_base = outbuf + 12;
				outiov[12].iov_len = 1;
				outiov[13].iov_base = outbuf + 13;
				outiov[13].iov_len = 1;
				outiov[14].iov_base = outbuf + 14;
				outiov[14].iov_len = (outbuflen - 14 -
						      cavs_test->taglen);
				outiov[15].iov_base = outbuf +
						(outbuflen - cavs_test->taglen);
				outiov[15].iov_len = cavs_test->taglen;
				ret = kcapi_aead_stream_op(handle, outiov, 16);
			} else {
				outiov[0].iov_base = outbuf;
				outiov[0].iov_len = outbuflen;
				ret = kcapi_aead_stream_op(handle, outiov, 1);
			}
		} else {
			ret = kcapi_aead_stream_update(handle, &iov, 1);
			if (0 > ret) {
				printf("Sending update buffer failed\n");
				goto out;
			}
			/* send ciphertext with intermediary call */
			iov.iov_base = cavs_test->ct;
			iov.iov_len = cavs_test->ctlen;
			ret = kcapi_aead_stream_update(handle, &iov, 1);
			if (0 > ret) {
				printf("Sending update buffer failed\n");
				goto out;
			}
			/* send tag with last send call */
			iov.iov_base = cavs_test->tag;
			iov.iov_len = cavs_test->taglen;
			ret = kcapi_aead_stream_update_last(handle, &iov, 1);
			if (0 > ret) {
				printf("Sending last update buffer failed\n");
				goto out;
			}

			outiov[0].iov_base = outbuf;
			outiov[0].iov_len = outbuflen;
			ret = kcapi_aead_stream_op(handle, outiov, 1);
		}
		errsv = errno;
		if (0 > ret && EBADMSG != errsv) {
			printf("Cipher operation of buffer failed: %d %zd\n",
			       errno, ret);
			goto out;
		}

		if (EBADMSG == errsv) {
			printf("EBADMSG\n");
		} else {
			if (printaad && assoc && assoclen)
				bin2print(assoc, assoclen);
			bin2print(data, datalen);

			if (tag && taglen) 
				bin2print(tag, taglen);
			printf("\n");
		}
	}
	ret = 0;

out:
	kcapi_aead_destroy(handle);
	if (newiv)
		free(newiv);
	if (outbuf)
		free(outbuf);
	return (int)ret;
}

static int cavs_aead_large(int stream, uint32_t loops, int splice)
{
	struct kcapi_cavs test;

	uint8_t *nonce;

	char *key = "8a5220f5aa1b8aaddfa3bdefc91afe7c";
	char *iv = "82b782d0047d840ccfe4387159";
	char *msg = "64f855a85e5a7b8afa05421ebf6f15b50c8fdc23b7f2c670f50c45d07acc5ad5";
	char *aad =
		"fd580146691be45b31ea3f2f444a950d4a92f2a0db4cc36deeddeaa19469120d"
		"fd580146691be45b31ea3f2f444a950d4a92f2a0db4cc36deeddeaa19469120d"
		"fd580146691be45b31ea3f2f444a950d4a92f2a0db4cc36deeddeaa19469120d"
		"fd580146691be45b31ea3f2f444a950d4a92f2a0db4cc36deeddeaa19469120d"
		"e6f1406f3bbeabf39f03cef981bebb19acdfb26479acf2ed4264cf89192205d2"
		"ba054c72bf8e2d9e134913e0a9b0a51a6e4c53c87c1d2f85903cffd1bebf9011"
		"63dd4dd75c530f647505376b24e9fb187821fd514c67223cc0aea101ea065ad1"
		"c8c16a2779d4fc4dad8061235b31641cb2a6d7895152721aba02dea104c10c1a"
		"d1f8cbe980da9a62a4ffba8eb44f882c04220af7f3a6c8276680dd3a76b64df4"
		"66cc99a5d82d91aa40cd6a36980d105356dfbd239b2acb6cad70c753a7aec668"
		"6f83fce3e9958a2d6a3198a37031a49690231996afa724f07519c375ff701f7d"
		"d4661b2c1bda2df40b726d5ba284ebff9a3746d799e57abba8c4fa27e6c6ff3c"
		"7dbd1f07d6c3210609d910e898ce8e955c636b6ebfac76d62cb993f1c4760eab"
		"53d02ffd82190f6c4eaea9d2b8d73460beeeb1e48bc4c048eb40b75b0149f5d5"
		"3ce6749587a49e2cc039629f6c668669a9223fc063f4ff19cba18eee05075cbf"
		"214916574d2c775049c161d91b452cb703453e8ab105db52b6233f313978ea73"
		"eb3f3ccb3d7941dfd090ce072c3acd52b6a0d5cbdcc0fefa930ff3ad036348f8"
		"80110e7abd52a5e23cecd2b2090e1143a87b2d094cea0d194aadd1e8cc921e56"
		"ca07b5eb36814b60771e95611989a291c31e6dcf694eb3b8c245026cfdcb1395"
		"b06859a611ccda61686d3e9cc4722544edd0bea29bb396dde51fadc1fcd7cfbe"
		"197e2134b4fcfbeef723f5ec7293456510da480c4ae05e939a83fb6d337efbd9"
		"ef8f361c89d9550d0c87e4d78bb2a8fb13843294de9eb4dfc9b814fa08873fec"
		"19e4c0e6f62a91c98fe030e77798f60ede16a5c3bfb540cb5a071ff0e5bc4201"
		"7fc5e61b65b95627687704a49f0dd8a759d8c81f55eda95e36b844d531e3ad1f"
		"0979d0423d4c4d318094869569d8f5cc6c12c432090e97a04313ad3354c5274f"
		"9f4aa7e3e6ac1deebd7ede423ec3f788ff0bc08441dfb49a6a5f7f91b62a5998"
		"297e9386c8a16f66087f3533879483e0fa0ce59b6629a55394e6e578bfdaea02"
		"8f5ebbb44bf2eba24addb3f1aa1444de455d5a01e1b415d3a7ee056fd79c8395"
		"b93248f4d76938a969e17f03110bdf89c846483e1848aa238dc007fe6639cc5a"
		"8f4261cfd4ccff834fd3c2f12241ffe96c0fd7d875ad0c4a2ca414add47a6c58"
		"fad52fccaae4e739e2fba344477d4a0717ff2e595faae4506ee1540589240c97"
		"e035da73c17999d20ca04b83e78968eab25f76493e09da3e39c1ee8ded025320"
		"2ba8894c8153bc56b30ce136692b029a2677d62e7990951b778a0acd68dbeafa"
		"c17764e05339f9cec1858ee5372cc020598f77927a08beef0f85d24e6376782d"
		"8cea94b69df4f8411d547a19b853498335ef81fca838fcc3e9fa6c97449ca6c2"
		"72484156c84d60b7afc1cc59546a46cba1df1bf56beaf89eed31003175151cc0"
		"5ddb92493d09da385f13ad2e73375e0184a66d042be45a880371b7a25ca9812f"
		"34e9b01663f30dcd1594441f7d843a2cc88da0b150efc9891304b87463207e18"
		"dfbbc345a1d2a27db98abab4da17815454dcdc8442d3edaa05302c2ef141ba82"
		"4599f25f616d4051333e3675f3b8dc8110db48066a586ff2c13e3b596dd5de75"
		"50ca65eb0a8d904f6bf8e1eb2e31f3bce4d10dbe2e46f76a2f760c7c41a491f9"
		"e798457104fa39814a00e29df4496d0cb8085234f7642c18381fc81fd4767c17"
		"f249ba79b67ce4efb69d6213aec7f37a74c640f12e7bb706c28296cb8e1346d6"
		"5a26eb8c8adb39a0981889d6c2742c0d0054ff7c39533f3cb6e89f06d743983f"
		"05770131e7dedf9cd9b97e6d9a18c1cd44fab65d82b46dc0fd970b5b17cd1a58"
		"dc8423f1354f7feb5fc86a609c7b59c229ff8e1d6f66e99c7dd8014fb67a732b"
		"c7947a53ddf4c096148d743832649df595adae436a305ad820f2a96c1c124cc0"
		"aff12edf45954ba3df50c57cc39c346d714a3e57dadc697acd2f2c39b25d4c1d"
		"7ae1661dd6fcc71da75884b4b6ecc832a61f68e22730bd8c6cd5b23ede221c4c"
		"12ad4a96f8f0dd0956eeda69751afe4d1b74526bb8f5ff15e42d6204092b6355"
		"5d9d03d114383571d35aef2167ee80c5b791247af7f2d61e1f7f65129c3eca3e"
		"45f8b956909d765c06e4ea67f432f6a264bd07974bf1ebae0413e3f0fd24f911"
		"b10893aed6e749d3d7d4f4c084ac07ed0941234b1cb8e5cd7b30032796a597d6"
		"8813ba604cde55dd2e7134b67f255cad8d659f1dd3116d836c1fed3ece884c93"
		"b46256f45c494382f304d3d04e669deada71a396d6c22bd9bf29cabd0c97c252"
		"1c3d8ef36df2baca0ed5f897573471acd7ad593c8e93c6d65c94c22dba989e1a"
		"a8eb8ae4e69f63be672ccc91035a80fc6c61e79a634ee7832ca8fc153f548bf4"
		"40b6734f3119e665e7517748ba9e73e181d47535beb935e615afa1fd03932fe6"
		"cce471bcb528eac8748b2044e5caf264fe4f2c97059e590a00efd86d6e1c32fb"
		"34beabb4da9317edf724ef0beaa4a48ccb1a3347a2c3faf4d6b1caeee8b93d38"
		"608c4abe082416de59620d2733f53261d17db3cdfbf0c1ae7d3d9e07d930f8a7"
		"39967563a7a18fa3808ea220268443ebf6c0d4b27aef553fdfdb7d41a94a0a4f"
		"a523552a1fd3294256efd57c2d1b8033232abd7d858760afe3d38f23c0cf1c38"
		"8d7d129bd9828dc5c2cfcfc5af809140410497b6867f8706706cfb358687d56b"
		"daead33e3b766333ab74b882147c1d1a369689e5e4a0744d70f0eaff643adeef"
		"72b3c09cae765295fb27b73cc3d7cccaec28bc9307b2cf8ccaa5830ac0afdecc"
		"3f20023c9b4c02f29930f47a2659485749025847577d3fc966d4efdd03af7e0b"
		"2878c1a668be1c526dd798c4a4ca36c9376c848a3cc86d0e2cc45500960266b3"
		"140524637f9548be5f64cba2a5f141299dad68e31e5d016204bfdefcdf703dcc"
		"ed0d54fa46982d3c571eb49d91970f7e620e2dda6502a2ced60bb25848c1ab5f"
		"9ad979f3279174d73d4f7c3cd18448d070d7fbf77980f8588af1f89c38bc5a72"
		"03b1bad78846c494f93d4a08cb809527ae50f9c3c29eac0b08b9d951172aef10"
		"10dc3f2dd381c67d73304788e8539e8c04c050c5a92666ec38ab7cfe4cd3153e"
		"a9a4317d6f08229994729b4490c40a065a71278594decd05020f0a2b417f7206"
		"b64fb850c4a37ff0424a6dc42c9d819e98a9a78cec908a5d4f2caa605df6ae6f"
		"1f26fb2c3a1c858b66ffe59122a4ad5ba7b1f8611a0245fc054b852608ff7281"
		"cc71239c393add71e9da2d32dca233456dd1418d84fda5eb0eb4c204aa646645"
		"a578572529c42faab1236a2fc05ebe64d350ab969448523150af8a83abeb31c2"
		"9382c0517283223fa822c71138a2f4c1c1785d06b1adf5d6b5840529745d7b01"
		"7cd985a77c3f5f37b51e6a5eab347d63208f7f6442f236e3247a5a816b81ee08"
		"4ac3d0afb0bf8e9abf617ba181dd0252d6de3b39b1e0bc5f84dab210f92130e1"
		"e389c6f274cd5671b031235f21652b97cdadb70c653f3052bfec34608603e994"
		"317391f7312f5fc36fd78922f5949f39eb441b65c6d739c4bcf809f87bf0c227"
		"1ac8594650ae5298e49bd771643207401aea90cc3c6f80be634658603eb062a4"
		"88d245683712d7f8f7c432d5d6060ab541e83eca2fd1ac479c1e4a21390b7312"
		"62d77ee4502395ec909cc4d5b3d9519f48864ce607c366684fc707c2d3c99a7a"
		"90202c4202a9357b9769b5f964738306160ce2a92c0e5628648ab6cb73b181e3"
		"f9f5750bb46b5eaef4742dc94f9c49f295c22a9a077a238fc3af7fc4838dd055"
		"879d84c6d032b98c8f0553cedd1c4b6cacf04941fece76a5557e8b366a232fd9"
		"21627ffbbdc6ee1d50634f8f76ba307b43dd6a267ad4f673003e02a9903b4475"
		"af8a8f33e3efa46920d84a94833fa12843d2b3d2e4524c00ad390ca35d9fba33"
		"1a5edbf4aa758379e5aa6c666a74457a92174ccca2111f5445b5cfae3916371b"
		"48268cc97a1f35548922dc8c951ec57919f45e9c1ed91878aefb76518c676334"
		"222ac937bbb65f02f288c38e6a08c82dc0b111cbbe71df73d2532715be5be886"
		"90b1bbc8d503ac8c0a2448f553f9f79f70958ce0eca31b4d97040a8037ba6b19"
		"7b05890330cbc1f9b73d9448b7b8fad60fe9f8630f35740fe758491c5f4c97f6"
		"c96c5c7034d94951e31dce0ffe0e78da86f57cdc8ef094c0a99509719fd81124"
		"642f5c984af4ea9c750a1fd38fc319b4be0141d4d39c2068c50475055d2884ab"
		"3296b002d8e34ce3554daf1ad49f866b9e556fd34501c30f22edb26302029694"
		"1de88136486f182e6b2ea56f346a67070d392d5f4ce623beaa98eb10f72fefe6"
		"0c6ff6bd0060f6839ff4295717eb6391f5f4a3025015e87d444c4695a37738a9"
		"e671381e6a7e8decd9e9655ce5eb23103dcffa43b954bb52d853eb7b6da119e5"
		"95376ee1ec90867001537e0507324f8ccd125aaaf06c44474ff3034abf7739a3"
		"0009c18ff0608817ff7b9fdae3888e0d8d05eac05b252a638f75b68800bf41eb"
		"0f2e59afddb43ceabba9ee64e2b5889c65efd30c634615ae81212bbf9742d8c3"
		"aaf05dc91b554af01d25932a6c80e6403d1a3c177099af310d3e8b76eec8a735"
		"b995f666120b59320e36b7b5eab25002fdcc4e67ebe49df31c16fd366c195648"
		"24664b0d2a9d11b67425828bc2136de88d4e31863af08afc94efaa8679fc8c04"
		"d3ab8546cbd51c86393b1b365e6be6fdd5e80cfcc7851c555f12baee7d3af172"
		"afaccb995d791faa43bdab3e24826246bde1074ff96afb0563c754f6e09b2e99"
		"9eb0468f4852c5287cf659297e208acd2e834c093769d0148a55a0270be7eb82"
		"89011daff428b30aca2d4e81d30c06990e1400b1eb48438bba06c70864e6cf33"
		"59e57981c9c3945817a9b1cd8b0f7db247dd4ed07cd0fb71dd20f122546083b6"
		"f4a5828e30ea0e184ab3ab960ef19821bf265ced52c9a1cedaec45fb441caf13"
		"44895f5d8f67c9544b936463c37afeed60375290d5fbdcab99b2ec1d9ae3fa50"
		"30d839774f006e13029103bc1471571e105759426d2e550f02ba0e10c07d0c77"
		"9fdc3762d97ea55e57f5b12968a04dbdb9cf99898229b402fd4bd15a1cb28e8f"
		"7bdb82a894a8153c3206953328cd86d042e839f07cb5a08c72ae6085184a28a1"
		"ab1e41d0e74867b57b0dd861bac1aa6293e761fcc39ac1b6492ce1191a0c81b4"
		"17ed9d633c2443d11a52a13c8744627894173b37bfa0c0876a0b7d9c8cc142d0"
		"a790bee8fa064f99f71d194bf71e561c2dbfec28d88e4508bd935b98d53112fd"
		"434ecbe788b43614fab6671673162d5546269f57772ef73f2b0ea4945d249a44"
		"d370ede950f69e4a0c64b52561f58f2cc7957a4d02467f369ac27f198c6282ac"
		"3f3e4b75b9963044137128012a8326a79854a591e39f84f5f3f815aecab2713e"
		"6f000e132b5a9309f823ea31378897d1a1ab49ab8001af821ff88ddb7fde0f01"
		"4bfe5d4b0e0c6fa1a4c3233defcc8dafcbe28e244334a8e7050a102813ac05fd"
		"bc8061a6cb726e15fe98faaeb916ae4bfc409b8393ff162c8c76c61eeee5fb3a"
		"a8cd41abc855366cedec980aff30a2ac1d0e9950d72ba2579e83d644785198c1"
		"f92e26e36e7c6fae5b0525dc28e012da1795af147980f372227b69221ab78599"
		"95eb38d425b1c2e42f2cc8a99cefa6ded01a0655e0c6b284ffa4a6413ae06aca"
		"664c9e0856bad61551a9a9fbc22505bf32e8c59e74c586961f47b6284295ed5d"
		"5298810767605549a8c4f1590449d885244615749d4518af69abc05f989cb959"
		"43190857c26be4881ec5c84cc925c6388d7b1e61c30d0fd7c51aed6fa6bd74c6"
		"20155c82cda32ddb9af3555b7a7f78e157d007ec4ee614161bda65dfd2c2c7ac"
		"d1d5a410f2d0d8490598c10e7d209588698df99ea698cf7553344f3786715914"
		"3da1098798b98ddb45fa33ed3bd0c633abfa1bfd33ebe7fb5670d3002994d305"
		"4ec1b3712627f3984361d4811c56b3ec055e96935ea705b10ad61bc123f1dc88"
		"eb7cc95506e2b288e717cc51897c03ba5f0391e88d93d09d58ae4c02db511da4"
		"fc1b74bc9fb273b31a6342e5e8085fa6a12f35822978f1c9283f914cbb7b3d61"
		"6ae6db2d595fde22c28c5ec6a2c36eb6b32baaeb9b1e0f3d63d210252a39e5c7"
		"1b2527309cb09adcc8db4a7b2075d9f47d3f17ab4a4dd300efaff1189051bddf"
		"f8207f4dd06e50e915982b8cc9e64768e8b2a4489dcde419b61e5daa568c6cb0"
		"e91f0c0d5d61a752900b2c8204dd6119dace7b4cfe65ec939f677c65e2b29b42"
		"d769f5f7ac51481e207b72e43b24cf0f3cd9c13fd4df907391d175d09d8bf19e"
		"a84763942306da55af32283ad5813852f71ca1a786017ac376a57173efde17cb"
		"46017e6a2b4706002476740d3abd44ebf1df410e7e94528b352c97d74175b4d1"
		"97df6d032dde742566907ee3d1a09ce1146ac9fb235fbfd1b6ab1083f91671b9"
		"852859e78f91cbcf5fc86f4704f1e83c470462f7dd2c6a9fe16d03ff818af68a"
		"f726699cbb29b303f6656fbe3a7acf0471f6348914c1fbfc9eb999d43f99ea4c"
		"d41fc6ac176ed6cb13b1a5d2dc01fa427c89663930e719f1d5d6f9899d0af608"
		"065c979f0d27d92e9ef23a0a504f11fe4f02208f99666c846e0d4da601a7c1c5"
		"742505fb031e6735807156eeff2cbb3ed2ac8c14b8069dbf51a6bab4d536f48b"
		"06c2384a631926e69f761f07515fa00cedcecf4ff38f54aa66e96a3a80803662"
		"a47a571394e1be4be448c0dcafb2696f88af14c8b3c8384c961d85c06a4d3053"
		"36968bdffe3ed86c37315ff67febbe708b988108617af2adc78c32cefb658965"
		"a45efb3509f71c4f817725db2ad34615ded13e96636d2ad5e27c9aed9b8feaa1"
		"d61ad09d1dd631fea86339151932aa686aa274fa236987cdd036e5a4b295fb0d"
		"b512319fa2a1c081963dc32cb3d0927115534bbd0736b19c77023a7ca83d63b4"
		"278e47c4002170de314deda65f74a437c82bea66799b514ac127c1fce550cb9b"
		"15d539939f1eea1f63dadd0d87e88bc26c737a7de0620fe095efa4acd195dacc"
		"68303095e860d54c132ebbe892f2ed1ae774228ba4519265daa00814d5d6394e"
		"06e7545041aeda6b298fb0c0e85b734823730b172c3183e17a8317bd57d98f29"
		"d942cc4e13d1a1868c46e41cf1eac45306bb5ca9e2c9895c5ce0f92ec1678565"
		"c888c117c792d1a4269b7e84146989437a933ec92de34ddf68ffd6ef7948c30b"
		"ba035a31c3b712ceded5a680bc9e69206642d900754576718627d589e944f023"
		"99f9c02671080e0b9c3e86994e530df3b11154d523b8ad1b9ea21e837723b4b3"
		"4cb31a7e384f6a63481c4356334e1cc44548d8d19d049ae498b6da658dacb9c5"
		"bb7991bf7f52d1decbb80840d3583f99092f8c7a4cf1e4d45cac31b892a8a460"
		"ce934d73b0dae9850b5afbdd96381e7ce50d995b984734f3d3cc4a02eee0208d"
		"6d48752132af5a5ff14a44b8e5b86074c12c26f9eacd314ae35d4ece0819d353"
		"80e132526d99cd7465cf0c56269ead8985d25cdea84c84e075a964a14a1e65ba"
		"efa6ab8dc960eacd50327b41c3b3afc41a4863913c8dd4bd72f6b5051bb67fca"
		"a2df095aaecb587198bcb80022bf0b2c66d6629a0c55caeac08d6981e3a8c98c"
		"81d4734184a4c06827b2ec1bad8a6cca52c38182826f0e6e49b6a79e0bbdea07"
		"75cd12cbb3b1c9bbe35f3e1acadb78a4c659eacf04a24751f3b897e2f9bd8b43"
		"64110d7fa3bb1c71b60ad786e37bd7c5abdec20cfcb51d9ca8dd62d716705349"
		"38e98de6bc89609287fadee75f333232e79b34bed1713a564f6b3005ca9deb20"
		"d79dba8667e53e273d787cc3a6c931f464d8656feb9e4387d0ab28f37e0efad0"
		"2b75bbea0a955e37c2ccd9a420057b1408dd80a6b204e33713e5732998892962"
		"1ab8b9970f6267cafd3e1c1135b1b99abdf1abec8e6ac06fff61382f82d720dd"
		"8eb0db17dc1402e8d6166e934d93928c6a5d0ec8e79982367e66a08ea2c08649"
		"6ea34af0db73d69a359bf6b1d075aff4f76ad3c2255ad295783dd3cd620b03af"
		"a2da2dad72468ce70216ddf3261db7d94b5d1f62b0735893d32ff87429824116"
		"119dadd30b57cbd825cf4ae1b753534450811d31f0acbb387882380b5eebe586"
		"a534f2ec0d6c3c74870e6604ebe12b3ced1df2b64ecfa38c4f7eba1b6b0f9a07"
		"45e62380e04e86c30e1b58e32b8ee6c90a78c97930a2ba98406da72bb7b606a2"
		"d9fc6915ecc552cda33d4906dd212df390dbc803ffefa563349526c4aaa7d15e"
		"4abeeb359899489b2fbe61f66b63a7c3658e17db247c0ff51140606dacaca444"
		"7e74d2674e910f3498e4c73a3b1cfd4072d9df8905119e57c1b47cae258b275a"
		"5e664534767650a0c8f8a45ab713d6739f0448960c78fa902a39a30f7d0d01aa"
		"d2dc6d227610b2e8a5411fdf4512db62d5567989a078cca83619fd191cfada3c"
		"c31d71bbb727de13190961504fdfb417fa189bea28d8bca8cc9ab1536b1a5c16"
		"17727a87a1837b290b9692353c43089af793d5420e617197d306e846d0352d42"
		"b823b00d9deb32336232d81774067ff1b50c5018b9db947d35a3c978b412f5c8"
		"8c783ad51129ab3708235e7c5ff0c2261bce33f4910ecc63d9ba7d73807a5dae"
		"7db8416766038d40e4b14aef65c979411020a75efec1c250a7922bbf9a350cfe"
		"722dec4c05428153de26c5f5ee584c487e49d4df68be1e4c8775fce26c0bacc0"
		"521d640b54ae2e7adec8f6186266e1454c92e1fe37cb875f61a918665cc4e2fa"
		"07d1d02cbd0e3dbccce106df29bbe33f6243f744d3b1a5921d77a6d3d42758b6"
		"78915937a72b552290b71cd2ab1ff83fa8a43d38a53721eca327ceaf3bfdb6fb"
		"8da527b57ace1fb21392617a505ac84c06fcdc621327a375db01ba84f90ea3d2"
		"2e54612e9dbd42763bbcfd5e8133fc6e6495fb4a8648d236ae4d8fd97622c841"
		"43e730287ac16776f17c1707a4743cadaab5c37967615736025278371901cd53"
		"b4a6bb2d78a136b91e19d7fb23e32f12c0a55c761c3bd97ec1599b254c72590d"
		"69d92bc4ff275647a8dc66c464497ea48eadedc90f9e0114d1aa202b773f1479"
		"4bc8a77677197028790decead16dd16cfc149efba65177021c8d30d1002ea89e"
		"40bb58c948402b6577f490f3d019ce70f32499934b1ee250884af3a05008ba84"
		"31f96547db6430048cd87b69cb1320ba5923031965cbeb04ff28901fcf94f534"
		"07cbf778964d26109f03d5d329246d52185a07155c21392868702fd7e59cfeb5"
		"a87936e3e2c2b68e97bbc5ba52145e3e1611ca1097e875c3aa6bfa4efbe6800f"
		"fe4b4910288c88885e4973a5aeab9a883d90779280e846deaf5e170e773c214b"
		"f0885987ce734305dbf5081ca5b1ca38731e34217ee855805e94ae9fc3648970"
		"657a8dd13e3f900ef606aca79fed9554a2042947f9b249b19f54e88745266186"
		"47670e75deb816aa97c686cf0428a4e6b18b808b590ccb795ae5ec50674c5196"
		"7d9803fb18a67ee1a67bbf1b3c2a9ef588f85e7507bf83e17790e381909c00a6"
		"ef5595ec53d06fbb0b6e7e14afbb2c8a0f96ed8e699318f0df9df5a327e017c1"
		"85e6eccef6ff9241aee7ec40c5a3f6ac2eac555de84f33af7854493d96de3dec"
		"27922f2c6bfb8f7a782d3129e7a9a363cd81be6bedbd7b242bfc08d7445f1b31"
		"bda2878b198c0d6f4f8a74577b97dbb7d45e4f3edea39959e1df59fa992a5997"
		"2f5e1b75687ab4261d44dd51eb3348b12b8b306024ca34568043652cfd099e26"
		"650e1471c08c2da9c8a4969f9d469058ba508a5928faf521f17154f8d8c292e7"
		"47fa9908898b200039f2c4c9fb975bb56af585af51fa83c41db14de3921edee1"
		"be6ad3c02b403431597692576bf052ce21c148ec06948847eb4b787793e52a1d"
		"b0a5e9240e7012460f7826d257171cadc8fdfc97b18ea9b04286fe3b44df1da1"
		"07f404b99be66246423fa8c226d5625a48f2c839b9b190090cab07b70bd36077"
		"a99f4c093869cb3adc1441ad40f2ccdb87e5d55986c5e55a3002ba74518b9ba7"
		"80eee89b4ec0f529c43f181d0d36013a6f214a7f80924fa996d340f97fcd7537"
		"722801f746b4891be2085799f569aa7fe7ed50340fdf77002666c1cefb629631"
		"6997bea6860d2f191eb623aa60526eb0d6900ffe9b760566c802647c2f12a79c"
		"4c81482f78938e296093a7d6b6baf6d72653ae688c1da0e464f1518a81a45081"
		"032fc61a830d4f5690e508a85f69eafbbe7e56f74a9df080e279b1805be238e7"
		"75e961f00e4519a596f571a5c327f12586592e353dbe9e442ae3ace7249208d6"
		"8cf74137830195205a0b08574abcb35c662b5fa9cd47523824776946447d6757"
		"2fa08d7a490a6bcec56ff5455defd9a8463e10db6302b363b97c1125236bfe70"
		"462d6e3ec82842b7bd6861f762890b110ed86a5465b56acdcf3ccb0c2924752b"
		"bae60b0d6822c2e42b3f74f6c353f0a0a642959b3d291f7e4ffdc084be6f7390"
		"71138d6e91c2945cf83d55c9e612315cf6c4b8385126797f220817144a15a0a6"
		"54fc1beaabce60270aa72df83591754ee7a5fbb40b7420d72ea5f94535dfa575"
		"4be9de081e0fcd4e4bc8230c1697657c5f2f8796d2dabd8e5d1b8e9ee7922a05"
		"3f21fd50524d84d8a2e7608cf3eba9f047a884660d21f8ad96b4fda7c8f9d65f"
		"16eda14ab0502dcdf64b0b003356e8b288591aad2611783ac0b66fe841db528a"
		"ba95f27f9edf6f36313d4df03ea0cac8088a6ff18472e640c56a0beab8ff458e"
		"1161177685c4f21a3a054ee57c91f93cb183aebd8f0ce9c48c18fa34962e5874"
		"059839b7cec55f81f9eb356755f01a166a8bfd96afa72ad0fd08634e44303343"
		"7d847fcbdfab5e7356372bfc3187d85c1aeb84064c0a506b00816fc128cd7d03"
		"606b1239223d96f93930572e781cd818abec6d94cefe049e7dcd4614accddfbc"
		"98961989fd45b01a8a1fe2849278c55104d4ddc99d4bee705c320fcf37f70077"
		"0c4dbd44da8953df314cf386e76345100debfe2b21b9b5e985f9f37b3014893c"
		"a4d826f120d3284e16ffb3bddfa5005cae7bf844c30f0211e169199f01ec2111"
		"487e7b1837e9d772228049b0e305a03dcfcaf39ce9177cf156cca9c311477100"
		"e088e541879307503b16dee8594ccabb582116b9fd97cc90cd68cd6fc8ed2010"
		"543e8bf5789b60f24a0b9aebab4228df31c88925655899f62f87ab2c8ea6d749"
		"8ce896bb72c88c5f38a5a4433faf62b0430775688b228c2c626f6b81cb393eb4"
		"71ce2d1cdde1309feb2d25777f5b203674260208d5bd4d39506836f7e76ffc58"
		"e938799f21aff7bb4dea4410d20e097aad6c578fadf08325dfbc34154a10ba3e"
		"dd6da1cca6fa86ba45262a959f8fc583d7239d857a84d6f9f9b18c635de41f6c"
		"36b6ce2bd48988a4ba27fe8e50a7fd5ad891fb70a342f0bc8591676986b2d4ec"
		"da5b28451426a3819637e9844c1e59059afe9ada92ef76766ba2ecb02e4480c6"
		"b3a4d6a1cc977f5ac09c13fefbbc808e03b4a14aae56132f932d44bfbe60cc00"
		"a8d801c766a5c536209ea384c5481bfcfdfa39495f3e6df0e579961e9ccf60a4"
		"a041d04048181d1e9e87c29e128cd1586f178a5e0d6e2cc049d00b563258e3b9"
		"85256c93dcb82e19229d97d54a4e4ba94054bb1120aff9a8a778cbeee7c5fe48"
		"3ecdfc48884da12f942a4bb0d55730f75af9f5ea00c97cafe7bafd6e22dd5858"
		"b381a9e8b69e1d68dc7405b81b6f294ba44e5f7216845cddf1dec95e4d679af1"
		"cc899bfacd744bcde2c4ee73855ddeac069a2230c8a8413aad2c5847cf2c6b1b"
		"712cf9063597d3658f612e6b79ebf622682765ac7ffcd5cf03ecd2b110f474df"
		"8ab3eb9455cf5c39c995ec2860df1ab5b23b516fa449bda3dc655f2278865c44"
		"ff669b2d97e48e4f79a65030a302f16ecc1f0e009d57a4be1ee025246faccc53"
		"b88d2e58629d13b188dd830da81c24549f1bc3e7d4ee3029b3a54f3e5d2c6c13"
		"9d70cf9e1fc39067dc82ad47d9f55a6f117698adafd609eb81fc03f9aacfe38c"
		"9757a486341eb0775fddf5649d543cc80b7ab6d998d6d80c722d69dbbe5ddac6"
		"8c89d5980a7618ebf73584ee5b037166766d45f3f6b845956d7fab6e019ef8ca"
		"664f8b5c099373ca8ed4826d7dc8a25238986c843142f78d593cee3adc5ae69f"
		"0bf1ee5b993d671d0b0016676a6c77923b435413b13d97fc20aa5dc6b5584b4d"
		"65b7251c233b9ceb560268668ab7973065b62528dd70cceba9111d9af561d0dd"
		"5ae859270d56bc3c5722a1f14570ab33a038064b1fa53f60dcbb593e053d1d56"
		"d4ceb105c1566c19f6a7e99103615aa4d3121f05dea29866a1ef373b4bb4d9c0"
		"baaf563da50356881bdb67cc2c504d8ae68d99dd83307e02e0f4df17318dac23"
		"f4d46f5723242294ae04442d28062cedc0ef9c5c7417993e81137a5d1e924088"
		"698525dca2837842976ba7395f4b9ed64b804f081a1f92216c9430927a893af6"
		"030aa0538ae6fe9cbe58b97a3ae64b4b6e8adb6cdd1011b38abf2840ac3b4576"
		"a9aa074442165fa90b12a2771fa1dc571153680d26b1bdfdc1db8bee1e70070f"
		"43ae823734db417167e389b87742f9ff1c241d755bcb3f06fa32802537f028c9"
		"ba5e3bb5c7fc4dfdb81196c6ab92494d7845222be6263ed71e0a306c5f8251ac"
		"f402574563432a54e8e5f328215975480bfea0b72d8a637613acc34bfef02ac1"
		"dae201707076807edda7c566435f24f8be97bfa29abf56edc360604a7c005a0f"
		"54465fbd565ef984819f3709786bff667a57a672938cbe44146e2ff2427b8a9e"
		"4b7599b47ec33b6dba156e982747ae9925887eb282bb4481f01d59cab6286177"
		"a5b8d8dd4e6dee417250959bbab9d899a8706ee7ce128fae3eb6065b41d188a1"
		"4c5744c12f23bb099099d29a988a256fec579f9bdf5a48d2e6815d2b4c3ca624"
		"269a04e78aaf4accfc384d1e29823f22d88738551d5a16f6cfc687c43d326409"
		"1dc841d7c5d742929e7530aed568cbba5347629ef0dca221e3cdacae7d7b6a57"
		"182b221a4a644b635e97a0d30406744047de45fdc0a6935b09ddf26f75df5f16"
		"fe09d0377f1d0f4824e8c7141e22dfbb9b9508faf58292ac294084918c26eb4f"
		"b9ab72b6cecc3348d8aecdf98b85b73337b4d41df736471d2c3c889c2917b709"
		"305931209e37626c6232da0ab3f7a2b10383d0ef2e8a59b5f81a2716b67c6b4c"
		"4b5b35fc562742bbaabc14d0ff3f483be74925f70348717d762288899a1baf20"
		"f2f8a5d260647b3d9894a6d2d52753dccb50fabddc36367b8e9bd47c3dbc298e"
		"0d79a92b23b6b6fa1501b6989e75689997de78ca221e51b929cf32780729849d"
		"84266b8d07e59bfb074c6dabc3f2317c333cc6a53ec6693f2d04cb0460296656"
		"3f47108374b8d14758bef292aa66568c87b20ed696f627138483c6a8b08378bf"
		"2724c392d2f901e6ee9d6ed5bd997fd17b8775e69478333f14944cec5f0061e3"
		"2205aa44896ed2e1b33108fd63525354f805255c9f1334cbc77e8559d568c9c7"
		"1931ed2001e0ed3f8dc4e991035b7a1ce47246c01e8ed2bd838b98767a835a75"
		"f5f1b5aea316f908669c3819077a9d312917ff9b7bb2b61f3201aecbb718baf4"
		"9c8d2a77d5da9f4425021e1ed678649cad3c79741d4788f8bb29eee1f2f1914c"
		"f84d730200f287fcb23ec327d81c76645a29dcd36c15ef51064b813f94d48886"
		"f078b9d78d275838f5984ebc75307c9116254f40d0e39431fbaf8e6e068a46a8"
		"6b58237fe241bafed658e765157a1d2ccb79fa44b17a1fa0829c3ef4afdb74bd"
		"5333da81690857583dc5b8ab20c4023c606e066677a337a7835cb95bf68ebaca"
		"8f5205658944d44d1228e615fed4d2c9bd4a9b2f8a24844ce635262a456dbfd9"
		"07fdcdb4a9bcdce53dc99c2c177236dcca55e02653c5b0999370adea033e2cf1"
		"a37c5af533391529a6f00076d468d67b6fd9fed3385060967254782297caa81b"
		"4b16d3b08e83272035e53a7d9b7d59b1941c1dbea28b3e4a6c2bac5a6bd9dc5e"
		"e714606e2262bbd3d3ef73c9d578688321676370fa40f2bd673b741be63370c2"
		"5fbe2bb5579e79486658d3e0eb22aafbfe02fb70a63524f74ccef6eb709f0b4f"
		"9b5c591095fe0889d766814c4343c82013350b4610337b01042a5a5571e6550e"
		"83361504444b119e0f62a69547a369fa4848bc7b9e019fe27697c9de51d0f806"
		"0094851bcc4d3b8df59469415e09369286823596ba6939a2895f6b107925993f"
		"f8bdd1dc95cc2f607043f3daef3ed6efb32d9f1fcb31f14a27c967724fade3c2"
		"55fa22cf0790941f6ab86be8640bf219b98f219e39226ee0371ce58c3c307b96"
		"fd93a07d8b6013d0ca3cfaf1243632197ef0e49c6b04596fa0a10fe7a9750cc3"
		"dad0726d8706547d7815c87f97873df6ec9a0fa1cb9f59fc4ca00b0afc453c52"
		"d2f8c1276548fe2d5b8bfc1925c8bcb8ead4cb33c0ba17912260017d9f68b34a"
		"cf55b4348befb9e95de8bf4836bf56685fe540dcb21f3a350a2b1ac9f8a61ab3"
		"b82d741b63c32fb8657238923235b40d3516952309946bf1ec477d7571c71996"
		"75c92864538b05a25c73908281f37eaf53aff3902ee252ccb0fd5409709257fa"
		"ed71f998c511e6af2831ee9d8bbe5b56a1f881ac87d196ce3f95c40e5fd07de7"
		"0a6d0f3e201b78e8b2f57b6db961f30b073868fe7d28e0ff7f57f70ba5493265"
		"b30491decc726354e2065e7971a2efd56db9cf0f79b1d768598b1588aac51f7d"
		"d07fa70131de50fba1aec0491c4bf7bdbbc1df65e1322410b578450dd60cec36"
		"4a267b2eb726e7e6d533c9662322b2cad999bf8a1e746eff7c67b02391e54099"
		"074132edc614cf1c67dea057ecf0c904af899906993f5e3e94a07e51431ac3ac"
		"f018f7c6c66eb1a540f76ea4e17ce37326d8925fb95a9cd4e76bd62054711e79"
		"edf3f0421ffd348a46c65ad66990a92024d0d41fe58fcfc95c10e0172cb3f908"
		"e71945e8398901d263928d74ebf2c31292b787cd87a49f26dad6c6be33a8fb5f"
		"c4d31f407cdabf857ea52f06d16bd85159d6d2f20662b6f24b07ad9dd217cd88"
		"6e69a6d351b717ac7f45671482c390e65f75de15ca91b93596e9bf3d6fc9178b"
		"cb2301281ee9b14e4dbb5d2766c295d88edcd3be3bf953f7a3c524257487806e"
		"c54859c84c393473d24f3ac6e5308c2fcd52d876c1612a415ae204dd4717b03b"
		"4322d539446c4923f548267a67d420f4032015c3c493e61aa38a86ee524150fa"
		"2cf79e056d4d97679ef048ca5477f72e1a8fb330ac55308b6603d2dffbcf08b1"
		"6a10dbb32ea3c746b58dc93e14e1b9e5f9e5da42e170b09b8b961138ac877f6a"
		"e4b5b5ccf13580c92368d05e0fda0f21886ab183cbac0d52fa8b6b82cc335e2c"
		"822e54d71dcc6bf7cec986b3ae2aa1ebaf68617ad2d0efb89b2a0743c3994c00"
		"2cc2df5c1a302fd89ff713c45798164a562511af5fa600d656ba0e06f882f2ec"
		"caba7ee44f2975747e3c9e1973ee164765eaeaabd8f4e5b31485a750d5b5f7fb"
		"445e5bf6267fe5d454de4f3b6bf24be9c4ff14f5a7834957bbd1fbabc1fc0532"
		"82f69b1a06f926ff07264fb1a56d5a385cacb615321bd2cb35e7329e241dc19b"
		"6dca69d85761e1fd815cc6038b26ee3c1339f994e3832816680f73b267e1d53d"
		"eb22ebb9827dbdd7a8c8dcba84e7adfed2ed04f92185f4403e91e66df010e920"
		"e5454944ed16639466b2b75df7763f85821200cc53e7de529eb4b45a2872a44d"
		"447cac0201f37a3ca26182744e9c4dd909ee1496e3728d536fc105fe77ceafcb"
		"ee0f3c7926deabd8441e6388f0217f0351c969dd38eeaa4b9b0000e346eeb1a2"
		"cd462033c59d9e6e3331822045cd7c0a40ed262cba23dc4309b9ce90fb9853db"
		"c86881b844f9fa0959e208c4b568edf6c0a17408d1d9cc41a134968d00953d7d"
		"c6bf868e0dba68ae9d791dfca8b979d0b82c7bfbe5d722504bb88163bbad1690"
		"b191583f86a88f67e73de8518689c99f0fd7628c5ee68575ef8fb79996a7871d"
		"70271e53198a183b1f77924ab7a0846bafea5244a4ce9dba75ff5fb7f74d372a"
		"ebc901502d2aaa332e6f4270a3c6533c7fad72a91f571326c551a2454865cfc2"
		"0abf29c0294eee55fa6d2149b3c3de1b6767eb4538488fc1c8cda7ccf0b8f6ea"
		"b550bd2a77bf8bab6cb9575f4d5ecc0f4f62e4a0556bb89464ba97d4570e55ac"
		"d4c5e5177e452a3d6c9a0b3adb60c6211fe48640e08637a6826299e3e52f930f"
		"4f66cb0ea6a77311e35a6660c3927358bf36f8af3f62b3000b0bd68302e2591b"
		"0e7b949757af0d31b73f8f5b6fb97cbc18a06375dcc7d5a8e5fe753b16f04fd9"
		"f94c6b3af923a1a5d292aeb345a088551069ef181d7d45a8fa839f9389221c50"
		"f9217680f4ccd6731a9aedeeaf0e402c90dbc3226c4baa0830e17c14c33e6989"
		"f441ddf0b17255a579a1729613ca4b48813c081b30faadce716233452d0cdd8a"
		"d3f5c91396ddc643d6ed6532db9d53b1c9d5e589d052f504a44cedaf2d56215d"
		"7f85626f0cd4cf5318c7ef4b6e4ffd7052ee83f6b61b2bb1b1e8d1d82ce2dc0a"
		"df39cf8e7c211bdf2977386834a8f38c02cf0ae9491df6de7f7e084a9379b797"
		"da5839f84c8a50eef04567119570dd0dc3bfa1ebf120ff92f856b98dc8e35a0e"
		"5a2cc733e6d817895579a4cff96e62fc7c08708316ebedd503b70d2735e86c76"
		"46fba2c9b0d317b7405a1928c86b2b6015f0a039204769af88eb2ca2405096d8"
		"850ef1421442f9809931eba66a2fe04175c0599578fc1b2970383d8653e27f3b"
		"01addd2478ee64ec484645d1488228a786bfc22084d2aa4aa1e76859d567cfa7"
		"a1208ef946a0010436e14d30c82cab9b2f370461ad91bf1b043fd7a52ea83025"
		"4dae2b48e51e78cf494a2b4b53f41224586e46e05b0001a2818aaff1c56a48bb"
		"eda0dc9abd3070556ac808aa52a3054be9adb126f7e819e9010e1bc60478bf74"
		"6a3ecb7636a0919f82a50cd62b012b17cb3c6dbae711aef86a1541ab52993e55"
		"aad01d64b83584b477275e5648d62d90e463a124954369d5a6e5492817946d68"
		"969efdecabb6f19d339727b20feab2be1d6a76ed6746f28a9bc65cc5bc32f3b4"
		"16f0919777ec7f609c3d8e73ea0563aa5f98139cc7e1f01f3302a20ba73b7941"
		"130d01ec849fd7079c60bc2040eee85b9037a0b91cde0b9a54e042814177a618"
		"733e76743b96a1991a49d841786ee8d9998d47cdce03ec05e8a764b0f2ad2340"
		"20cb18b5029b841ffd410b5efc4d0c2d63e32e5f45193b67d6a0321e23a797c1"
		"00fc0e39427428a02f8e7d003353fb5ed5807df7e8e79fc90613d1553a2baba4"
		"fd18818864ea3624977855ae85475d74d6ae5d1d2137c13260476cdda10207f0"
		"fe699828cec556b41d49bcf15af3dc7850b3f65a58cf49aacc86293cbef452ad"
		"ea357ca3eacd2f56a947d9501a1d1e712ad86f35f378de3a321630fcfbc834e3"
		"abc554811fca6a1423bcd5532d8ecb674c65f0375bfa28e87a40aaa4bf48579b"
		"28614948d483aef673eed782fc0e8c629ea2a3e6f81dd1be8c4cbfbd713a60dd"
		"4951838273c1a40382260866ed65096b07d6aecd32a97ec4508296ce7b67faaf"
		"f6dc29b6634cf44336ab8f86695ae989724b39717265d901af2a585f4497cb1b"
		"174b636d0cec45be78c7956ad9b6d4c5c4476d5c1e1a8a7d8f8b2cf934917b28"
		"94e65b2ed6693f7d31c0429ba3417426e6137115a0903940daee3b23b31fb3de"
		"55f53681298a8b8747dfbda031c36eb4c0f76e245e8f8d53769bad6529071b46"
		"43c01fee6d18d1e4a46c2f01e9046d773a3a8c12c2df2ebd4ddaa947fe125a67"
		"448f3cfe0adcb89d2eafbf4735cb17783d26f2653247c58645f357529a08194a"
		"41a9b538689be9b9cfef96f97ce214beaf01c9a81891fab7482de00d66b1fff5"
		"2357b325ef200c406e76db9f250f0d517a143860db8374563dd26c00c8d5b572"
		"d0e15e4b0832c83bf28ab7c29a1baa3a84a76817e3e6dc6e0b2822b4293be2c9"
		"328fdd341998c5b1457452e942ce9280b70281549881d9049c782bb0f2ac2f00"
		"30a859688c1bacaa4e7cd39c85ef6e2bf96caaa0621e1422d709af7c89f04321"
		"b176f96dc783252ef5e96363cb48e544342f0b82a98334cfa425d5a158cfc833"
		"9f3fe6cd3498d746220529c77c9fa0d14f91cd82d579e214eb12c5a6c511633f"
		"e14c471039216bf9bd164e4f00bd46dd32db18284ec8c6f89419a8133a7dbe4c"
		"5fe545bc40e88850ae65f984c06a806dc55413fd7c3887838882a6711edc8162"
		"0152085bb0b3d751dd3a53ec226df68bf046e788c891cebdad95e647d9f65489"
		"afdab774f14b000633dd84118f904f3e9bf7bb51989a42afec9a911dd393ddca"
		"51c67a906b78aa779695b37b7099348faeb0b8e1551c8c602ed8ce7c737bc72c"
		"cf5e7b3686017dabefab08b02b514c8411b906bf68e053d85998c6ea2375b8b8"
		"11eadfeeaab023aa2767ac3a2a804028ac5acc7337ab40205622a0f14b4b5875"
		"ffb2d1413f4b417c2411c7a1d3eeb78067db33862c48fb3f0ebe851951c3516b"
		"82fe77b5ad9b822ad0f1806b90625a962b83627fae7d2b3d68b49de99ea648a2"
		"8015f9d45c688bba124f0022c8a6d171de9c81e6241478234b4b0fe99abbe823"
		"e2408026b47a0737d1726f4de280c3196a6cba44f8d38cf8a1cc04a1adccd6f5"
		"91c734321e989ca6f7a3f47548b9d897b53c332091830cc4517fa39a409fbd20"
		"74f23c80008cf2116b2ab7216119b9f2a953140257eca38f43ac155bb9fe43ad"
		"7208c098c31cb27f154fe1d995670e322dfb8672b2d5f7625f9b816c82af10a3"
		"7553ea03d01184f9dd5a9a264c6d7e60287ab1f90a07b0448d941056017acd0a"
		"6419e0488e320f86ab92098eeef1b2828419bc1ec74b773eb5deeaa0a02922ea"
		"26a3caef6449fc2e6740579be3bc52a32820cf6a5167f457bfc236d2c682b64c"
		"a539d180bc1cf2f9f9acabd5949605c8fcd714641123ce9793881d75da4f3237"
		"c8231d84fd759af0491e2ec3674673fbe885b0946d49ad061978c61046563db4"
		"77a8d5838e1a9c1a40de08edc5964543d474ce82ce9f3bad3ad9592b716080ca"
		"9a112103d9d39f80c43360db174c23a9a8ea94b79def1d93dcf5004ec334a381"
		"1aa62a8e456a4b28be675e16c331b4334c302aba40fffec0e812e102a49c4de1"
		"ddaf18ab3aa54a1c17c02c25330da1eba88eb9132197843d477924ce7c5e26f3"
		"cc7413e3204e4164b587ef90cda891d9a54b694ba6815711df72f23bb343d7be"
		"cf3d42bc602bdb068203d2e0fbc92d0429b161e9398420449a4473d0b113084a"
		"cf51cdc06005be0c657efa9c243a1d741d06ca75416787df5f39ce15df9660a0"
		"b2f9dd7789a3927d453e924cafc108316a93cb7726f333e915972c92a39388c7"
		"627d9a6843cf00620c8cc07806279744f6a08d784ff0cd6aa6a7b4d066d428c7"
		"c5252b1bf74fafc2a1b0aca9903371b4ab7538002626fc6bf9b18f56911fe7a9"
		"c538b8180bec49a5ecf28066b5af3e897059f395125c69f2f6fde4ac8a3d6d74"
		"49006be8e96e7314d59a6138dd61a8cb2c96e6c17b5cbc0a85d2dc5bbbf66330"
		"38c36a12f79dd71544ef79a670135583c9723a0bc9ec9cb88e7a9fea8a1171e6"
		"7ccadd1e9f411db3213af038d68bedb92e3617fb65d5b106f93b54e161583e9d"
		"fc5ded944821edf354c3ee76789219734329a41ab5dea4fbae5e23c9a791735d"
		"a0c4c1fd5906eddfc5d29ae9bcef81bbf0950aef22d11d9f962a3528c485b72e"
		"504683e13cb8c87e5daf1c180b6ccc981dc070031575c3fb97e9b28920fcb319"
		"f42c58c658ff24d802a29d8bcecfa213b2f3ffdcf4913f169ae1c27123be0f25"
		"74bf6a3615a3aaf69df245cb6be1ad329776df0428ee38f9885c8b6a3592725b"
		"b844e1b8db6b01df17e83b5f4c6a92ffb59137031a5457aa47a038fbbe4184c1"
		"a906e5d51220d19b56cca8cfd732fc82f28c2f5f318a4433c1f5efad2694ee62"
		"2d4c9c13228ac43344e6b3a4760091c237aef1a2d45aa69bdca5d806d5505843"
		"2d5d31fd747180aec87d8565909df9c76d41a2536d8a26eb82f71d903340696e"
		"9282ca186e9dad14c9da459a8cd2dd997a8b6dfb63e36b2a9a32e3d3a92bcaea"
		"420390ee79d6f46e31461cccd465e54148d578211e2d1e600c9f55569dd823bf"
		"2728aa06fee3fdc3e7073282cf1eb8c6bd66eb4d0630e696c08698a178101bf6"
		"283940e8638d6f1bd365ae44e5c7ff30c388ef0883b36cd39d2fd73ca39b5a95"
		"2c7d7c1d129cf27eddaab89a7e2661874181acd8fd80571f8de138b0844189a7"
		"1d3d842c71d830f5ed1c7a0d020587d41e9a4948dc5d508278e5e38385ca5031"
		"e2c1809dea08ce87eb051924d92a181f441beedd8813ff05448401400dfd563d"
		"635199f9e3f6773dbfabc0686c5dbd6e9a4cc521696a0bafda03ba6c83a344d2"
		"8835f6c6c668d11d5157955f21681ecb0874f39be7291d8922ad35915184c1f9"
		"39b4c18ffa2784328950c0936112e23d76dda3d36b1adc9904c99b36de6876b9"
		"5e171fd9e7fb398150e06a8c9522b2cdcccdfb525b03f1e9699e13e492170a1a"
		"dfa73a2ef5ab98148c4dbbd023613581f28d239f21ad03813775c622d5582624"
		"a4a93a158c0148f227e0dae975971463d165444223e0bb675896dc780ff572e0"
		"9568471714c3f22307e1f05ff18bf67b4f9c86c4cb63c1a5b2497c6ea8b49555"
		"9b2b87bbf5ba3db0169824b8010784cf557c10ac8000bc432fd6ce8d085e388b"
		"9c39258997aed2a03a4c9f7e0cd1666acc4b0b82a97d5447b684fb5c98bb028b"
		"81db4709636758fb5d4788387ab243519a529ecfb0a332bb2e9d2b64be929c5c"
		"335916c4bfac78c966cf086fb272c38ea9d9f219fc3afea68167852be3acad06"
		"99fbb9411446da133d2d47aa1ed98f27df282eebf50a5f11962b323b70d2de92"
		"9a095808cbfe25e1caa96c7125af4f2726867bca03dafe0355305a1ccbcad707"
		"20ca1da24a9a0139f58aa04c2fbbaa93653d01408e748384a6c023545e5c3f6d"
		"12872e96fbe21825a61a0ac4a4c649758493e7d4fe9e959c7121b86d9052bfcd"
		"5788b36c45a00facc59fd360ed98d4d46ad1560fbb21dc549e9c3fefc873fe2e"
		"d915d5ad8f9a91d63a6222a970f9f2b9013e75772dc502b31579e1607086a598"
		"7f76bbe0439944acedab202696b14b2b30246d96bd51acc2bf00c54aef545b13"
		"31f28f8dc865d035c6c2f45fc7878832dfc965f4d18f848882791434ada5c9a8"
		"d7d2763c86c6de7aaeeec8dc6c4551d6f6768617d345320d472bf5a71240965e"
		"5a5f9a76e58416818b78c126ebb14d205e73f889293c5e59f75f912a86ef6b3e"
		"a0de23c24d661f5447a809c4ae942517fd08e2d23d3caf75785d0f457178f04e"
		"929a39a92636a2fbc8c6c83e1bb581c4bc7d6c78750dcd68b46d98803ba4cc98"
		"18da02b2d8ba467cf81a251d9cde072d8319c0053b76613a91d754644c3ba824"
		"1be5a965cbbbb4e1bdec49e798d5625c3b260301f64013f3f9e26a780c052bf8"
		"8104544a6700933201835c2777633859caea60f20d338a9cd3d70344e4cafe1e"
		"347f2cea15538c75ab288562a050322a1aaefd62ea176f3d07fe46513a51c89e"
		"1a9e58cc3b7a47b4a323ec227d64f7d912b902d8f4b469dc7c9f5c267763327e"
		"1da90078433e6bf6d1bcbaee7567306e995598dd93d221831c026c4c04c8e4c8"
		"24e74e779367a0441d3b174ff02084ef99c8e7f82f383e39ce6f9f4947488584"
		"16a1685095bd90a56fe72acc56589c66f95b16b130af69077a2d1da7aaaabdb8"
		"dd1f768baf08e121af091ced10d71fdaa1564d90ffff4af308850ded94b8366e"
		"60a9a1b14b0f3bc0c5e9143a8465b6547801b61e02f0880861bf97a46d3895ad"
		"87871049d09b478b99cf3b3c1bca09db68a376e2a249cc4b6b23e5539cf3857e"
		"3a00eddba674ac891303b97a3dcdbf775986b86447d4bdc60ff81c828bb1ace7"
		"615d5def356213c21cccb57c5338803031f0a22d5a570480368867baa13ab2f3"
		"e4e78a0ee42d243f9a7457cbc3d1f60fd92a5cc4419b4881c619ec81465540a7"
		"abe39cbf1d9c86077741c9eef761c71b397c0fb1666832d2a9f4d362e2ccfe0d"
		"9f9cbb8b4878e222997c306d55af9b5d392de37d2f866a7ac56145e2dd65932c"
		"a6590df9cb89df99ea6cb7d147851bdbc287ffaf06bc978104a76a8ba0e9a80c"
		"a961bd910f972673505b83a134a9ee9fbad08ccf52d361f04c1069e4911fe4b6"
		"91fdf1db7c6a5eb8b58fbf6584e4bdb10b51b1667b9472ce87e26a7519d1f031"
		"4475d2607bc93071005191a69efe30179b5297fbe9c46f239c6697c7a1c57385"
		"ac1187a7727e44a519e921eaecbfeedb541b6516032e03f773e416618fc416bb"
		"b0193838ca4f415ce89f98bcd5efa0051cf3443f3399d453f4a40fcb4c9681da"
		"37d40f9cec05d09e54bb1ea1c155ed9bdd245cffe1cc8a3e07edab8e41035bea"
		"2b8b315a3e6898744784da2318ba7ea77ef4d4dd7390cec194091131d5d34cf4"
		"7386c9fa2a3f42e5a943f5c943e6fa30e7acd56252ad48e3833e6b3c6fcdfefe"
		"f70dfd05175475fa6041971ba8a10a3f00938614e6eb9facbcd5de3879bb1613"
		"9f68f5026d6ddaba55c3e6a2b0b356dbb1f3107e97127b24271594ac5a633f38"
		"53deda799353182d70140de5c3e3850ce2129a25cee98654ad48b5207a8d1f77"
		"fbb8d4f2f3ced85b9a7b326d4afa40da7b3a4d93f139654334b4681c41035ed7"
		"7f3f0af6f4a5c24db93f7ec0abc12e4e64b1514f6acac3f9a5a3d629178ca561"
		"c7b8a50cfea27d0ab6a9186850fdf86f85bfcde19f64467fe95b27ce64ef9c1b"
		"bb6eccbd798bb29a7a0128ed9f794546c6aee9d2facf96dce625829490f5ea0f"
		"44a8a890cd290806ec8fd8d502fcbed910c4cfa8e1d25c1886480f0203663745"
		"48ad610d63442855f39a4eaae04d0b32494ba4eebe37403cb00ef8a0250a2dc3"
		"b0c61ebca1a4b98f796cb2f3a135d3595b899329f8c4e94f4cbd62f65fa87293"
		"653b0726f01064bd654b2d39ac7cbe542cc7c1e3f7420059419e778d170aaebd"
		"4e5446d2b951d1e59f80e7036bea762da64c59a323782c6379f95fecb6f68a47"
		"52590048622fa7120e5207d94546a0ecb06281f2e4301673db16429ba535ad3b"
		"5b91601155728f499c0bb543a25ae797314f6157a23066944f3c47234b8fc1a0"
		"50458bb4f8e2309430f21bcaeaecf038135c235ac541c3cbbdb4960b0fcb6b7f"
		"18bdacb9b54733fab24e5ef586c566d63dd1ec83b52bd5220dc758db5bb355df"
		"9d41e9a9f3683f840b68a94ddcadef7a97f6e75bdab645a027bab51c960d27c8"
		"c6196a0b190efd3821882259556c332b091239699daabb4df4d8d45527a28843"
		"7b8c586791011420ddf5f1a159c9dcf17b6f0d3564cede325a68de0e783a2156"
		"a4e3db46c2092d4427f93fad518d8fd4d553894898eb575642b1facff09d9a0c"
		"2a671a2e14eef0aae8da3406a380f6ddff07d529a2c9cdc295fc5121f7929a6a"
		"f35d3eaaef77045c06e1f733b96ab913e1d31a60e830e97c39910b8bf5e2c97a"
		"e8106e3fbb6e12626b56b1bcfa13807f64fe8076d4e8538e18b84f965255d143"
		"f1c7d377e099c1c2fd81892acd43f2276ed22ef2cdb8b2ff19b945c877b357cd"
		"f7c995d9c6c0ba86a6a9a8039cc1b715e8954d5c3a6aafd823db16accac40621"
		"e05fdbedd6ada5b64d1835d2ce567851bb90043d85c4f1202068eac7b4508346"
		"96d1cd3c76272958da14591ccbcadde1cd0b7c1c158f21dff7a6e8a39e1e7944"
		"ff67954d0ff5ee7634e63c6bfae58dcf084edc815292e61e90de39c7eef78e24"
		"056958a80ae09d1745d60546c56e312353a04df4a497e9e4d35704bb0ea36aed"
		"8f1e41d6cdb0de44f42bdd36932f70e3954bf7fe7364d139a85b720864eab6a7"
		"84cf755ec22d5804292febc2cdeef319b895012627c34725f730ab355a941a5a"
		"cec41fc8501eb45fcc285872d97461cca3c794f52879f3b1a81fd6ca56683d0f"
		"5445659dde4d995dc65f4bce208963053e28d7f2df517ce4a3701c4fc22fc8ce"
		"fe9a6f64d680b007fd1ced5f0af4a1cb7102f3a5b2128bc7d06ba44d05b1629d"
		"b40a66a59f80a1645aa765ac007fc226249b0f960a83c7601758974c87b6b486"
		"5ede72e9a115137cc547dc3d68f06f1e3f3d544e506ed9b9617e1cd2b0066690"
		"e45fbab64406ae5827457a9bab104fbcaa2eea54ea9968da94265c69e8681fc3"
		"2ed26797f01d1bff66e9664d32a70b074eb6f83042cc1dc99a987e9897a68728"
		"2582a0110d2002796c7bc9db647d4a08111fa66bbed1a090591cabe8258647c6"
		"afb68eae03d80acf1f43cacea859b5c5dcaf1e8cc86f9837bbfa0bdffad107a6"
		"b5b559f53a0ddc08698992ad6805f34898b0851bc76dadc4a779c5077e4e6ece"
		"20c8286e1b87202c319448000b47ad992b6806a02394884104e202e81ac72548"
		"d63723a20c0d7d445fad1550f9e88bbe7f20c6a443acd1b5bc7de9083402d41c"
		"c14a741876699b57da1c212399b034c17a1ff0af917d2f29b692a3f136c92250"
		"c8494058c261236d8c299304556651a906afaa4774ce4ba4da69572b86e2b7ee"
		"d27bb2eb56bebd8e5c1c947894d4897f0a161cf65468cd2e104a2e3c8e153cfd"
		"c929ef589c4710c3323c4b09bfc0854a6d9d70439a145ccf407c50aeb42c5986"
		"949b2227fac6c513f6d2e13e3cf3ed12198ccbb6ac98a0905248e40962edb590"
		"1b1971e1da01838790267d9f743568e0f52b57d8f3bc43782ef612d3ff22f923"
		"46eb040da3c2f326e98048b5cf4d9ebbe9c13c30d74aea90bdce0496f391cc47"
		"fd580433bdcfbdf8e7286a07b60538abdd98a247c1083fdfe517dfd9a503d705"
		"28a999dc90f0880573650a1e8f23deb8b9f6b0a317c0ea6d8f1bce257f3fc264"
		"af27ea8f84effc5676815080c37037eb65248ece42389342a420f701e80f346d"
		"7a1720d40193c2f2d6c265b7bbb4ec4bca6a6550ab39e1670a6f82f54839d527"
		"71c462336fa382e17d71714bdeb7a4e0ce0f5dafb98a7ce3ab50988908864e9a"
		"7d75d93536e8e32c51d59bc2934008b35a5d9d75d3f50dbe6d0a61468ebe47ce"
		"8471ad61be2a8eda3c380ca64419c0cb579a4e2963403c003ae704b343a967cc"
		"6f01053f6f302bf325e0ec7e58087331ab0f9754d034b0b2f92da9598f0e579b"
		"276d0958b2c46180f31662d337d6c9eb4004a17d829912dc92257abedbb7bf43"
		"93fde333edacd8879022962c494b6c03fcc1932ce1370984ec179c6c8d6a45cd"
		"9af9b8598ab13913e34cb111f52e0180c98d96ea55d53eb4f14b3aeb0ff09440"
		"26a8b350ef9b2c29d4dcdb0aa649336b8eb2d23d463d587388087ac1c71152a4"
		"1e53f9a2863258d34b193ba0c162a7cb33766eb01c3500ca999884781f942801"
		"6942b5d6b53e6618304dfa5aaf4208a89f2293c83f86debf0d4181987d43bd60"
		"f1bd0d75e686fd016bbe3fc1d8b1fc0bbcfd680f17f8995dca4c99a74be4bac8"
		"9d0c290680d3c694e5b4335ba4762bfb7151160c0d52daa9b901f32ff040c642"
		"55763211ebed69db8479feb37c5b3f80a664c447875e48adc2a7b8b7d41f8ad5"
		"0144501f8e9c8dde3154c74ec626dda243809b49eee28c70ce870fc85f49ad89"
		"8abfaab7d3a8daa4d58cb6b6eba0af6a31ebc399aba74dfac3ea21e9f985d866"
		"d62c696121d8fa35566af57254915ddf56ed63bf247534548b1616a20a9cb375"
		"ced6b4a5e1f592999e36a90a68c18f099bd0a344c313e9850c54157bfa57e5bd"
		"5a04b40c79c74dd89338fd068ef7ecf1e8daacafef4b139530eb46fd317c1746"
		"63fd911d5216d0fb1fb717ef30fd1c9e2655a6880fe35a8ddd25d2af18d3f019"
		"cf0a7261d4aac60a29fd1f4db599c8183b87b9588da46874fd48e1191526193d"
		"88737f5e674bd50b98503ea68594986811b90ba5d056e252779d9ac4913b39ba"
		"7480e29e74c0a50856f99b8408b533958f32c7fa40c1732f336c2637f5dbf999"
		"7d79c0a961d2df084a3f606ea6c642a79c3c13dc45acc11419fdadfaa7ce01e1"
		"8aa5440598492b145c6cb2edc78d6ca7221d17d547e174081197569611dcf89a"
		"824d933c7fed303374c7bb88d3d45a9c081efd6cae2635140383499299cd87cd"
		"4fb9d8d68085976d7a97a3c73261b38e3687ea2ae244ac3fd70aaf76a9685581"
		"d831395902db07ca562592324cfc208693a008954b0380917572b0cba8760bbe"
		"05fdde4f6db52953f1b9af52896f498a09b07f37522a5912c5037318febf508c"
		"be64f03f28dca50f319a22ae5281d5a57f0177985d83e1cbb00721e5120bcdf4"
		"ebaf97b29d182207ff1214ce0df96ddcded9173ed6d4bdc31cc4e1bb4e2229fd"
		"7427fa2f333048414467ad3b24a0b8390c8187b323e69802f383dc2019cc0db0"
		"4111423e52eec1c7e6e2147cfd3e5fc3f241f07fae8118911b8c399fdbd02113"
		"3bb89667621832a1cfcb7219029b098278607a28dd6ce5777e2721bdfdf70c31"
		"48631f33cb7746d5e56aee9b997e5f7f87284c381a71a8bc029cbc04e509770f"
		"51590529f6d3a36d1206b1892cb008c105df8f37cc560969913231fbfcce09b7"
		"3fe36fd249f4f1703ce9e26b22faad50dcce6aab5ae4af851233a92aaa0d6b30"
		"f84985b42da1d9e74d59aacae322f635f23d061e2ee343186ce54b1a58904482"
		"66d371590ba402d92c9f312cd7f08a7731748a17af1b6c2b899140526c1d3db6"
		"70c9584949c3164ec1039e1c662e121e7fba1f1f4554d3c4507eaf5a507dfed2"
		"fd72650a51c7ba4ff4cc191ff8a23533c659edbd585520eea9f6c1bb6a782ee1"
		"f717bd26897798e2ad44ccbff5159cbded971b7950e7faae7c3f9efc24d575e8"
		"45008b255b9d5812d4b1dd83c550efc4dcbdd2db96d2090eb1a26da5e55e7df1"
		"cf75f58d2effa2e4515c74f3d018d5517b12396c90def6153167573f14d9eb03"
		"7dbe23e869671c620c8dba987e38f66ab2e079b3a7d269cbe2d683511b0f6a27"
		"37223ebd769b7193ee8cd6f93876fb1a696db93843780939ad37196361c8a064"
		"e5ea6e95bc63477fdda0f19f649c8c6688032284cd967f667ad143fd4ecb35c2"
		"6f5fdaf7a389472fc21233106c705058f7e8dc1eabf5725b32ed27a84ae2d249"
		"bdc6ab6b93d318aa862ac3d6b6bbf0f79e640e8e475d8b1ebbd3edebbdd31f02"
		"b76a0879f40b62f80f30ca79ac44134b65c1e05d089672b9ffcbbe4f0f67c3f4"
		"46921aaa2ef7cf22476c6f7fb4d5625d35457b125567ce33e51dc25ba8666727"
		"50850985a960052f1526db7238348534f43a07359899489554102097f198b2a4"
		"be8cfc93ce0dac2760a535d99f2a23d88ce6ab4f38f487e636ed018b50c54d72"
		"79ef1b5a03c86d131232a63d517fe452e39290e79d40342e72fc8cc02eb4df99"
		"68f68f64b157f0fa12155625b6fb72a9e385de852f45f676f085eabdf42e1122"
		"72e980394183dce448966c19366672e57309bcb156cb76c598d0420a08fb8b14"
		"810f155f1914d9d99cfd11a139878f0f7a6452f47a995b235225bd30d4e3f477"
		"7cb17760a3d291e2f6916c4627276f2ee2dfc9d503784e9806cb83b6beaef454"
		"4a17cec44685a9063e9ba68f680eba4a92c249dd5930f72d9c0bbb24302335b2"
		"d589411169f4cc4e5c63e6056404196c7255f992e489fde9fc2d8d03910b5c99"
		"044ff8d176e8a0c03831552e83d1339a6ae0027e0c4b09d50e7922d9492e1411"
		"bfb01c8bd429cd67bb4d1b952e3cb2de62aa8c293a3dc2f7bb36a231c0540323"
		"eef5d5c8eb7ffc48cbfe5fbfcb0f3b4042fcbe1ad428d159e9ae35905d45d1d6"
		"7a674a0f23b2d56d518e4936c41079c7f21ec0d944d4dd03812701808ac82733"
		"494ba4e8e489ffdd364302817f08117b5a58bbeef0098ffb6cea3188afa7ad40"
		"44ec0adb96cd23a06066b22866beae6463f2d7e2428f8f4b903feb3132a80a07"
		"5391a571a146e8bfb93e80b3dffcf68bf3333b3ba02d84fbd76d57017c94e690"
		"5f819d316dbcf741281595ab548891f7f364108474ad161128be9f82f532ebe1"
		"4e0519a462f7f72e943119982c2b28b04ccd7d4225d5ee976a78e83c054cbf04"
		"0a654150e9be918ee7db3300cfad63bfe4b6abff1b6eb49487e45db615a80a01"
		"79e93ebf68db6d6a085b0b6da5d6e92ba567c142be3f1011664a23788b1075de"
		"85d93879491432c9dff9ca66166e63fc7627e8947612a815eff2650ad149a7a5"
		"157c5604f23288b454fd98748a3c783b3e40487cabad27a80a2349f54d1e495e"
		"101bc1eacdfd19324fae9c1d6909d1efe7f80882c5d933d29f27f7c06956030f"
		"60fea1b3403c8a4bb856ffec1b9d15205898512e2c5e749c964498f38cb87cc2"
		"ec6d1de5b5b98607773be86608c0edd679674a094804940dd7c354161d0e5d7e"
		"9cb05d0a933ab36f74a58015983a011a32af1c9a8293382e4bec52b2861e4d4c"
		"580e8aa94288b98a98deef8034d2f8f36bb6ee6940d20a05d806bb4e2eb1f533"
		"08d1cc4b2a6b4161c92d5c2f42527b6a0cc6e9ffeb8ab29d675bb6737d8efd3b"
		"943f4a77b3aaf3faf0d9efab2c803186fd2534e3ec83d8fbe1316ca8db7f0c6c"
		"e4a12db5450f765ff62bd27b5824c34f261bf99da98523292cd10575b04acacf"
		"e13e9c8d48607398c16b2a273008d8cd70f25db68c583b2e3283a86264b8e16b"
		"7160c088246691ab3be122381af31909c1f08ab5fcc3c912d98e7df85f91f648"
		"7d4dc12d41e979a24bd4df3580ac2d0a035fa822619075dd0b3cadbe0a9db46f"
		"ee4ec60507b1d284d88e8ca6c9fcbed81c85de862285e698afd3603dcba3c0e7"
		"aaabf797df85455acc554f135dab717cf6ab5568a96bc54bad9cbdfb0b6dc5b8"
		"9bac7d6b2f2e7a2b0e725005a481f0fd771835505d09b9fceddfed8233c169eb"
		"a8998009607518ff862db8040646e3638916a5c6a6296bb556e4185aa9685487"
		"b8b927fadb20c8df1ccdaf96ebc1f1b713ebcd53ec91827dd2f26409d72a2f94"
		"b5559bc507f731d1b89c5c45bbbbc300fce0d67e970aa75d4952fc1923cea21b"
		"86b504f24bc4fce042e0e898defc01462e3de8d00f5c825ba14d0612f71e5422"
		"13218909114dd011a2e27b17bc4c5291904a2ad0bd4fba82c329ab7abae0eeb4"
		"44e15293c05b566ec0ea3b4bbd735eea0a4fc50607abf8d7972e12dbd4dd17d6"
		"013c8818bfb635fe843f53bb4a38ce588493e1fa5637e36405a664bcaddd7892"
		"327c531e782616c9d72be9f0c9644ae4e65fa43513bc2430f6d7c8a6ada8b9ef"
		"bfe7da2f5273a1d89ff42670a4bf799518fb393ea4026243500a67203c0581f6"
		"90c646d2b5647d32c6e331c54111047303afc69d73d146a6fd8868b2c2bd78ad"
		"8d60be9009c353df324033760a2292868dc374dbe6f17860e396f4e4a798471e"
		"9fff6befb756cae8cd53530c65baccd79f7e6a7f67299f79ec7f333f535e9651"
		"ace9757925e68b547d63ba0ebca05a6d2229d1115d4363faff894c4a2ed70c4c"
		"9d6703b6bc3a3d2b2cba8f04769de350fc0cd01930056eea03fe688da1cb5219"
		"5bc13d2de41c8976c19efb77fb790f89176f902047386551e224ae91120110c0"
		"cd3f4c660652173c245826eeb3fc881f599a38ad0ca4f337834447ddea42ed47"
		"da2958e988a58e853d3037f106edf31aacd4f149e610bea5cea55afa925691b8"
		"6cc6883fd4dd9759f46d56085c16fb83f767e37b3d456ea2ab91106e7005a51a"
		"6a5f05ef50c2d9c13159adbc1d3d4661229935cb7a0cac37024e91c3ee17d176"
		"bb3cf781661bfdc4dc3a6194b12b7cbc14b310c1032b206bbb2504807353bcd3"
		"49a5857d7db2aa6bdd599d1980a8469cb7fc9be6416a7146be5e912e66820f39"
		"fbe2d76cfc4d89bd1cfe87d1f37c4c0af2beffc19c9347d0f3416254316c71b1"
		"b93a16d64db541c281714746706e350dad3f63db7d6c4c1243169c7a3bd98b41"
		"6bf76a41d7b27b82f5f906006047a9aed0c9f0ba4abf261394246a29ec9105f4"
		"f95ffa37020cdf065edfec862ccf52f444a2cde86d527ddbd0b4f2e7ac5b86cf"
		"4cbbef3f368a1455a66c205f3aced5e7ef1224ed4cedfa73dd0e5c3fe301b6dc"
		"4a5270e2dbf5c377b3e5cb16f40cdd8fba631a4f515a44e2a57ad1b6f9493e22"
		"dc6ea6a6591593756f951430c15010f58ddbd998e26004300e4079d656fcc6a9"
		"eb55b91619b22d56c0c324370864162051c4894f69c6e26602a77b2663e2f57a"
		"5d50d0b78194382290b622b3330e9818ec6451fd4d55858b68f8ff2e86c2749c"
		"1ca71313fa825de1c6b7372aa9173ee648045a29f6d596a7277c2f772865ea17"
		"0ea2abb1ed46449c4a0e8b26d247af914cebcc5bcc0ebcc329783188b29400f4"
		"1d89c019c0a6945b0403452e16659421df63ce1c37c7a0e555372de98a155e3a"
		"30a379d4dd6bf624dcde8ecbdd3b949febb288f29fcaea1893004c231ab0abf1"
		"2e39ff69aa5d1101bae68d838f8f5812572123686cdd4161cb1ab5bdc92f9021"
		"01937a6091438ef986646be1942a87820bf8c70306c94dcae5ce923ffe58b4d3"
		"90f91142f8e6141428a04f6a54d4caf7ee7f9b4dd555b75aca64083223f5c00f"
		"c3b3ec95490f4c5b88e262a83854c97aeafec8cd424b27196024411d9fcc5bdb"
		"820834e4eb84ddd58e72cb22a6742b12e6bc750bb371441090556588daa62e41"
		"b54211b4460e718b2397b36007fa99c8cb02cb909191b74643419bfb3c4ae048"
		"44a7aa8fc274ad832d9b42ebc4afbaa37f18f2e3457127c35f2e0cff2d821af8"
		"178028fcc7803bc795c49f4a435b37abeb46118c35da3d90cd65e01b1514845a"
		"1714b284bdf8c35f445bf305eec6b7e8f7d45114cb93a1b4762e3ed85cc9c575"
		"2aad71ad0ca5ec5121a765a52cb7e3638c09d9026e66fa3741d04ebd6a698652"
		"39918d021c4f5fa713f21eb164f86323902ed2de8519f12215953a52a7bc6ef7"
		"2d092d0856bdc469048246b1004fde30ed8b63317a752d7cdcc3271f7c89266e"
		"ec5d794920b9c29ddba1042d6785fc938968b581b442574d7da33fad4f9a55bf"
		"60d59a4ce309014d809580ae016266534e0def599b48169ee07daa8389b5a4f0"
		"6fb9b89908762a80daa6e3bb36adc47822c13a3e974e1376ed99902993a3bb0b"
		"0350fab9f5c8e53fd31e55dd6e30bd0befcebeba101ef5dd8c3e1828d32c4117"
		"03e3893314c7d9915243fd9b11b1fa129c7aa2546e7e65dba5b66a07b317df1d"
		"57ba8d8fcc3baf7e405f047d87f92398110e0f9519370b792047af4e9a2e3c24"
		"e71d2d5684eb0e0e83b8910b38d0dfa236d12c037a118ebee53a0f86f0370134"
		"9b54910fa6a09f4a0496cdce8dfdd63af30d2228f7d397b3dcd7b1361cfbd555"
		"5ba6e24299220a39ab43e04dec4ab1673008188cf947cd5eee65bee688426190"
		"0f5d4877c539f6e36106f110be7d1832d50c37b5e933d9c9012e5d1e9bd44cec"
		"9fbfea3792ad0b510c2628a06c5fb2a1ca5fa62d2d6062fcfe78b767bd783f72"
		"f315f1096845f28a95ecae845cb828bff7498e7c2f9611fdce8cf44856f8e229"
		"f3a68476afca5396e5a0ab44f850219144141728559c8ed657b23b4ace1adc19"
		"88bccc05cf05d57ee38a4669a7ee46219a0668bb093c808f8331b4f38ea7d64a"
		"989df13e30bb214976f1a87ad05c3f76df69aabdb23c8f2e395388cefc6677c5"
		"0c921aa93ab7dfff881ff9ffdd60b398fd8304b4b76564bd615edf6081216891"
		"cde36fcf56c0b6a9005a608135c34b90da9d9f2a827fa743e29be033869e50b6"
		"c2d81937ea9d4e4ec5eb0587404cae6560fea3a67a5200c9a652b4ce71a6d83d"
		"d2b94069601750f6c11a119966c5841f75f037b107a5155694cb82b9ab01a82d"
		"e7cd0bee1ef664a9db2eac3f0ff477c703b983d2914291f2944d737d9d77678e"
		"e85da34d8e023170fb71fd02a3a32d63f1a2b09180ef1aa58e21afa1aed0bd68"
		"bcb1300e1602605209292d698a984efe27f3e6763d7558786a905dad45d354c4"
		"4d11d9ba20c09858ee9f63fd2c9c839d8df44c0a2e9cf57210e0a629cc4ad1a9"
		"82c5c6d813028289901bc844f276744a0bed0bd4bc2b969c6959b19eaafbdf20"
		"431420f05791c6edd8e484c842f0c80c89254a5c4fece5fc5b45a79447ae2430"
		"78480f8a54350b8cae44be1185d027ecefe5322b50a58a9dcfeaaf910b2d48e1"
		"09a7ba2f72b5f96ffb819fa524df3bf02575ebc8251f2d84ae92f21f5e3ff43b"
		"df7a4a6619db399da5e44e0e85e5a922131d9cbb382275bbde8397c5a8abd047"
		"e008e6b8b16d731e96b5f3d412aa1c8aa2256e8df0760a494905c70c513a830c"
		"f59bb7aca2344efbb43cb87d32f53a2fb8d488c5b4e29536d562aa7ac1b4b692"
		"0779e5ca54f8733be9c1c3934c8fab193e7312ebee2fbe8a6ce0679960e110e2"
		"fceb979a2f818ae61c8b3c9eca4118501d4a368805252c4ef5c927f197883a03"
		"be39f5a59c963a0535e34c2413d129dd3ba11a23618c888a58631108cc73dbfd"
		"33ab287201012b9e1b111baf8f0785c782c0e6446a2c79447df74e6868689cd9"
		"45895889c78806bcb85dd0c6a6add516d9eec37388cda8864ccc0599d430259e"
		"db1aac7357f47364f30e93f2c089c0d22775d9392336bc57ad2c5f2177931d54"
		"dca74db7170c19a0b46e8eb94565ef04569b4f1da3305ec0885d848ab8582c04"
		"327863dd719aa177e3c3e6a69d0709b44da94da8708336c7c5a89b5c0149fbb5"
		"c4d5156ecc64b2f26956c63e3037b7e8f4e6fd60f2f7eb774c55cc1db92c326f"
		"7a068bf19034f5172c6f540b67bfa1aa339c85cf915326d505ac415747ca793a"
		"3c52eeee24d012f01556b894a8666e01f2110d7db6618eebd8f51f9115eb761f"
		"f20366edf200b0850c521b615cf3c7f6198fbef1c7e7ccc0ae7791548a56d425"
		"845f1a77618e77dcfaaca5fbec2f538f905cbfb32eae875c6d7bbd270ed53955"
		"daaf3313d94011ffc5ad7de9bee2bbd63fc0394b517e68c8ff49cb92092e4eb5"
		"dd3ad84ac2e023f6579accb33cd3a6d30f0554429a1f170b4a29e41de32aba50"
		"734a32a3853458c796beb9e2cdccbd8de671371e70583b2d386330510591252b"
		"852569a68805557c6c606dfdd893a80cae4e0b6a3af27c37b03ed6b5d52b3950"
		"fc14a4db341ac51dc0c70f8cc7f20e584de2f7ab62b684309903fed2bcc09bc6"
		"be5f0bcbf13d4eb0793cc81701ae977aad76246b4f69f820ddfbd22e2317f695"
		"b54ec7fd2834983f8107c027ee92ec79b451ba3169d6830f636b775370f9f0c6"
		"c72900f93fc84cd1bf701e43f665b55d4cbde08618c4cb06139e18c90d2e315f"
		"de37dd48a0c1126f1bbf0bf481ee992e5c00bef1c4fa780cd5dbdb16607e626b"
		"e1c18771b1e791207d3baec1f7f641f5cb637dfad541332a9169e8c4d3b12bef"
		"b80f26fcdc0272eccd2d3032c04555ba832e4529b361a4672f91685bcc8e33f5"
		"4b69e17288d95cdbf3ddb8cf44a37c836ba93d07c62272cb979b8361b5de2384"
		"8217e05a1c35f8f6d8936f21ecd85e5a6b1c8e1b774c455eb2cf6060f569a2a5"
		"45604c3c02deee4462977caf1eaba4466bce5fed2ca6c729667428dff4f7595f"
		"7c8e4da0a19ce5cd7a30080143e6f6505308d9064ef99e339cd402671a50f0ba"
		"0fe70a0f6137869a09a83ba0c44ffb7e0b1224ed460d72843d35177fcf3b0ebe"
		"e6b4ac11aa7678b2f5453c1307af5cda7c34672a7baaec252fe08faf7b825b74"
		"e93c5a2ce422631e285034e276cdc16c8cb6cb465498b31d5c1d917f86eb81e3"
		"01c93dea7703f1e488104a967873d03b24df77c83b9e7074aa344578583f2513"
		"14a17dd2cce1c80effcfa7b67467344f2df893389786cb33036cd4215945f20d"
		"0b0d416c498490a374d372cad47293b08d49491fcf166b614e0e6602f2c78dd8"
		"cf55b14157b4f2acce66d45bff5c96672e1abf044d17f906736222a4898ba17c"
		"47c1f6d85f389530f7cef5f05dede47af6b31d6f78501c2b59b0318e885bd402"
		"5a9938b9c7d92337d653fc1156ed26f4cf5b8ce8b88b7dd6ea40bb4855fdce71"
		"f2249e6df85f41ca533f1246522303daa05c34f8758ec4120d59e75b5a3938d1"
		"f6ab517b5b9299ef56d85e18b958243651fc3c26172298e4aa45dd4efdd9ba2b"
		"4d76796b5739d3b0c768090ef354300fc984ccfb060fa156aa4ac6a9a8a3fb86"
		"e1cd3cc6531e97158e353ab168dfd06ef23c0efeab1d886ff3b1caf5c261a4ea"
		"99f8c513b9078b2594881a8781c1ac5ab36b28b76c14f5376ec210b9b3d95c5f"
		"5d3e3adaf0bd5ae8bfa8d11aa4c16bdbf45a42aeb2bb8fb703c4c17de2d4ccee"
		"15e9c4a46008aa66f8df86f23aa9b5f99d52856ce6dbfff69b0104cab9199c9e"
		"a93f8af771af24a828736195ac3f34bd979918786e3cecfc1cbf02269f727378"
		"0289b55e8b7c6fb535ad8b8d604c8d2ec877245ab4a6ffd27047e21cfca5f982"
		"060e6c5e1635339509d52c62c0976b551936d19b1ee1e07f7de1cd31397bd7c6"
		"9e18d8817aa31a518a336b9a33ea7438721d46c216b4360b2dd4ebefbcbcb54c"
		"b3ed204e1f8ecaf0a20e71bf200b50e1bc73ac5703e9aa7f666a63ddee303a1a"
		"2bd66e4d6ebeeb7a38b06658f1c3a858dd812ae24d46e3e212e95e83379e0f3a"
		"f01be707cdfa26f8335f71ee0dda24a3bf8fe9ec5b948a3c189a036a00d0dcb4"
		"e804b503a50b23717d64ba08dc186bcc48e411fc979a469660c57b19af8c488e"
		"fdd900c95fba89edfd076a2ec64526db62cac99b6822c0f7d2b2ed18ae9bfbd2"
		"16e1efe261cd00749b8fa9e93328fcd6f487395036f29f6756a882f063c59e88"
		"1a65abd5150c320f3f469ebf8b8a96c7e6648aa36ad48ceed4f1622838d1d9b6"
		"f3ad5c2ae241c4c5d172723a36339bb520a9e41c6a8d2f9534d3b44893895366"
		"8801286a2f32619f395c4ce29cebb4a9899e6e449fe82f635e97a1d9deb3b59f"
		"c1a93a1c66a8afa35f4c553e267a89aa0b8b51a271ac35613a8450628018a66a"
		"86ecb8c8ee6b56db2c89b5d63aa7c1c08db7b4bf49a0e895b1e4e96be180cfce"
		"bf14cbf72f43ff4f865d9332423b05f3f86bc0218d8ef109a9fd967c69b3d7d3"
		"54679a2f91f85206570e17dba4fffc4c32ef9d52a73cf7c50b197d1e80786881"
		"2d2e4efb7c51f60885e56b58cab84fd2248b72dafd72a3cfc07ec6d88e9827e1"
		"33b00ee05818945df92ab4311a31a58eb687673ff9fa9d31af749a33fbdcbefa"
		"4c3703688d13d30e9c251deffe31a786d12aa60b019b8cf3bf4521b62f09d5d4"
		"6109541a830b5c21551ecb19dd7ffdc45bbd54c57f1c181bda3782e993ea1378"
		"5b6f2a7ea2c7d6a10b5ce9371ee44e503e889cf6da46eab3e794e6548d4621ed"
		"20b1ad1d5311ea93a8289dd12b28423060d3a4257ae1aac2cda2748086e4a63b"
		"9a17047efcaf400113ca0f706b13826eabe694dac7b5005176aa55f4e78d4b6b"
		"afe9582a076a7ff2348a699b466cb6120508959e29899267c9f3b0381609b884"
		"496ed0a7da0a4f6ff3afd0db24fd86225883cff708260b0caec7aed57d20948e"
		"4fef957fdf575a7f38836eb76d8c98a88b9d6970cc5511480d6c7752829a8892"
		"a9b4ce397c19452aeb4c6bb789e297ab869f8b8edddc4c24ce2b32378f3e3b96"
		"3f05a45e1b17bb78f453ef63e1c7293431d15fdba38366a7da4c070d0bd556a5"
		"f92a3f75231a62723be02144db03f64a747a0ade871404da17171f5a5e2780c4"
		"bf6ac606fceae21fa93b29e1e05da7f537e3b71fef55d1c36ed4a2a9effc62fd"
		"790f629a0d4fe48824ab30c2599ee43d62558c274410726cc7cab87f281ca357"
		"0f5f3ab8c01110b395795e70ac8e542bdd16b17def0b92dd0b428766704fecdb"
		"69a377e87cf70daae5eeda7243f5a0c6906e4fa9560fd71d20843ae52f5ce58f"
		"6f2240b2aaca8475fa50cd50849b701763a78e34e3e3e933f0d8f785ce0c357d"
		"0a26be9fb0521c1abee75e93d9486a243f0895a5fd51712a6286e6ccb32785ad"
		"20f51836f7577ea318fdb6c2a9c339f70ad88d840b1f17075dd5314447757c25"
		"9ad877ffe7a15117efd8fc655bd58398ae609d5a771682d4cb0ffd75f2bdc3ef"
		"61170383e8f73e7f2dc159055946f10d11e8eeada8fe5b99937a75e61dc90113"
		"5cfae3496323ede2b900f5290ade2a601db7a808069f495c9d5ebe1f2e5fdf97"
		"72c940dabeeb05487bddf759d664d799b817f2f0f9c0f527d10503a88f480585"
		"8dcb41bc63182fba5ba0871d25a29fbecc4ef4efe92b060117b66a0aa64c1ae4"
		"94490f79b872123e4190cffe5f5e2bd940a5d78c3ea625f357b81bccdd32c7bd"
		"6e8bd19927c057df15f6f483ec6122f1fc64c35060fafa0379543f769bc4b317"
		"05d9b0a217cca5a2bf1a213535732d0fe8d3dfc1b8ef2c3b65d2fe9047c886fa"
		"407bd41ef05ca59127447c9aa05bf43aec3a5469ac4c64a3037a7fa34b07ea6f"
		"07b864941939feb336bc2d3c96e31e7af0e049d0a5db49423c93eb360e49857c"
		"42da898dfc2b5910d2c95da380d154d7dc0ee77c0c628420f66769d2f855ff2c"
		"d9276a9000f95eb1e4b53455c4ee3d5a980c56f747aabc451a3c22fe71f50184"
		"b5e830258d6db49d55c6d9dccc02820a0c22bdc9c07b9aba915b3e42e1ef338e"
		"bc6402d40b4d04dc0b4575c0fed5caf021984478dd9cc686410ce426b00c3c51"
		"d7e50926e262f577f07a2f87c42ebe12bdb5158e08d7e7b114973c334614c5d5"
		"efb16ca27b743075ebac30bb85d7057ac9c25593a8f2a544f1436ff00ccf7523"
		"ea1154d13c4b5cdee3249fe3a89648302e072f0d24b6aa46bf59a5e66805f542"
		"b24de9398eae22bbc22ba58897342f3ad2ccc986e6eb9bbf6821059bc37dec3a"
		"2dad5264da662a136f076a31b97961a29f594b85555923b7d3e3b89986000314"
		"4579b8da863c1beed2001566762c87707cf5de93d9c7e837e8e7e6681756e2d7"
		"e1f84221fcf59e54d360cfb0361748aa50eaaa37daff92468f74b58ee047308b"
		"e87319c3a25c5a4e5a6dbf9561004d5a057ed6f9c0c7caedb0d45095479b9538"
		"44326448e238f8e34f710e9f5fb03e8782fa8a61f4e83833334ddd05b619bbe7"
		"dc7d4c3623501f1c9ab2e35699efc23aafa6f0f8dc2a832000288564948a47a0"
		"989cf917cc6d78ff237967417584817a74c92d45e15453bc00ad6f3c49b6e469"
		"60d692724757aa97d30dc1e85c39244fb9ac6cd06b3052101923c4143d65384c"
		"1c7540d0fbd65ee990b81ad3b7d453c16698d322e384262334d4ab75d85feb50"
		"b4bf2ab850b23cff43c09a8bec1eb5d963d38ac2af1977fd3a064de6826ba67d"
		"10fd79b2aeb2ebe0d56e689765dff39e98a5ba3839b7eea71102d1efa35311dc"
		"197654467da014942c0aad7f88dfb419ee588b0de8253228a3106018a3ddd374"
		"b574e4fd25425e2432dc90ccbfe5a1504b3324c8232dec88d67722eaead2944e"
		"cd3d505e0e607297cd2b3a0571bb624d997daef15495c4d094813eece0f9fe70"
		"4a1ac1f2a1c4f7f5e741d3b205279e18be7f5011e2266107c474dda7ed1cb7e4"
		"12535f3f443596466764825be5f2fdb7a48133af35a86c354e9926a17a0167b2"
		"0f3051cf607af79335dd6f8978e4293431ca7e53b5e38c6219384264ed71b7e0"
		"27f9c02a5e5cc1e339f4c3c326c4c7964fa45a85ca9f6a970f995878b0344e78"
		"44f5d3d6a4a39d3f5bf0a692575c82e6e555efcedca3aedc170391632912d681"
		"4d6db35d9c1732ae831b3f7d7372ff2bda2664b553b8ff3719c015afc2d3f404"
		"2aa98747ad7f293899bbb70ce2cfe96d185fe2c397a605b2fe160be3e23e5208"
		"c3f1781a3ea529e5851935c70d3be6b58648907e10356954ac4e9b88f01d9895"
		"008dae60b94fdbbe2f7de2375a7d9e0a0c299770262cd3250cafef2556366eb3"
		"c9c450a08546e6ca7f2ee6e3325fbb7492491e214255ea2e06832c427b517a6b"
		"06e087630a52f4125e766853fea7e2fb00f14e18ca76577683107d68c73867c4"
		"9f277a30b03aaa9cb29b9010241ebda83e694fdd2858c20569a0081da2b2dbc7"
		"7ce2528fdfc8b27265e687a10e8cf48235f948f8c2c3d1e4a279f5ec74867e7b"
		"85583608ffc2b49c5d9f758e22b92f91cbe961f2027f2f1a14e36d5aa57dfae8"
		"a3d34f2478f15720840e8260ca6c15dee980c4514f5382afa92898f19d5ff416"
		"bc99c46ab21d4408c07bd49e6d6f4e70780796a0100873ac478f9d38c5f4170e"
		"b9f3be63160e235cfb2d96d0728883505ec60264af66a918d85fa4b7830308d7"
		"832965950a8b9b221c6dee7f43805c8485052d279335cdfb43e1d7f740567279"
		"0083e08af75e54640b830432471e8016d30c4270243d865e705d5c7f65b3fbfd"
		"1a4958ca464df729b0b70171e62c980d322267c8ca467d48471a5bd758e34b6a"
		"b8c2f4db5d212c7af3500dc488704b728991c4b6ed1759c1b062fd8883ae0bc8"
		"c237dd47a6a19a5ebc984fb495b4424cbf9f83c2f579c3d1937b69194ddbe31f"
		"1ff03a968797eaddf3d5f0c875be24a3be95c9744a346381d8aec8121d347a78"
		"b935344e6ac9c3ff8050178991569a806dbbc1555410e0d8674342fc5d7f79da"
		"774ef3f9b601cecd4b51ed7d4f464ceab45890ec7cd5e3de2882fe5e7485874e"
		"41829e1ed305b34e3c209a2e1855e1e97bb561c1284a139c04b325c0ca0e4ddb"
		"ff1b5e46299d198a3c044524554a0285aa1b5a5dc1381919e11ddeaac7e27389"
		"995f5af82093a88a314717e56cee56c72ad0a347b0679c5ea90952a5d3c8a060"
		"f897bbbc20ae0955052f37fbc70986b6e11c65075c9f457142bfa93856897c69"
		"020aa81a91b5e4f39e05cdeecc63395ab849c8262ca8bc5c96870aecb8edb0ab"
		"a0024a9bdb71e06de6100344e5c318bc979ef32b8a49a8278ba99d4861bce42e"
		"bbc5c8c666aaa6cac39aff8779f2cae367620f9edd4cb1d80b6c8cd4b9bebffb"
		"399c4b249a27de121fe9e93eefb9f8d70ede43088c778079fd1afc1829bbea19"
		"04cffb3be0b22f4ee146eaf2b1de4aa1765ab8f00193bd1148f9179d177a0d90"
		"02a6ff969e114185f1f92a2a26296748851d95dea36710a9d65205eaecc4cf69"
		"1d6980ba3d0dbdbf374ad06eb664f8d42571035adabd1f488e6cee871161d8ab"
		"3b5fa531266e4b049a810446c955a44e3d9c2aed0e5b95f65891f9fdec19d15e"
		"46d19782c0fc925d05e5f03bc7c614bdb5e7311ea70a18bb1c074ed3e7b4628b"
		"25077d35727f3bd15dbfb9d4197df029759a41760d9250a0c217169169f93239"
		"c04980d2a6beed698b578a9a2542df9b64fd817ca9bbe7ac330979c0d9b1ea70"
		"ffdfc8e2c382512c77f5891454df89196c581ab8e14d82e855259ee7a1a43138"
		"ca107ced31930f2209e1deca0e1a97ae74f233b21e0fcc5a11b3ae8e289ab09a"
		"0926c57957b9ce532a62b244bcbdb15f6514f5f3c9ca6a0c50fad03dd65b0f9d"
		"a467ca109fbc36c8c0c22d0bc48e7e362506880248460706f8432d7d13aef54a"
		"831cb4397063f088b44776a69056a73a9d101367054b494ef2d6ecd5475d0aa7"
		"8f8caa7d3277a49bef3ab69d86dcd373b57abeab66a1d8ee27fb37ceda2ef7bf"
		"ae01d5624ec1f90a58e3147910eaabea568bb355d50f5dee7efa33ee35ea6497"
		"c9c15c722a0698dcd689b9c09546d7a6668c17edb95f8054de1a0ac0be59f839"
		"c91568352f1129195375ccfd7db9feafcec515fb7a57e82a31a4e4c9de425cac"
		"94452132c5a953c9b6f076b52f0bc80e777ed20880c03e785ee0e893fd6e38f8"
		"1499aef15595bef5e740df721504dfca48ff799b326129444d163fa584a63326"
		"2f5938fa459e13a5cdad2ebb966ce8eb288f303dfa045298e68e1087d9b0f53c"
		"cfcce6d6ff8cfadf52818c191a0a8e7a01781f753f6f607b118f84c266542745"
		"db3be10ce9271aad5d02201309a7767eba0070cb6a6bfcf6b663c3dd925c7146"
		"3bee50246d361c16d77a1331cc0b4bff3b7048c7e1c0ce0fbd50f460c48e7a49"
		"d72d5ca6f283a723a62f8cfbc9feb3066c10d2f20d367dd00e9f40d366b4eb55"
		"97402d1be0d464dab36ab4fa69485699352733d35695b2419198cebfdf946b73"
		"636eea0b9ef2fb45e672b2b514b0dec37eff96f325a414692f82c7ac97f7a3aa"
		"2301bcfc96a5136c2791afb43300f0892fde21d8e02c4c50cea75220f6a43a02"
		"bf3fca782fb454555f0dd3802cfe37f5300dfc0cf1f501fe574d98a56465d983"
		"1f713d06d1e9680a742f45a06973580e69d45017bec7dc7cb3bdc0c249002836"
		"2bde3c2fe40af493503f2e9c5026fedcc27a457fb16a85d1c83ff3000d3ece22"
		"ccd0f079d0e0a3f6d985b5fd4be1cf68244902ce30a5a305801a59e518e7744f"
		"e88d806efe331a3df948034ac16a73b97587b08ba542de21c29819fbd2c3c1c6"
		"685e1596d4cb047097d23f0b1a8a93d79f7d763f7707e02b75ff5ccaa4995e8e"
		"358bd778bb6f07959b6992c9bd09d7cb88737d710ebd4e2e839849d9f433f2af"
		"355ced9c1ce9cbb6ec56240a14afe69c1ab0eca9d22cd32fd3ab09b02b572632"
		"5219808a5dfff9da74e11c59864469523b7eec702b1b15384d80c3d7b2cea21e"
		"7309b7cbe87a390a1a51a33b7b8f07f6d523a54c8153bc50d95ea0d7ef600d7b"
		"8075bbe62321324dc6f0e03a5b59698fcfe83ec83c9d71805f8fc8364cd41052"
		"60a5b36378be8dab6004fcdd8f6a36251115e069c4bfdccfc759627f30f452aa"
		"fde1c8cb4e17f12cd1d61eac7d8a17c183f2b2b98181a445f905963703867c8b"
		"3e7122a40cf607d9ffae6f308e81b4690dc7dd3fdcad71eadeda8ee82c5335fd"
		"0b9ce8791c2177b9d3d417f02a16b42897db88833b09edc75c226f1915232609"
		"4cac43cfe560e8d4358f3d75ba13c0030977dc0e075fbee35c23645325bef6b6"
		"e9e75a30cf7d03330e280945a43e7f044be30167a9758c46c727921dc4eb4e0d"
		"cb965623423e6fdd44e7a4ea525f9a3245671e16871300f9837424ff5a74d614"
		"d8005e31a66dd4dac11436ec2a40b895e04b5ba40b03c1037a5240814f1f35d5"
		"f96f9be063d0dc336bf7e6d196a8823602d6e1989c0c786c920b0f2c0cb51458"
		"172934bbe1302def2cd8dd23fd5e9f1c9451d87aa1f5cd3db5e6b887f7fd1aa3"
		"1877524789546f16ebfe4369c72bb84f7f0468d38487677dca2a631b79c1f0c0"
		"e6a11d0ec1064bb190b23f2c5bd775d8a937b729ac8aef34b9203a6efbc73db7"
		"67efbc97f20c68c7023cf9f3232a7dbefc32f00781c60c6a6a10620ae3d8aa8e"
		"85a9586a852f70602be49a4686ec79095f3c39f26b026728c44106779abcdf4f"
		"26161810e0370884f2f24aadece410c2b99fba74d208a875b1fd4c3b893b8302"
		"347f25106decda3c3fad30b1bddbebf0f4a19d141e9e765a198a5ce0171d3ead"
		"962ca6f293168e8ffa5e75d96299b29bf78b075bb78d79dee2315feeab29ba5a"
		"3465c43fb97ccc860c4d40ae41e60ccbaaa522cf069c5a09f53a7debaf289c10"
		"f672a77e49e73b285bc2bab7c38aa189f53616fa7195c1e33aeddd618ae38fd8"
		"c49a7637aa1f837dd0050b7c504c1adcc0880b64613e55759992a8d7a41f39b9"
		"86275af244ec4d8d535d5a8551f51fcdf3e128933f61bfc6fb7005d665a742bb"
		"245f7a387f164161cd14cf5b2c4d5763768a951171c4a7de46d01de5354253e6"
		"868bff90c3640600247094854b1c6ba631cb7b666130b3c664fa188c7cb71443"
		"95f21083789f457242bace8b142a029e0deb0218756c8e853b361d53a2cf2cd9"
		"37ded698068fa5c00d39a8f6f13fc554f03451b11742de23b5cc54c30f5244b0"
		"55957857d5fccff16f37484c49225ccfc4ec91b9ae784ca9b903e6632b0803d1"
		"d8601f484dae6a0d4ffad618849c6e176f5ce9b6a2d77f1e2e25fbbb5fb81243"
		"a687f3f4d76c1f1d94cb7bdf0975a335dbcc82325a27208afe78ba54112c180e"
		"a9521be2d900962728f25e2b4275a530ee8383b44030d6f610454cb5ab2abe3b"
		"c709c09abd307636f2b7a9839663191092cb15c5bbb94a694cd3d966937bacd1"
		"eaf309a5e9c5674fda6281706d09aadeaeea60ec338c23eb9a6c88f033e789d8"
		"f9591f8ac787137cc83a1079302dfea129298bb1106f0a84e25681daf135fd59"
		"dc8329d1bd3d1fc4a4887e264598bd61edd0bf9cbb2ba73d0cdaedac372fb25a"
		"7bb9500335b136305694f3ff15129026e12723369a88a11d0040f4ef6c9b4de6"
		"be43bca796a9fec6c7a6968d08631ff9ed76e006164da12ca7d0bd2af7427902"
		"8d68944548ee1f90dd068f57875211e1f9041d9498444e73e7d271e542ecdcb8"
		"d0720165b348429681fc07e5f8a80ee7ed1a0369863351f9a98d37a9b4601e0f"
		"6fa72a903f7e0fdf9ccf26c0c42dc012b100ba0c49e351c7d64a38fcb568e810"
		"5250384d545a2d7314c8136f54a9cc6a2efe69054a1cf7e354519b69adcae2c1"
		"61b452255aa2455ad32ff77a0fe4ddf74a5c38ddf0a5eb570dea8975044fb32c"
		"851da19fb91ffe9cbf4cf96a5ca599c2ee61501ba248d42be75d2aaa23bf0359"
		"a4d14c43d9990142c26642c6a5b6a8d20356d947cacb5a65ccf1a58f70e27c4e"
		"a7197c9922d8f554c3c6f91651ddb32f6f83faeacff7260fa3ef23ac5480c415"
		"773d592afda383d8a9b547e3c8e362e21c30dc8b1994e030549fcb8a386083b6"
		"fa850a7dd0c353d85e7954b371905cf2f0a5a7b2106a30d1c649c6b0824b6237"
		"1a39b81a04010c5bc95a4711b6ab4a67d52982e71c40bcf9e3353ba69c0908a2"
		"bea08a8a0223566ad2a24882fefed34ab20695b3a5e02fb092ab53f5ec621ffe"
		"ce03a95431f1db0c61978190b24fa0a26e82099d13102ffebbf23624dc1e4c54"
		"31aa3c00f83540495e8317c238675877f3e6062ece9964ec46530bbbd20439ab"
		"d1dd6c17c1b53029b1ac35a0f90ea4d1287ab3ec3e4378811c16fa4338dd8e0b"
		"95e46120f33a51b5435b01b35d0b2cb9f5853961cbd510c623832d437571f27d"
		"650642a3f58c4bf4fad7a382cd2897364251c015de19d7c144e1c943f1880e07"
		"298d37283173c7efbf6a4496af2b8e51f7246f8fddd5727c687af9cb14ea8ab4"
		"c9bf6a380eb76dac7b5a0c756cddb811fd476e5732d28cff7594e364465e0d89"
		"2ee5005af41fe43514f022a96d06be7e3a02e6f543d8cb505578af95efae3f90"
		"3e4624174b75d5927474afba196e47a0979cfff17aafd779ee6e86e777a0cad0"
		"e22cfcf67c7fe7c9812eda2ed7dcfc80fc5fe0d43e1e59822abd90e146fd5351"
		"03ddb07fed06c3e42565cc8f111a84255291b226f6eef971efaff40bc48c851c"
		"87a2693a07d110ea4663ac642eee89977f7b9c6d0ce75e50278adbed5a170538"
		"58c34fb032aa77e4ce6ea3369621b0df6d65c733e7d13126b9976c106e647ead"
		"5c888968d757a0d9a4cfd98cb07ba30402965affef7419fc8d1ed0fb6a3d9684"
		"7d3940ea5ca132d1b0ce75eee6c30a0e28587e5a8c98bfd98b672e36b468f5c4"
		"a11d9bbf2b50d6d5dab2a0e49fc38c06c6f15bcb2604cac59bb9af4ab6ad4475"
		"b27dc36eaa2c33eb0ac581f74441d2f3c4aa18da2581e3c9a55e7bbed6d62b9f"
		"97a1df7f43fcf21e284d41ae3b0684dd09cbde0ff1d7b2eb919cb91a7ea9514b"
		"38d1187b5d8aba731c930792edda49cc7f9cd4f3f2cede3547bc91e715f05f81"
		"7d5596e95f9c34f4cedffc2ac284c9c90d65230d912d10afaf052cab0371fc47"
		"4e748051b3fb07a8277947fe23ceaddb9b6df2e534beef60b2c1b2f1aff5d1a7"
		"9378fe3bc06fdc970da81296767e9d0b12fd6a044547245036364b3e834386a8"
		"34a73a30eec05bca69b5827b245d4060585db3f12a91568724ae1d1ce625c252"
		"194a59b7a5b52b4824e8c13496333fe256d5f4344d642e0e656f531240612dae"
		"2ba886594d17f5192489f74933c84199f4ad5556148854ecdfc113a9fac070c3"
		"500be79d4eae604653e04b4262e3ef8e1b2cffdee9c46f297cee85677a0a339a"
		"71b9a40b114215d69835e6a88d4ef1c8b19b1a5433e127ce233dd3d729071d39"
		"77fbe62bfc9bbbd1dacff0031bcfee4f9f42cd4159a826e1bcf5227e6f7ed7aa"
		"4819d5867880fb4003f790d9742f8f2cce69412cc5de116d2e5f9de6b53909f5"
		"ce5b98a3eebb7d2afaf5eeb400357b6625589e9dde4e937763c3699661fe5a20"
		"ef09580ac412e897a711331b26ab5a058b560b1c0cbf52094269b116dd967235"
		"956a3c44644ee58ff29387975157d612eaadb032b7f8f62ab3989bef8fc9fa3b"
		"a7c76dd834371b1bc3c211afe603959329a3b66647c228e39e994fa8e15e9a3b"
		"0d68124e9e94334202e7faeb4e753f933081454124e5903bebb5f6c93a1ff93c"
		"af95542f082fd40d974a69d3f1767d17e78f844ab729d53a8331b8da01d2c046"
		"75965b02dccea7826a3387f037cdf72936149c0966569fe84c58bc64a0409661"
		"47b24e4f813a53ac64ea7cc9894454d0055ab5069a33984e2f712bef7e312496"
		"0d33559f5f3b81906bb66fe64da13c153ca7f5cabc89667314c32c01036d12ec"
		"af5f9a78de98d93868e188d0edad59fec34487dc3220b15fe497e82497bb076c"
		"157f4265661b02ab44b1f10ecf305096827991c466c0221b853587dfa2e4ab1d"
		"27da78eb5f8aa5f1e56fcf285df2cce2618d3c0bbe3160aee1e530ba8cb1a707"
		"ceba629431ae691335624da7fdba73ec49caaf38a43a1420dfef0b3ebde7a332"
		"f06528e7444ff7181bd490121951edbb207613d37fa5e67a669a41f29e5146a7"
		"7624f36c0135f6087e0bc3f11880e357d0da8f64b7387dc36030fa5f95b6396d"
		"493febacce270feb48500ccd620dfdc93f3e4c74b4bc8203b4f75d0b0bdd248c"
		"4ffe372e14eeeaca60eb932c5fc0e21857e9718addf89c424a389380698fad0d"
		"72a9007a3c522eacae24819977633b4cfe25272f9cb674890a3ac34615947ff7"
		"99876d19ac1b849a1a43fe9912bcaf6e1e3896ea58bcb2dfdc4716e379b44052"
		"ace1a792ce11939b8c8f31b69895e7849e6be5437ad3fd4da8a5b4e1fbb79926"
		"92ffd56d09fc04b7ec51437771b48a9966063dc268c3fdda569dc4c80564317c"
		"35292033c4a37ef622d25c6405e141b25e51c5f08b545b8ece776f1efe84b15b"
		"7ca7b06b69cfaa611657a206bce6b4d96e94a6544b4ebf71f87bdc6d4edfc0cc"
		"4fc0ac9d5f482fffb12b40e4ff8a8a157e1607771178d08cbcf1343c5c3d07d6"
		"96be3c520ed6b7d9d9955c8734946c6f762011df439b37e603209e1492662d81"
		"39e78a10de41e7f577dc1f75c5cd01ed3efaeb164b7f9c87b351437c5721dbd5"
		"2184bb623750695d7449b03818fdf29abeecbfa48feca578b6cc4afc1338b9db"
		"34dcfacd81cde519b624375897ece67bdf3eb20f79aafdc0f2d9dc1c2f716e9a"
		"5b396ddb247e022f27b5de5ba861869a8737eee16f804a6751c021651195a31a"
		"7fe13c13882b69a9ae43cbcbb5257afe9f209ba1db383576bac8405e226cff64"
		"861d90fd159ec28e3218262f250169af1041e0d8249865f4143a6290cabd2b7f"
		"5a359122349eb4e79d7a181060bafbb6c0e2e60db26983e9495eae817252ce73"
		"e17166094bf2e7bbd6b2c9f5ce1bd91a994bd5c8ed72365e407c4dbb80f19149"
		"0519383bc4630412c5076066d7ebabe382c4d4923d7d2759e1dc66c65e631c08"
		"ac742e3e05b9b3f552c305ebe3f1181962940bf10a50fde514c62228726f16b8"
		"c0cb719c78bc9b6a652ce20d5af6c9c52304a36fbcb56107c181a96b26df2862"
		"286628dc8333657ce68c1c53a4c266efac5cc494bb71fbc9d0562216e17af90d"
		"cc8d7c8790e8b830bd29de46291d969de5e495e76f4f7232298db5b20a0732c1"
		"9488952406a13d90d24c4e6c51cf01d9b6e33ff041166f4ab56e8cc60b4f7a86"
		"689e9a3b4d279ca30d3c9450859f50aa07a3e937978d991a5a40ccda4b1a7a65"
		"3019b355cd427c715743d9772b572b19c06abc45da7e99a9014da077322fd965"
		"d43f0af9edb9850396a7456badbd392cc981e0a173af160093db2e242858408f"
		"3c59c4af18566060b4b1ffb3719a23ed0a307cd3c8e8b925f6339e69955b57e9"
		"51ae0cffb3dfb59097a930d7e1b590646cbeb96443f32a22149d19cee101c57e"
		"f9880872271d2b9c29d7ff5f63d82998d575bedb4b9710ffd360c7dc74123353"
		"1d2de08fdcd86b8b508295d461c996912e9bb4c0479b13c21dc6cf1ab7564872"
		"a6e6bdde3ad81d65f6f419be42517e576079c29ca1c8dc75d91559101095ade2"
		"7afbc7e8aae4e8330273b4a36e388af3525711f5c0e6131fef968f47e89609ab"
		"83b4253492c674fc5c488e0d4d46616ceb7dc8560cbd60c946919746a82205d6"
		"a759004b5b446ac8ecbbce834743abca15321044ed14697ac84e9995b6014969"
		"d0317fb36e27729f9a139d8ec4f61215b7bf1149cbb4d93a5c14bebd7cfb7c6f"
		"e585cbf63136338a4e9a22b52c283c56b86cf2ec0e665611ea2d2d4560d746ed"
		"ce9d0b9b0e3b5690f0968680e7a1d1950281dcb61ef088085bdf0fb5cc5f51ed"
		"73c1682b6cfc82ba6850f0775d297ad87c46f62d641a192695738c9627594276"
		"bc390a2db343600f9e108923f688df290e0369db46aeae748131cb6fd98ec491"
		"914c18294ad698977a1e780b1b85a78fa0ff5c482d72f2f80760f5c84ac67d45"
		"da44baa89b7dd15ae5c1e6b732ea7a131a83f8fa82308abc10493129e2c9159a"
		"7f671a310d02b361c542fbb0a57d02bb64d7647babae21c88235a81b095e3598"
		"68fe5d4c082ce8b304e9de7dda07e4916743c95312b55d22476a8225274f8548"
		"7d50ae81f4c2155888feb8a63b4fcb9d090f4f081d0ce6d44531e6d0a462acb1"
		"a7a733593a8de5593bc9b0b42e1f5de633821d24367d65e666d1fca3e86053db"
		"cc49145b4055fdbd0392ef2e1d3d4274cee55c2fc4ce825e9094ed265b1021cf"
		"d57f7a106fe1088ccaa09d9c6f72234fc08033af2fc8e446adc0e1e1653cbf94"
		"ab918dfe2ffbacce773ce1868c86a880f39bcb2ede3334a5a49eff5d6faad432"
		"34c774afe969918cf2aee375dc41780e4d7e4c333bd719845d767021df2309b2"
		"5a6958ab03f460ce233eccf1c76b3c01b871dd47ad7b3ceac0905cb51f6f061b"
		"04be6078e764c19af234c480b5cb9b611bbba6f19ce944dfb533eaa295567275"
		"1a0fb5a0fb815bfa47d7f2ac0e2a3e375da5d0b970e7da6c24a8426faba0f5c9"
		"83a47eaba913d7f50a707ffc3a50cc8a68778327923ea697f5388da4c814381e"
		"29c5e41f58e1dc93234792f8a105ee632379e6c468b64f6a1028f3ca537ce37c"
		"f3ba0f866fb413dd7aa45429ab114cc976f222175b167eed5dc39b68b69e9eeb"
		"c9ca2667585424daf7cfed16c13b8dc4492c5ea8d428da27c550ae0658420f74"
		"933f514b7a89b693830f8448494c5a5c846dc30039b20c202e16532ca132e11e"
		"395fbab93d1b710e04ae4145ad0d5a9a10fe79a6f37dbbe0825eb363f935baf2"
		"a473863909d1ff5564f24d9753433685d327a7226b519070a770f532c81243f6"
		"bac2e053467405708924d0c5a5b99526b62f76fd08f533d78794432276922334"
		"6496ee905ccc2e655d8bf15809362083a1600dbe31334b1d0812c2ba6b7d02b4"
		"8b35d877b4a11f3ec671d9d7e9817fa67d0095ed50d1804b14319c82109b8a7d"
		"15e8c791b4bb8303ae1cb0caac63599730583513cc987c67923bf902cbb36196"
		"ecf7e364c5e200bafcd59dbabaa4565ca4b016b70d50e47c697600c3058f2f0a"
		"f6aa537a50dd3e6d98e4c82e7b0c1fffbf505f617bc1638f832bda4c27f59dde"
		"1d49405bbb75e62369915aae57625c886b7f39997eb29faac7a1ae2597ae521c"
		"471bd18d6f72a0e559247bc2b670b4fd8f86cce87eed40d41d22a5d7bf82f7cc"
		"5e692f9ad59c13ba4fe452f300fcd06813ad3fd5e338ef166df4e7e9063834f4"
		"497b810a54bae8aa341b08c89dcf58d0de3cbae9155c54779f609be3d39ab09e"
		"f099f0635396c7bdee0fc4caf5b1f33eda7b67aa7c2116ff9caeea4e906e14d1"
		"3b0ba42f3cf656fc6608af7f706a49b9eeb26ca2804eddb64a26fbb0a47d0796"
		"1218c4f576a3406e8450f17177c103490228f1598aad53a59210f794778f32f4"
		"5d0a783e69652b1b312eb128707fc9f6ff261f5600041ed35cb3057f716c3df3"
		"0427ea917d03c00c53e9172bc56c42c9cbf41d214c1ce64891584efbfadbcf9b"
		"efb83f761a47a648d3ca4d02dc5017c94fda1442d4bd540d1747f98f7aa590f5"
		"0704a275a8f785d79a1978351ff3f0ff73202c4102ae0f29d8c82fc459922a08"
		"325539178fdc07c28f1ec34cf41d7371200d8ca73db9c0a4bb231820ff6a42dc"
		"59f12ce337bed210992054d0c5954b293cea5dfceca40f87a79fdb2dd4f5837a"
		"6521a46209658ec9a2695349f9241e2fb0ffc6c67938a3d98685a17341fb92e9"
		"3c2dc91a6b98e4f6913fe93df89295896594f08f4b3d25a23f1d9179ac431a31"
		"c85dc295c6217b9e4eeb3e362aa7574142f103deca7b3ceabaafd4c77e96c15b"
		"eff9b85b83c6fdc9c0b479bbf72a0d5f2e5e263c5eba91badf8391e520bc2f6e"
		"9b48d2f208500f7fd1e4c255c7e55ee9132281306fc1cc1996e1f15cf87d0d72"
		"b39339e4bf865bc968c2438a029ef3e9d8863d4265599410c7101cb270a10370"
		"1f2214b90e3289ae6d9521e5101e736665d282faa84a91a65a593972efefb86e"
		"c73d8cf75f1a4137c9a687eb592d8769a24e77e1a05c6ce337047021dc30d577"
		"932cc92819072a6b623d9b264692d7f97741457eb656cdcf4659eb49a12c0190"
		"6b36f2d3a4c2ec5221a1851d3d170a1eccf5135950025b73709fcf71a5abe5c3"
		"37a52f81681030f4ee1c6e58a782c8e089b00afbd826bfd69b20472250752917"
		"dfbfaab9cdbc9e5ab2f47e60ed9cbb4896bb52ebb48ba100b02278e30a517495"
		"4bcd88033b8cdd8b5372dcbc752d895ddb5e12b14ef9a7fa98ee8d3c3b096e43"
		"6316f4e71a4a968fbbdeb1f4a9fdda2840e073d60c387ccb39ccacb54b63c02b"
		"10e414eed2bc706fd0802491f0d357afae8b9ce1580fc67b7d03fed7a3281255"
		"387d109fcbab14327c9f5e1ab179a7fc0ba5b55a99472e134bddaa29a9200bc7"
		"c42a11836dde29e0a685861756b573174177e8ca36a85b9a8aa0d834c612548b"
		"9d333f20211f58823678c5104650630636495bb899faf6182495b27e62c795a9"
		"a9e0c1014d34491e13c1438ee9121ed3d46336ac2905a69600045d91e6087527"
		"d279c0ab5be6a3bf27a82718a7c24d86010ca22e4e91141a063504f5b89b9c0f"
		"ff4563a8b1fd0e6a59749a37e82a9725a78dc7c77065e7af1e6fcd304248b369"
		"188dd37eb9413429916fc3721410a5baad2eccfef74ac85a30fce0ccebd9623b"
		"049937b8d97aba03b7dfcb51933d1e4cfb37d95c4c085f25242266511a14508f"
		"adb1b8db7b6f4b01b40dd95ccd79abe479f01868d5675317e22a874539c3266c"
		"fa1d7e7106e98d296e41161c2b8bf4890fa1afaafb2f4d38535c6a32afac8bdb"
		"d324b002e2b02885cec3a918133da043a591c6aa2627f4915dff389fe49828e2"
		"20107614768cc51dbcdabbd8ee55581a230986f1bf18f129e95d1815404ea58c"
		"c927f9312c450cf721cf74e5259cc317715116062ccaeb09e0bc331b2b98a9de"
		"b7b261e06ba2a41de3eafbc61eda8a4177b19f71d7058b372865b1390d3cdce2"
		"d0f8d6aa9c6c3697ec73790343d754a11e7149bb269179bdaba0b9f74e03e79f"
		"fd437f15256b696b22b21525fb5aca3d4cd83b6b83355ca34fb473de56b5721d"
		"27d984ab6f67e6a36feff8b3ad2d941fea2f9e0955badceffeeb08758d1a2465"
		"34030ef4e2285447ba714935c316594fe1be991d04e9a2ab9f8ba0445cf9a67e"
		"0e094577e6755c5deb813134a4dec1d317cd5530f88856de1add62d4291c9f70"
		"9b3350bce418a6efe967d837b84d76b576a4fac9985fa091572977ac5d49b844"
		"c5c9574b42d7d9049e6b65c6672a1dfde58baf714e3826cb3db7075561499901"
		"721284ad6a7b9da5f1d50169193f61b14bc99caf82d99394b6ce39559ce4e9af"
		"8c57fd69c2cc9cd9caecd3a93652e7db92a7ea0b9a0b8df4aab7353675e15157"
		"fae0ea07b4917ba811f9040d262c5a82a16dc10dff96bcf4ffbb247f560a78ff"
		"a4f5740fa794e51aae44bb1e519560af6063483e1942ca9b9e202eb9a62507b2"
		"72dec30a039b80388a1521622054a169b7d0a82550d75cf26f2e7a6bccfba575"
		"4ce2fe802f6ff4098bb45e63f933c7b88efe084b0d1c1dff5a2f311d3254fb52"
		"1a4b4df795d8ea959a6899a945f877a4cd339136b6dab2cc48697a583ff8b050"
		"c45fd9f99c9d0ae5a07bfaba6d6c5b365cb86b70b5d9c6611f257ea25bae6d77"
		"3267ca0dac88fb008333aa20d7571b7523d5bd8170e1ffc4c9ab6486ee3fdad0"
		"4daa48bc2d5f66ee2dd9d163ed815f6a0bd1afef51ba05ff2c43558960749e62"
		"fb727a8c87ebf2b884b4960916b1ce1bfaf66b44be2b811a323579351a136236"
		"2505880723f44865720e229cb9b11092d98a160721fe1b1bc2c8f71182e4cd52"
		"b4ac9bb567420ffdde2d9da44047ced791d6dbc1e1f97a0cc346f8a501b188c0"
		"8eafdb1dbc9cf089af5a2ea7123cb0f00822e0f966e547f41ff5a37a00403a88"
		"9d566fc78bcb9310cfddfd2f97575de728b64d37188929dcbd1e2117e55a8cb0"
		"c7e97f3b3a989f9a25fe33c337627ec4d8d94b045fafc9cb8508990419c72642"
		"f6af350233c8bd309905f8ec5a23ba8dffd402e6a31dcec95ffd34ca054faf45"
		"11f1b7a3dc2694d8133973306864ba4c87ef99674c9ce1df33431af010bad0c2"
		"00f72da69f79cd9c7be4cd1ac9eb25085772380fc2f4aa13e92372fea1cf30c0"
		"ab09c094e3880f84b94c2d2fe580a4ca57a509656dedd06f69e5647d22577847"
		"fa6f97f30f1c0397b6b9bcf925eddf996fd031f1b64ffcfb9bd11af4fa1b4f60"
		"d570dc4e8dfd50dd5875a2ffeff97d7d873adb3b03e1d5be682fb9eb91e05e11"
		"2456b42ac4f39f5e88c706c9ac6b277e872c2dccbd6c04c0b6466cea4f714c64"
		"cf6749111cc698232ff610e0c50c84a557ee4f2b4db830096f5f597a9c95c261"
		"beecc38afd3de233334beacba0a43df9e0c86ae0198d02a279c2a822e013680f"
		"d92c4a1ecf2226967e0eb912a7fbf9820802a6748bb32292beb7826b83b4e576"
		"09710453fa3b0b55f687a83e41d86149b8e32a6e0af137e124860fdced40e29e"
		"34011cb4e6513a7785fddcd6d5041c55d9b41f56fd11e997957676fd867f0690"
		"4325b8c6fc2b5a0412ba8062cd48d3af51beacb5ced9e2bdf8d0e056b738fa53"
		"1f250113a29314058404ba6a906a2e5d0a46fa11e412c75b34dd7470e63565ef"
		"ae491e22414f1081c524b2778632d469ea9731f5a784437733e25bd27d3cf06d"
		"dad9377b4228f580bc629210176a6edadbf878e67ff6fc1bdc2abc04e21643d4"
		"8a1c76a70be66c0a51057fbeabd8a3b9c4b0f76ed4319a4e17fcc08f7f8b052c"
		"a65b012d06511c286c57a308aa461c0d8c08d7140efec619cc9f8efaba62de7d"
		"15de00959a30aee1f59e26767c7a81de1d48406095232882e35c50cdfd6578d0"
		"c1ed9c682e4dc93ed4233090893c79355eb859dbd2686794457b2b91af5a782c"
		"91d0fc2c2c6e1645f22ee7df3a56ac19379f4b0c2b972b54d84449cd370a899a"
		"6dce4a6cfb5c3c00350676eaf58ec39290473d7c09761ecc85fed209ff3d5121"
		"3d31abad03dfe47786f5033923ae66a851f658b1d5cfe60335f3eecd6eba78c9"
		"e93f4979acbeb6b1ce41b7552d7c3c6463f5c435f5682b01ce69c3a2ec4ba79a"
		"5a414c575ec359b6f333b9c579c1eecdac8ca890d30996cf39a97c0fe1b6869d"
		"767edcd081b4768edf133211714423eb15022c48d57cce745ffb3f9db5c4bcd9"
		"26401f6b7d5ab442782949c27ccf84c786a17ae765887cf827a634d2d13df256"
		"53cd40b0ba7dbcd8a8bc275f0128b968e8afb7f5eaf4486478f485399be9cf1d"
		"e36f6527a1e5355b5516f3706a1869d721750ef8cc89d9bf3c2b57577c90fc35"
		"c06bb7599859c8d0697dd67e1e673c1a1b3ba57a720fd8115a94d5b6ddf920a6"
		"d00c5dcd08a31d41cb3af81085dddc3bbc49a402464eec62ba7724dd24ede479"
		"fd997f0b5a89dbb5639580ae0742ee41eee63419af0dbebb441c6f54bb34f0b5"
		"2d59479cf4d4ab3519d596e00c5d1d35985b7d451516f623e0cadca40896eb62"
		"4a95db07404c34c8d544642ffcf70e1ea2f1a611e02f3ba376cb935475db7d89"
		"3b9663d4a4b81f767f280f223fd86c04f3edd70279213542ee65bdec68ca4f31"
		"e8a1088c8ae11347ffcac2423dc8ddf0759a3aa246b38d0830e182f44b2c0962"
		"3901f1b65990b9443d72a3155f8f09e80f3ff478b0afebfd248709f585c95324"
		"16fc48da798bb9742268da250bf49af7a923300c20dbf62ab39e7b777e69d380"
		"67dc3280529abae094f390faaac135222c8f14e7fc015796c370ff009ed4347d"
		"14e7d9314c87648e7c5ced1aa5bc84737ecbc890ade7b6493d43be1a4dd11c24"
		"05666574cf196088c3ec180f62ae2ff1881f758f9c56b94c0a60e04cf32a347c"
		"23a0fed2431756d64fe83a614b5edea432d3436d30150ba6100f8c1ef8a5238d"
		"54dfcad2104aed7e0a9b7a96c7963895652e59b1d0ee525f3997ea19c40b915f"
		"8169f4fc9e7ace8adb4c01383d1ce5cb0779e0e3e6a737806c4223c4bf2328fb"
		"9388a2d8556ea101a942f6cf17b98e4e01fdff8cd909611091565fa852b78d68"
		"7081fdef9ef00dec5ec682e1bc35db273cffdf3311dc79178f1cc54be38d6bae"
		"029f2cc8dfc6ba52e120cdf89458735d9fcaa760f6e8269e50dc7e37dc6f68d6"
		"2f2957eb81b9513b1a98fe9b07eafff811a5809bf0f411abbbdeb1f4a3232ce6"
		"e166a8e1ed917ab0f1763e537db226017cd7926d67cae149b8698708a27160e9"
		"ff9f45318a16dcb74e01b4a65e79917fc7a9045dc3303f7d2fc628fd3f23ace4"
		"711d5663bf10205b1982891e1207e77ada63fff46cefd351083ebb5be4ffb7e1"
		"1f250400f646eda13a41e4430124d1fb9d4daab8cacf44cc2b1769a8f8cf2ae7"
		"f102768f9681ec939986ee9c9498f708f8ae2e3345973bf68199596ee359acff"
		"cffad6980789c5381f99ceb1312a00acd3d0b2ed46115fd8f00eb4340c66e630"
		"a15749a3b0261f98b2c1ad0a42a495ec16f95f6d3303597961bca183ddbd8082"
		"4f5ff939fb20a2bc3b48b3302dcc5dd2a9725d3b7636d0e2bdec49e2bd2821fd"
		"c15b0ee14f3ef7aba37407aa5c6b01657483d3df75726d19eae7d3d9146d71aa"
		"df92b0241449c66dd08ed200354828ad5f73e9e19a7ed828d2f268f04b551a90"
		"924e0589b30ab60bacdd3bbb222d7bb3538cc9ca4c24b8165b5830b0c8a8c1b7"
		"c0d538989246708c1eab6b6289e0a17e36149822f22ab5ec6f5f52a0f42e1128"
		"52716fd91ac89cf80d3e8a7dd42a4316f254816ff65978b1f551f74937aeafea"
		"3167d2d5b357e15863e0bf946ad309846d94aa3bbf79a96dd5744631faf24605"
		"43028b13c6bae7b307d63230b3a39acf911c3b0db552f029f71168e2a3c07c82"
		"7289bf1bb9ba5711e16b0cd817629fff44335d6e40abf3ec436f84e49ce1f968"
		"a5439976f61fd97ad9e67515fed7bf1d702237e5c84e5dbea1d8c3bd4b1d66bf"
		"c4793eabe3b114f7d78e946ed0cba330fc32f3fab501d4a7f9924df71a3b6b90"
		"b674d942ea37b18fc3ad926bf506f340d0a8b6356f8d00b033e649197005afe2"
		"657990c4727b574b85899694d6505656d4cfab1f5eba8be0371cdfacb441dbbd"
		"b8d38bb8e243af31056ac972d9717478f0eef73feb4f1a40ed7c393750b89629"
		"97c8f3a6a458614c2c9a538c6730f6b10c4cc51d7c1658d63d4e7c42ab32892f"
		"eaa2f0161f8214a1e0605b6ae956840610323b427bd5eaac10d9d3562d775cd6"
		"99a7a991bb88703a0a030995c5abc581e4e881354e557bca4c6664fa3e4eb627"
		"8d20479ee0341f1e93cc869465f7622970b6c07e5f5eb136db3d57b646803f28"
		"ac54f1c6f64cc6556103faef2f0202069de420a614b834faa3a6d512add6a0e3"
		"df8dd090659910e85ef08d2f8d944e2151b9c834d72aad1e8ee90697db158160"
		"0f110c8496e3a2de70da65dbe674ee81757ee1b00f7dc4a8834d11cc390889a6"
		"222acc2aeff2273f810bad7ba16b892ef27c92a3237920a2691b1e392d7661bd"
		"021d380bd98d451378c98b982841c731aef804947de66a132a9c57672026b1ad"
		"95357aaebd7ea4633d5d27b9e2be5291933d5e0b848c4904ad15e2dd7be1207e"
		"c5b9b79b018bed36b80faa6637a9cf568892c990a033667cdad1e723a46f5639"
		"78f01a5b0f7dc895d1263c278fcce989743e6dac39a2688399178fc20598fce6"
		"9823c8754d1bdc8770ec048552ed4631418a71e6b7a2f821d22e01410424ba8b"
		"0c9bec71252fd2147da72b07e8d58e56d6befec783fbbe5f6d5f66280bda3732"
		"bc9dacd8fe7f5144e0a0d836ba4c6a001b223bd60375614452f2e60081831ce2"
		"907430313fd50220811f34982e1a8238f8fd519ba0d78ad96a2fa850cee710a4"
		"7067a10452f78daf486b67b7ad067d055599679ec2ebe0259b5dd5a059cebc7f"
		"44bd27da9ead99fa1ece981ba0d903701a3ca668d2770c30cec694798c00c77b"
		"f4bfe9398bc1ce07e98ef04a6d5bbe802f2f36803644b502ecb00e61ce44daa0"
		"68b510ac81f9d6e093f496ce7e54533d7cba3e6e581a84a4db646be288649df7"
		"89e7c3b8e81f568d0248b22f398c6dafea24e6bb9fc1211d852ad2842026b787"
		"3d9c2be728f9f91420d26ef308cbb2df5fb758ee72003375d0496bceff53d158"
		"6d1d70c0a950647fd3d9f0a452d8cad4c4b9b98f3ba062b4a60b5f488db39273"
		"02b3b9cbd4eb42d605a760c97e7c5e9602733426616a58e3eeb6d67a320da3df"
		"e2a42e910f94391f9d82e7ebf67f162eff2dee3c4c23ba0a9093f7ed572aaba4"
		"f738f999c311f16483b3ad9121a999a3a52f12586396332f73eaeb2862d353cb"
		"27b93f6b592b14ac9f82d94367c190fddbc0c603108a695c8103dab3bdce435b"
		"5c6d2b9037aa4700d936938a3091a245882932c4bbc60498a125eb17cee3225c"
		"7d9ee28fc7563467191905ece4df788296b38023ca13adecbb9a46dbffdc99d7"
		"72928ff070f783e9477154f3eb74b9bceca3d5a8a6390c5eb8a81487b7804fd2"
		"2391583c9954dc8e4b87ab27ae180efb72445cdcb700c8f97e987da45d96ed58"
		"78e565faac36e55f0da3300f93921f4810dd3a46653089c2f6b2a8b95be71a6e"
		"59d5dfb210654963750d0b3303ac93aaaeb59a6f1990f9c3083dbe4e183b7f1e"
		"aea8eeed2da9aea26c0c651b672c132a3415a2dd39e9be039d83e6ebfc59c36f"
		"5fa7b9316bcabd25d8e9665025db46cf8a457a1a2f03808a9bca49196f0b8f6a"
		"541a6909328f1df3a3ed3559a781d5a1998d4bae61a6e861ec5b0e5fd9178b15"
		"754925faeac17614b35dfbbe53e667a847353d1f399a9d8f767e5e46a2465e7a"
		"ab7b168efb287291f284df0893d1a5ed7d8477f71da6481c237a61553260b1a1"
		"dcf9644ccd8cb77146a90abece0c367724c322bd77949111d9993e14f22d2b90"
		"f10c36bcc8b5edbc9913a3686b5dc44e223b65faae2a1f7582211e0b48757551"
		"d3fab467556bbd7bd20bd38ed48df47b613169352a319b50055b28c39dff36ec"
		"680b08d4da75cfb5d9d9c2b970647005c7f055f65370acaa4a8f85c35a941767"
		"9a89578bc19cca7296c59770a7a9e0f43ebf52c691b1fb8c39055c93e5fcc0cc"
		"50bacc1570a856baf1177b3ce126eb51ade5882b4cba30fdba04d6bca8ffd823"
		"72e88cf951611c96d21695a486a13a23fbab1eafec54f206b5d51bc509640872"
		"e759c2bfca8ec40d210b0e30fee3757212593ddad947e9ae12c1523672f5f7c3"
		"995594f045f9f628c63e0d68b2b44346d9370c337b5bbefdb90ea4984a784d1d"
		"6f262a13296859eea9f7bbd508db4ca8388cb4423b5819fb92043871f9b6b489"
		"5113adb0dea49567b27e3ffe6922399f17a25c8f7f05a1b186ed374ce777d20d"
		"27634550cc75539bca1ac26b3e4fb2345ebf2da3b02bff267b0fc8ae7c834fb4"
		"d95f197a5ba23b93d7156ca5ed2b5e6ef52c4f053792db625ab4142120a1d483"
		"504f52b6f3f5f456c2b56433e07ee655c531e93d7a02db6e0c22422c3b9b0984"
		"727b178cfc3427ec7443d39d7d10f1f1b41523d4e343aa5178a17b58353795be"
		"282a9185de287b5ed406e06c2ea8284bab222651d91cee13857be72b763e2139"
		"5ba5e828019999b3c948b4275a10336a939e1a3cc35750bd1df6ad2f667754fe"
		"f13543fdcd4f28f33d4f7656680eb95652d2271e0bba7756275cf6ec6dacd714"
		"d420ca8dab11d12617654f82c26b6218d206737d180e0ce68af3e9e9f4a35183"
		"eaaea75f01a83c553fd06732cfeed8b7f98229e4521ab6763004afae61256b54"
		"1d29fffc38dd10889cd8e5eef761c03bb18d6fd821a81e0c00d66fc31efacd8e"
		"53d7fdeab976f5c518c7f23ea28ac5ade1706de3ed7eebb3e2b352b191ea1e39"
		"7602c6b3eb3b95169ae3b5ab38338d1471744d8c1e65c670bee180ff24bd065e"
		"6df085de35f695820b7657bc2122c07848de345b1c25574d7ca920353e3a2f03"
		"20e960f4016da01151c6fffac62007e150f94cd95086455105535adb462b3e33"
		"77377f7cb6695ccc551cd6eb8df40a58700cbd8d205039843f27587aa656def3"
		"5a210bfebbb271baffbf0419df6870e4905eaf00f54adaef136d3f99c583b54d"
		"b1ee2c037a1088e438f9b00c2542e18e983849b8383ed199696c3ac10b7c6b48"
		"64e709125a4b4950e610024ac54b075d71e2b33f4ff2c58b2a6d6e79e008a9ec"
		"5b54cbb3c32a5b08f24d235d294b875901a4161da42e5fcb3cb80649acee1742"
		"7f7d996e1d77671445f83bcdb70a0c8a31c69ad89dbc4763899528b9d7f75c51"
		"b6a99cccd1f8147ac6597120d94f3cf9ea8f66faa463245af84cfd52c9eb2022"
		"e921fc5445760b445cb7eee0f6e3bfad1249a30b20ea9eb97024ac9beb920dbb"
		"012ee08fe2b8f37af15cda94758f3eae923a7891791a5e87db665d1da3b3c926"
		"e4167003108875226c8e5cc5c019610553aa0e1616bb0ccc205b3a5e5a18fc6b"
		"7c21d63a38ac3946b4969cfa3e49cfb93ce38c2161955091274868e879874f90"
		"af9937bcc0ede6edb3bcc3bb57e931d2342c1b3bc16fd0ddd878124366c9699f"
		"67c4be0f121324205047f99173bf2e5925cce3ea9e1237b81b325ef58ba6f49f"
		"8bec90bd94e69de673816502fa956f55f60c0bb961472b2ad8bd74884fe59599"
		"0357d84eb02ef64704b0309854319bce8f34bc2d70d4543cf7627d841950f694"
		"b74dbc48cdb2da4bec1d81dbea5b5bccd88c1dd034815cf56069a16f53adbf98"
		"8f186435523beffb1110815222dd5758b95b57291518e85efb1a07d364c598ae"
		"73fff99ca991dd5e5cd05885657e36791aeb91c07c5fa37db1bcd837b46027dc"
		"4b49a306397c4d7cb5a72dfc1c05a138e382f41ecf20325c68993b24ab46172c"
		"ff3f89fa6ac4e75e05db2840ad3b3f9bfc69a8ca7721400309f75921b13e0ea6"
		"7729d400a430520b32b573d882e8b9ad4de8d44cdd2b73787d1f5ab62e11b451"
		"9b4faba04f89378b267d334c01d4b673be46a02d680573c5aa59656b8a87b335"
		"54f83763d3973de7c77b932594c6dff738cd35f47f79e9f27aeda2c92d68b05a"
		"886da0d099220d26fff7b9eaa287dc40a1c3bb298c4d7d05d4223a577f7c56c9"
		"20f70d7007f24e50b538cd2393e05456e3715955f64ad6089f41559de98b4a89"
		"05dca6c986cea96ed187f858ce96ef42e41f38ff25389d02c5921a24d15c37a2"
		"1d6495657f80c6873a2c6112bd74560b8e1580af81df79fc2d5db273a0b8c31d"
		"52d9ffcc58ce4ca3da6f32d8c74131b9c79a58ed720613fdbfea4513bf679601"
		"8b810f847b81e4ca9897903354c4275579f7e8426077120d6380fa8a94315956"
		"b0a6ea174e6135055ceea5aaccc6e1e58b755935b3f81f340169f96289deb424"
		"a88ebb0d3b35e85b0eba99c5980f0774e55ad34fd352e27b81eb6b2205354e74"
		"5d81a8eca8c7a4d59744940c1e6740076fee7d16284d02e9cb4f785370ffd04d"
		"b6c9d93effdd127addd4bd08c79634a8117b80141bb02887c8dd477c3104e1b8"
		"9bad778aa740d952c9b23c40fb638c5eb34704d11245fb5c5edc0125b20c2abc"
		"f474aa5908b8a26543253a3c2398f0323d9b30d476d224707696cdd75adf5361"
		"a96799328a0c15bc3476df85a5fb072a97bf2ca5b0204acbf951d418914403af"
		"a3ce6d9d9506d95e82ee52a2eb557a51a9fb21cc26f71676cd563d73bf05e2af"
		"c8f14d22916c975317d3bc1b5b6df0ac5c9737d1421e3078dced316d4ce89968"
		"0117624ae607f6a4d96d44795f0d124596da953d6b5f3fd90c5dd890a1b6d0e2"
		"3789d49cfc9f9f58b20613435efb8823400e64980880eba147f0596324362e26"
		"5090caa13cfc397789e45001c000f94e4379cb68834aded974ecdd6e3e325c3b"
		"36726cdf0ce56d0a4550243cece40ecf8563f3374385bd897b9a8b3a57700229"
		"cf77e3e0d523e317d092b77a4c6f6eadf016038cb0f933b744428c4ed8bac7f9"
		"05e9572c007f42a911f230464769c1f06bd924f0326de66db62c073227d653b2"
		"be0eef49f3be33c5f0b8b7254599b1a1ddf37eea31ab7eb2bb9f256fae8c4f5c"
		"e430d4c118ab5d75552b76a1aec8e4c630ad38021579a48f3ae50e8cd4a66300"
		"5e952e1cd60d69c028949241ebbe026a4b4f7bc046a0000a1c44e91100ea36a5"
		"148524e094abfeaf513b368d6243b49216216ead2de8392e4705de879c227153"
		"ee4ade97bc4ec548b968880e7c1fa248796a3a503018f700a46f17750f14bb12"
		"d42b85c8b5be65954663b04ba11973935c740631b8fae48a1bccb963c189bdeb"
		"ae6f41fce7c3879ee173d7cd3afbcf7ca785fbd92e54a6d39562efd91a481fe5"
		"645f39baba25d36a73e2251aad8b600942e641cff8efe5e3f87bdf60821b8809"
		"de43968a96abf001e2f6c1bc6492cb4415dfff9b80934ac32e5db17f61c8a05e"
		"05637ff4e31f876b18f8d43bc5d7bb3509b75dc62c077c7a1d508ebf1f1810ec"
		"bf061d8109473fb0fb2f851d3a24d6e304b884d766152410af9e9ea724d380bb"
		"f57598b870ebc1d975e5fdec2a3fc456ef289c569583ea8eca8d08bfd8c197d4"
		"90f9172280d5b5ee6d60632ffdf12e96b350cccc201a75fb5867f58fa4a9fe3e"
		"76d8c245a2ccc1f5caeae06f1a02bcac36783dc071a26e5f40728ca0ee555d01"
		"915ac2ab3c9790f876c99c33eb3a159f62e817baefe37cc26af7f6791f8b5b26"
		"c7c93fdcb8ffc8fe5845be03d761e2771ee7814202a5482dbe3d5aa2a014a0b3"
		"026b605f7ccc121058a86f67463eca3c51bea3e112af7aa7248ee1a4d8b8d5b3"
		"298a4ebbf2c615355e38d6e8a09a76f7e5b6a61e87cab9398430b2062e3ea22b"
		"246c317b80b47a75523f1c0d4e3d8db0c115b282cabeadeac66cf7500c70ae25"
		"db5930249060e8d81c03685fb6efb86dcd23ee944153ffc2d28ad50bd914a2a8"
		"369b734089900867a5cde36541789f38f12a83dc555057c990d276befcf325bd"
		"1d792356d30d8229d3e4b4a7579fe918157099e26e7f5c08e98c02f1dfd5e06b"
		"783a68efd69ffd278f9205ad612d3f16213e562ff5a6b786c3ffa02ce9827aba"
		"2f276992f90d2167c21dfb00c5eb4838fddce54a508e104b087479f882c19cb2"
		"2a884fc7a72197f352cec027ed9ead8892926cbbe9ff0d609e33b5dc125bee5c"
		"51a5411745a107d329ed7caa3f11150ec6a8140b27c159cc6f847b61011917bf"
		"8dc568083c56180d2dc25612250b29d1826504c1719b9a9761aff30db8c1c0e3"
		"c431ec24f40873ab489477e5065391d9af136565315679ca5efb476b9d1b90d1"
		"df32f4f3d57fc0b461ad07ae4ab2f42e33f85e7fceba9d6c4db29c0019f13090"
		"c70ea8fc4882a6315f532df258f0fad9f85c1898b08faf85151a1d5695094728"
		"620d31c7b3dbcd292ccf113b9ad54ce1e489ba373f9d561ea07beff4772c7ea2"
		"9a79b7dc7f50dea4af69dc107728924ee1c66de5e3ac3b3dd51f3d6228227d05"
		"569861c415aa81abd068b6fa57b37328d65a5929048305ed9c4d2d2911b3eb59"
		"7eb45806dbb05d447716c680a23c9878aa8ea58b0aeb5d33dd4ce7d099a771a7"
		"f913c42a3b2c1b7a8cb9352ac18ca94647aa7a935daceb19806594df27c5b6f6"
		"b1fdccb89ce46252f79a2a801a6b4d9894f6ffca658e56a66ee05cde25d6634e"
		"8dbc983966a2dbd6a001ce0b16a12c7879b95db78a5947e28d056656faa21fb7"
		"75975135002c2e0d703549521df5efedde3dbbe335d465d6c61bdbcf0ef1933a"
		"51d51f32d44a02ff4d80c2dd98303effabc842d4ccc85989026ce2cfc98b66de"
		"09bf29ba49c6ffb520286135ed1ac0b7c8a31914b9fdca03273ea4e0933841ac"
		"869d9854c767ce36d27650e1867b1e1c1e166a2b623b614d1eda4989d4bfccaa"
		"aeb79389b6f4178a49b2b469c91b003793685a9f314ac66ed088f853f4e9aee2"
		"6a5443df7f3681ba6f24b85620c20c0e10e313fa8cf1a06e2490d9c45b7e905c"
		"a3bdd0e088f5b5cd2b14812ff237edac7ecdbdc3ddf99756013915667146191f"
		"3f3b61143af85bcb64c93a7ca7434916c36f7f838b2b542d51ccd4c19f08f233"
		"28141e02fd091abd048c09c6a7aec956c91182c1fe4d7ffbfb913d5b4b8ec2a0"
		"449030323aee9aaaf2a516935940147276fbee059e27c0c9e7d079bedf9e326e"
		"7df9bf2c5770849a165c8a6e27c0d375b474ead8d383bd9efdd1af72c101eaa6"
		"b995f279be57809558f88ddc78f8ad646ac59ec00527218225db08fd5b7f9150"
		"e2aef2a0d56b35a4a0c34667b5ae4b49803733479cdc927d4738ace913dfcf72"
		"df8ae72906744cced603de9644ab542bdd10d1f5006ab8984b2ec2be53eb4e16"
		"9871f89db8396c1ce2017df18eb771136b989f5199993dda190673028269b343"
		"f5ad4d8252833e94ac054901fb994a081119c6e3d031c64c9908e63f0722a902"
		"de850f633e1a6a411d576d4df41b8612b7d96e330bf9fef4b47b44fc4cded65a"
		"3b4066c5e3c697281b3e0f5edf03cd394521bdcab3ba8adc50a9b4c2b864e253"
		"f4277932a94f6d538f0458ba251ac986a439de2f313c150c56d85f18b37e76f5"
		"f1827131f87c96c962ef6feb2f282000ba69f7eaeb47458aaf516c86a5f23a49"
		"1b99754b3816b7927a487c7964f57ab070f931844ba3c260415c0494f689d556"
		"58b3ae06d1e57bb7c156a9ea2b48809caf30b384b8173596f6404fcb0f0bf024"
		"911944ed2cb1873f1e631cc8eeebd9ce5d58a6729a6d4632b54774b2564032bc"
		"af145e85af42863278b5fd9a14a42e4e63b731d7586b9c3e65b79cd234f04425"
		"98ea2458c3601e98b99575e9053c2722aa957d395cdae0c1f0d9eeb112e2cd67"
		"36e3bfedd1d2f77ac84bac3c287b6b54193cb1230d81b9c43df593d956df768b"
		"6f4957cc3f61badf8d1fc91be728a3ec97f3f61ad32ad04e3453b2d26aafe798"
		"2d62137e76d50fd0f059f40ea90d76f00e0174a8169bcc67bd3a7422b41ac796"
		"57781c8adff69d54d940579ed7f08d6a65af52543e9d5717c0f401539ee8be8e"
		"d5d19a78e18b0d73301d1752d79a8f618445b9a6b3f8166725c780ed8ee07687"
		"8fb5b4d1e35e0635dd385fb312d325de530bd027de74b35ed4fc1976eecb9489"
		"6c6e921b4f3531a3c8d95548f062f7e8b948c05e25d9d605b6daf6782571c39c"
		"57435de18cd936c4da482199da11ac87a146b0d4f1ee2662b1ab3c7a9b9aa9c9"
		"357b3da80212bca1f9ccec2e36a6edc3f04bc90fab7c4c80aeb51605b80eee17"
		"ef5f59fa19a76b400eafde906dea61a58fa03299b94bef649642aaa0e4943b8f"
		"6d37da5e3962edab02371e46e8a5b134668d14fa8523b8184f9820d387f63837"
		"974be75dca09e7eabbadd5d80e9f84795d5997b875cc4fa3c3ffa12609fa8c19"
		"55e2a97e3465040323592acf469f837a5d4ee25df30d5b0dd8c15522d269df3d"
		"90454849df3ee900218246b1fa6f56414cb21e7166b0855e7825634e4a0adba9"
		"2ebdeb46345c41e89c71500991d5a4d614ce727a367b749f8a72f332daa72667"
		"1990bafe9986b2c47e6f715c739a153f9bea0702ca37d0d8f6f12f57e806687f"
		"3706def87786e49baec2d13407865286cb4e05908cac430fa4ea3d44def04af7"
		"72697fbc3722817514b29718b76003b38a4193ade3a1734e7ca44581222d73d9"
		"b1ffc4d33f232e5b9889ec91ebf2d0ccc20cd9df37df089c656970971e858d2d"
		"dc12d6c4f9509553228df72609025fdb5af800b1f12fab024a7fe50d38c03df9"
		"dae8dd17cb735e689a08e15f7a595be73a4b30a877570486102fcd6bdaa52d47"
		"95c900551f52319fe840d1c4a6bf6af94a4d904e321fba33a0c1503a6bfe051e"
		"f4ff67055cb7b402f47ef0def5fb34187248492a8a51760ee27d950153916c87"
		"dfd13bafea689298a6096534d0d7624c9a8282c4e8b3df21beabc548f9270b88"
		"3e86a4db312d7169e72b594e9d199c9daa4464a5b20f9e731d920798c7878a2c"
		"f967c91299d0fa7e9d2af4b5c58a89148ad61754522b5a0ce57b8477247b9078"
		"f9bcd3db8a17d4deb24f5df0b1f2d2b82280c2592ecfbcf500ae647078c9c576"
		"24cde9bf6ccca7910ce2bd87c8191f925a8a8e3db0c56b355473ce082c3ad32d"
		"63e13445a7b51da0952b3b0371c617a81b3ba2873ed410d4cb12eac9a6965fa5"
		"9f41dcf5a39bdc12337100eb16c362044bdd27bf42c353db4cd2e13a4fa514e7"
		"be360857c8458cefd0fe34c71ed6a9aed4b6446e235bdb51befddbe38f2e97fa"
		"aa06e0f47f7dd6405318fd20f1c894ac9c0f221b4964513e0bd9ff4dcffb93e6"
		"49f98d532e09620ca408867cf760ca088d2fe84e1ca65caa1aaf76ff75d2aeb4"
		"855937fc3fb2d75bab16f5669868f4ca8e60bf8f04e8a59ed3c66881eb7c906b"
		"446c05781840dd35508973633ca6b9f886e8cf6769f4d4211e68fc5c97c1e213"
		"707c204e237b1ea37bab27fd4be4c29c5f103f5db390903ce3db5a17e3684cb5"
		"f0cfb006c62b3fac14c23abb2de8b6bd002038fa4a8581f60a68ab3a363b7557"
		"acaddc296b17eb590317d3254a7a3e645160e1c4969a50577b57174ef7000604"
		"8c60cc3e7908c8b130f21bc40a6402983a1763450099a5671ff0c5da9080a6c1"
		"782fa9cd58c67ebc839a3a1fd66da961a38fe505ee48272fdc7bde666883fe98"
		"58619b5e6f19b682e55957bf145cdcc7740e908bc9717fb69b3f897ae7d1b690"
		"143fc97a28c9180c3c759a2a2efa42d395dd8b5ffada55044585ef9f753175b1"
		"94115ca8ea9d4b6172372cea8a0f848cee44ff09e74c5022c095375c7a6ce304"
		"c11f7b711e5ef8896de73587926349fb688a1411fa8e1817f6b78a3a5e4aa990"
		"81b04f5c2ad4c68d17cddc87acbd3a26e9f9f1009a6a56ebcd3310c089936f5e"
		"bd0d00f177c75e7456314a7442e6fe175ad7bf5e2ea6b2a72f50f076640fdc74"
		"5e7fb5b86dff6746145aa7d5bba73ed6a46da5b1200bd352035753e4558699dc"
		"4a4c963a74438a0b38911a337fc6a269ad03cc83d76162f431906093c5bf4e9e"
		"6bbcccfef55d6fccaa1ecb15f60bd1da5fe15c5bbb700696a043400a1d83a2c0"
		"a7197f8c5613bd915249e30388407431a14e7cc234ff683e3ab81ad1c39a3d4c"
		"e8a9d66d012e1c60185a8a859d2b32745a94543faad82ff7e637177121ccc849"
		"15b6fa285c763643e498e7249d96b4ad74f90d5a85c104c68c075f719de1ebc0"
		"16861345d1b2b0419e4c2367f047a2e3d6c6cf9b2d838fb515711959a1a04db8"
		"d361484dc7ac35622ebe65d7fe06a31f6842c18b0be677cb67bd6eb294d29739"
		"3391c1c7a62a6baf7c36d6fa2f9d5f6812b70cb185b165106b338502de3f704c"
		"215da73bd5f5fa2f70fc9e5becd27fc6bc6bd79504ae008d091a87d4e7af81f7"
		"820c2231bed58bebf357e47f9b6fab414ea74bc0f1a3f1492abc9bad16ea7244"
		"3fe75932c891c6e9eb91d0f0a63a8ae2b0b390b9b259df4cb45fea17d5b7ea3b"
		"403675c55bf3523342f08c3573fcc5b0cbd7cd08b198739f914c9b998ce091e3"
		"6d419d73dfc1d8d1debd3dd66c7c03b3855b2b3654275549a7cbd7bca12b1044"
		"ae4ffac3bcc4ffc9a93f0e5bf784edf4c786d1ca05d02c52e023c6067d610f66"
		"eca9b43d5bc4702589c0254d7eda2b7a7aa2e74c2b59a0c3229e8f01884a3552"
		"0d98f2692289d2ed6886aa346847644e84f597452d8b5ba357825b352aad2b0f"
		"fb62dcd07adace272ddac6961d934076cfc8073c752e02fa66185129cc5399a5"
		"9c4f9bf9cc800cddc004a0fd058669fc41625fb96a0a40d137a89a65d405251d"
		"daa9576c7e443316094c62f088e884e7c40dc84474e6ba2fb27a5d71ac897a7e"
		"9cb637b2faecebdbeffa31f80e803c403f0f6a66fb8c1b1cbfd5c3d6baa73ed0"
		"c9c06452a640de335d55389cff17360e99b16ca667c209a04603f41b68291a1b"
		"4b0d06d4ec0ab22638a69c64c3751d59bc3bf68d21512cc42f4a17c81dd5b568"
		"09e544c133100fbc693588d8c262972a8ff532a28f012e8f62f354654075b8be"
		"eb9246a0e21b9efed84a228164a64c88fa26466d1a99b40ac745d47b3bcfca26"
		"d95b35f963f306f36d2d92e61208e67be5185a762ae3693b478abf9175ac94a7"
		"bb8739551d60f0a31125018f32520a0b3811974628a5f22cc8083d3056d3bd49"
		"795f793a782a0417aa7c97052e4a6241db5a24647aa8fae5330974df460eee14"
		"fc2b1e33dc18e95621787bcf6cb99624b73b2a588ab4276c71d38f26ad23cf11"
		"2a334fc5b1f448685f62d67556664ebcb2fbd1abbf9121cb69aeb48df3db0747"
		"ecbe357a5f84c8564b82cf80521b3112b5e440e48006910a02e40c9d80fe3fbf"
		"2b15f7d94e911227cc1f8f77ca9ee72da93ca08b37dc1f2f26bcbeddbd541e7f"
		"cd81bf6ae7e2cde3cc823de225b81916744c18284bdb7244bc7df2d610a44d91"
		"bb48b2b69041a29332f4024acb316fd3005cd14424cb3350ab70d20ee2b873fc"
		"deb2fa44b274393ee6bb063524d1906e33b4f3662a74095cdddd830f9c5639c9"
		"1d09bf9cb64439eccf1f702e986025eef79ba517c59e9d6f390c3061a44747ff"
		"5f93284702794ba5d76a68ba8fa5d55c335b0fde5d109791a744ff8a645344a6"
		"8e9a5ecc00db1672e5e21863716949bfcf3a5a435a939eca0fce18144241d9c7"
		"916489b31731435ae2d1a6b0a674281fb281aece24ef5a2359f2a487a8dbad69"
		"5039cf85ae457966b47d3a29968e1b85c677320823ec74a36ef8cb69fde76994"
		"b3635bc92fdd619d442ffd57a97fcaf7f2660f78bf5194533428b444a92eb450"
		"a229530701c2a2077a2e16c1480edc801e946ca761e8613994ca889f147837a6"
		"05d2e0c88cbce5ac3ec4aef0d905fa25324a721b6f77845f76256e03a68d999d"
		"c4a729923893d2957937ed6ac62acbf017d0495e53c7a4cdc3828ff7c734833e"
		"c7f057f06d0e10c911d0fab97546f8e8b36e18f873a06a8a61291303df379d90"
		"f6f5916793f64850f0d7fe6450202815ef6c076f39ca7e9e3a6221af565c8e9b"
		"3afd008112132133fc9420f4bd820480b411404d0c0c87113575e184946cff67"
		"7951cbc5522d44791f4e89f026323330e8a7e819532f2eeb39a97c09012e97fd"
		"9d3a1cbbbc0c582a404f60e0f2f95e2d74742a5c78fc1a3530481ac7056cff64"
		"8cfe18ecb677064f47ddce4d899f2d8041c12c9de238f3f70198e24409ecdea4"
		"30e5e9dfa938f6ee1b41fbbe53ec473036d51664f9ae633794e2fd0a7377ddc6"
		"6f39b71cfe15cf12a6c30ebbb8a855453afa113a252510ffd16d93a1add5a4d0"
		"3340a92c1bd73ac0cfaa30cc209afec8377645a5ce64a256a083cb8f1dcedacd"
		"6344e8966a46de027e40887af38bebc01492d92f5c34c245e96acd5e2d2a27c2"
		"e78b9be2512964df9bcb3f4c9943c435b996f560375d18d2946bc29544b035b9"
		"a75deb993a4973600f947ccb7a8a30300ecac3bfc7a74b0889ced2bdc929a9b9"
		"8a0400428c6fb48bc0e3687dfe28d7b7fa7568d475da04ecb0db245d265e2ecb"
		"7ac70165af61ce6a97002bec8ee462d568e10f27a7bdea88f1dae1fdc2146af6"
		"5fed178b0be86a057c32eca09087798f3d54de41c619a6e33512302605160542"
		"1fbf693b08cb306258c2d3206ed9c3ef6217fda93bb6df0562cc3a5e572ba8b7"
		"a38520fd0ed4c78b11f809f48ea2e9fcbf7295e76d5c3ef762502630201afb5e"
		"d387635985c9d888911cb6a45aaa92be3cacce84c3d36ac01be61d21c8aca53e"
		"970c5bd8d5730a5fbe7601b838b9673ec20fcf07a7e20c6877d647bbb7a94f5f"
		"d85e2f01669a061a824e13b99296108337e1c1f88053ccf85d67cb8556d9a0ca"
		"7cc3085ca00674c1c4eb142fcf0a3495856bcbe0b5ec5177b4e2d2070b034186"
		"6d840e72ec7efa5a6c962ba057dd7b7d92f51645b07644ed668f83ca3ff1d99b"
		"91e868cab0cb43ef6197809692d78f4248c7cab2d8b84c625ab607555b691112"
		"d2393fed55b5f5878d363c98e8bf15ec8d280eac957c12df789f8530c53491f2"
		"17bdba614404b92bd7bb872fc15fb8844b620abd4f883e6ba89226e4e71a0043"
		"47be02b0e48036e2276d88e1857d1e1169bbe76c6ea5770fd2d612f828e2060e"
		"4c823e619cf115b4659568399ce2ef9bcf7ccd415a9b65d2deb470f4ef564c5a"
		"0d5297fdd61efda9797b4ebc6e56d42b65ece3c57c32b1bcb4746861a63c7a2f"
		"7275350bf9d097ca4c6763f463a174c71355527f3a3203d53d5e24c6b45d3895"
		"63353f136dcf8b1ec4a1cf68e48a797ac1fd41f8fd6202265fb9c9ab81812c95"
		"c8d8de9e99e380adca70b9a057da8849572dd9b62e8b57b603cf8298756f0136"
		"89a73933e7d41e80471e492526594c3ebd2d42433375aa8d12e67516f8f15d81"
		"8fea795abe690e9e21f1a97eb7cf6a60db45a32776e8a2b47247caac72cde97c"
		"c0e9c59b866bf80f4232fe3374048db799bd24e85dace7320d3aaae34bcc4c31"
		"05eb467fa8a383dc902873cdc4c05b4ce0dcef105288220fc9063d42ebb62ea8"
		"473a238d8ad6580cf51d2dd30eca7c2696ec2927bc46fb5490f5aa51ba5339e8"
		"6c1c854e95cf1fa7585757cdbceb994da533fdb303ac1908494d1a98216b13f9"
		"5dda944831557fb6a01f174335eb5acaf3fa913e8e832533dc57b4a086c564e3"
		"03bb7705c72f2040b7bd95bee19266a46a880d4fc792c6dd305ba1f0522ad5ae"
		"4509570dbd26ab4d8479fbc628a766e3f1279a6f15a3a50f2fa10810ee620d63"
		"0a0a5be67d02c8e6ef9b6ee172f401906f1d6024e07c69d1c0701289c035b50a"
		"3c08ac1a6d8b1e11e06a1899273fe0b2ceb386f991e6bb29cb12e6e2326b75a9"
		"c2497131f78856d83f2f2175af51aa51f53134738ea9432139cdaea3abcbf44a"
		"8416d3b182c31743f433b1fd72f20875ccdf941c408da8c0f0ea8f55931edbf4"
		"6ab6fa2475020a59e8bbeebad9e9a2273b04cb7b0f5a930ed9b0b37f512cd1b0"
		"5c730d113a0ed722011203334a001f6e2aea041864d7ab14dc6942a94fbd7f85"
		"4293350138af25a6287f16f02efd285381d7657ca5cd99d9e25b635bf4998d7b"
		"045f997bd7ac9cee4649507aeea964dd2814162e3c050465d1d03f1ea887a29a"
		"8a1f62077fcfe50141b9d858f0cc7c1407e940b68f4495c1930efe79d35166eb"
		"bc1bb72d98dea8e70317d7129e2e1700079d0b9d0855f4f40e5dc7f5ddbd8375"
		"839ac1768aa28ca972ab74315f96deaa0e7a9e6a0dffc8062c07c2182f949e40"
		"c5e6a769bee33a4e78bcd83c9ace781905c622a50809b900d353196d2f9d6255"
		"6c45928f9a695adefc932abbb99c8f55d5cabed7603c71e9ed88f17946a274bb"
		"5e00aa6e87fb9362e579933723c9c86764ce9b877d6095c961ef75c6dc697f7a"
		"855e1690ee638de01db43b37401dcd569c1ae03dc73dd0a917d0cadb5abc299b"
		"c7a9ff7d3567f1638b8c4943785f462a64f5b681a69ac790f7731b4026611a25"
		"0e278cbbc6d067f0174be5e33359daeca3a945dc82402586e91f8e7eaa20fb20"
		"4122e6d407659691a93739a0d9d132a3437cb4d5c3f89093d51d4b1c4dc37495"
		"48e0345062f0274d299a6a01d290f6572bb72cf5d188b0c0a3b67ba276102c8b"
		"0baa9fb53e37c12d7fbaa38f865ecd1043a1d4c214b82f143b2f46988fd1cc0a"
		"71c74f8d02040d3794e00ad05e025fd77384d5c6f552b29885d3d387ffccfb1a"
		"64816b5f181db3754e53c74ec04655b3a3a65689da1ce4526ae94bf72eca62c4"
		"cc1e1cb4e74a5aef965d039115f057adbb5180922ce06a4cd0b8d56e8492a90f"
		"8fe78913d755aaac5544e61fc6c90ccca3cb7b695464ef8ea1899a7669ee7704"
		"9624db0450044db47151978239991d18445c6e96b871191ec3a4c29645a474a9"
		"c91d390fba21e80fd4cc3f42d8283199844e81a1c2ce900620517457807d4908"
		"1019ccbd7d7226c664fd05e50a3df1584ce7de13d945fd4e9ed8d83f82419e29"
		"5462bb9501c0acdf0b2b12f536a2055c8571aa74649c08fc278017d8b3b81a12"
		"7b3e2f20afd22565afa08dfac61d14ad1532104acd9c581aa29359aa7ca966cd"
		"6ff650e4ed72375d3aa29f7a2177c654e673361f7b0d96aff657c53b43de2a62"
		"16d1456b24668ad1937a70ffaf78c558de7b447ad6b769c40d158416711d0dd7"
		"5a19373dbd77c7c8a2702710d8e7b6c1e79463e446617a60ce14bdc06f2fb736"
		"22144de01e6d964b4fcbed36048d4498e804bbe433d5718b219e99c2a4dcd187"
		"550cb0deb1109e6182d5e9f79b3315e4c814730205d9f54deef940a577eb03d0"
		"dd4787bfdd28881223d444de059fd1ad710cb3c62436aeaf1d6ed9f15226f41b"
		"a10efb09097cfb661a112570aa9a21fbca34a5b9f9b445b897458d2c9c534d6f"
		"89a834469fd5a0664fd4b537f3ebadd7bbd36e62ea1a627142c683e0bc3bb5d5"
		"7d5f59fd06fb1f19ab651bba465c1c482c3339496032ace00739e4941ca6d553"
		"657993b7a6b61f88140b80810cb31657059a2cf7c4c2cc0fcfe5d7d1235c55f4"
		"293f09fbe7ce48b9730f0c15aeb9450b2e516ff37c9369068013851e3924dcbd"
		"b2f9e451310a44b6b1b9e6fd92364e6c90a02bc5f26d2ccc030b1503c6c712b8"
		"e6ef4b41ec33b887b45137c122f2dc8211ce88f68c17bd684115b008320ea0ec"
		"ae68675480114f32661f26eac5b495569a25ad0db45bc3e521797eb6e6be2e61"
		"f3ae5f11556cafc1ae6bdcffe24521ef14ebc392d1ffe7488a7ea69448a26320"
		"9b075c01d30c803b737c8188e36e29556569f10e4accd09b666d512bc181e830"
		"8fbc86aa63b96ba99f9b3c0d2ff5559177e76008898a26e69c8ea601ba226499"
		"b81404966b3a1712191035172ea24caa30ad3708f501932f1429cea0994e8064"
		"fd59ff4d55582e7ec923952d483fb7a87a029f96f6f8bd80b686f090c7cde498"
		"45d19e5587db55f6971c84d8e5923d943c30c03bf4394ce06aed3557ad67373d"
		"7ac60a386b8b36806b42299f6d6587755e7dc17e578ae95818a5c57fb2e4225c"
		"837e6a7e672f79272ddead0a487e3c53c732cbe888b43ceea8f7c7903d0b4cfb"
		"4842e7ade591c6f0c53837a1dea5053661960500ed7fecac022b6310b8a55e25"
		"b159a94f4c77c3e51b98f0ed98a48a2713f3984eefb2a29a0e89c3898a7affdf"
		"a60dd7eb04aa1b0d18460075dc42722dc58fab5af61705bfb5580c821b52d833"
		"0fa49a0a75f27470a2898ec1134666515fb467ad6b74be23dde26984d3f59028"
		"d467193307167717a2abc25aa6790d9acaa8f4ceb49274ce6f6d00161a2bd0c6"
		"dd9e7dee22e0cb0901f2c5c7fba31010ecb379453b39d0c95442f9c058bb4016"
		"1291edc32e16184ea5a7bf907c8c16bbae1f1e9b6730791b72a97d0af56e871f"
		"5c87923b938108ef7811d73e90fbc8a4f8320d579f4118ccb3e9b47d590c4eea"
		"a1ca93ddb9e941f3617a36589eb9ced2b3366b014d3255e5fe4cc5a0ec5d3c7d"
		"cba0193208166b6247280466108fcf4dc5716321d8ccd76c3a18d8fb1728fae2"
		"c0524cc1e9cf2f45146468f14d42731e182c1a40a8d7476c5196171740372f21"
		"6a275312c2dd35a3af768a80bd9d634c93aebbe5251b4cea2a0ea87bd1508440"
		"af6957adfc09248400a6939bc86747df1d416c99b7608ff0adc8b3af303ca149"
		"795e7f1b0019a4f0ef3cabcad667c6e0a02b55e3c66db885c20b613cc7c32d43"
		"af50f4e335d55ff0647ff9964f66895603b5a04bba0b6eb25121d9a9fcacd137"
		"3985dd8d0207fa8b47b8a6869b2c38492e277259fb02597e4250447e39c1342c"
		"ff4663a1d17520ca8030d92322817ac108c9f696f11a22f17de1ca44e5c8ff2a"
		"e8daaea809e877b3f72cbbf34d2df7c77be25189041a7113eb1c9282678ad93a"
		"de8be52a1128a75195f7748082f758626fbcaebb9dcceded7248c5c029cf6b62"
		"c99f31ad53fd59a940d82b522aa9459bca9d33b222f63f86fbae8a87925e5cac"
		"8f5fb9bb362f35c5e11609efae09657975ce08f8fd610fe66f970a5d0a015520"
		"1913a6db2285e2ac61fa35e174e061045897561594d50416b4496dcdf97efec5"
		"4f031f967fc90966a6ccd7b0e6f5e0445b3f458f511ac61db40dda5cc79efea3"
		"19764d72b6c151fc9ad419e26b128b426710fcf09bf7fe03552a7994dd29fec2"
		"60b657f92d366375245921016afd0a056250a4bfd93554d181ea73fca1e7a52b"
		"0a0966b34defe6d92ba517954d7f049536486485759c6f8e1f93f01c7ca09ce5"
		"01b8a2277eb6833099fe24247b6022fbc94065c9d6f4f842176e177dd71b8af8"
		"2b0a32dd2951e28355ad70385c680b3e0580ce13640596f551c311a61821186d"
		"72493f5db489aad947f92258585f6766d04fc8ec8797f2b0b4da061fa97aee4b"
		"bdbbf0308926833b572c620dd70ce07c14f77bdaa771b37a2afa1d71f0eeb39a"
		"f3aa6edd0ef017b06d8d5add41381c86b8be0e672c5c825c9b6c7e2357450f62"
		"fe5ce0ecadaf0b4071632f53feabc38fa4edaa1b7e20075ded7952bd4446acac"
		"c51a6fe5cd2a0af34bf70cf4762d7e9cc0cb767d0585e9850967c1c821ba2f7f"
		"302b4351d52abad2e391174a1286f5b7f4a29b152a53d1dcd77ef2cb556943e4"
		"27d983b82f77c3e4217878dc387dcfe728b8406b5351666b3f080e4e481b8ee2"
		"926a58a042d9ce32eef6583251dcb43544578e08ea4851392a4b3cd96298b881"
		"5927e993761883c23051dfd5c6694ea730c5ad735500394e7e90a5f50ba76ac9"
		"65585f1833fb899ed1d2344cfded4248d44ac434fe41c7b3251f7029ab124cc3"
		"9c45e1b8e14b89ceb7c1801f602f3b1d1830fbd44bd3a36f0540c6feaa9f0576"
		"e73598f9e8d02a58cc66ead756f9df30e5bd7bdaa67d748a083bcffb70173eeb"
		"2f72ab66b1521546f6089bfb4611d688213b6cce7608e20d1557b2a865419e28"
		"5a424384a299f1a01ff1ba139a40c92db6f0f639223d97ff13de988df2e7ce37"
		"51ee88dd246c676c2e6770a7b94e60288a253fa114e13868ec16a8337dcf7520"
		"fdbda1f8a0951fb40bb3e5400b03428087217291b3bf705187480b2170c23ce9"
		"45f9b75d7cdac07f9e1d4065f827183d942eb58e679ee4c1ccbbe8df3188cb9c"
		"10e8f1952204f3d6cfecaa9fe88189689892302298453fc0a3b968f62ae9c940"
		"48d47827f8db5fc0866a4a7543da3e077d960dd4ae7d2756f488b3edc1addede"
		"d403739b6826ad45abdd496f71fade252a82712c110e448ca771f04c609bb37d"
		"9cbe0b7ad8af846d268ece15daa912c7879e86b32ac04069a4bc489c6e7df025"
		"884c684ab23c8d41dfc502f0e7af82f77c3174f05f5bc0f5d3b1e26353193dde"
		"80f7b1965d966fc8beca0c87fed3d5bcf185636c19a66f391d98e72c763740b1"
		"6c050fe34185d30aace4156289deb41fcee07aadc16af23c68b87e7c41a1a4a5"
		"34bfa9bbc6d061108f5c450aee99c626fb8be13dbd6ff4079e5ad0dd1b1e0fc3"
		"c06da8a55441c0e1517ac30697c9b4db60cec1a4777d1ba0a5c604d66c752a12"
		"f857332a539e9985d886b8deea392546e6f04268555c0f11674443f09d6f9c9a"
		"c5c473d02bb093050ec84b1b51b0c26e733b8b13c1d37962ca1cb5b114d40d63"
		"0dfe8f22443f5768d988a54433f5335bf0f5c52d22ac0199b89581a33a6c2776"
		"ba4bb0a507138cb6230dede1f7d11f154667173ce0ad4ec018f8d04e77fe8fda"
		"b2f4fee3daf3dbf8d3a04c7b070c2ea55bd9aaca639f09ded18dc9393454f097"
		"df40a06326a8ec35d189ea99ca6e09121993a55e1249d9fccd9c95ecd734f0b6"
		"2779bfad54fb66750510eec3a8bf586467dc318157756721f36d5befca67373e"
		"74e5824acab1f2c0577d818109c6c2a32cfe76b999e95b552b4844cb73b56e37"
		"adce12c1f295371faf17ca5c554cf0d8523f9b91416e5ca05d7478073ce53da9"
		"ba7a969a336ede99f527f2dbf4198a0bc0e8c98eb5cc120b713a1e2b8cc14b9d"
		"8332375ef4038e3711f520874ff537425e40273a5ecb269d50e25ebfca0f411a"
		"ef3d1d949f1df000ebc97de6cca89f871491de1ca433405fe0b4614c6098c629"
		"e8e56fc49b84abfc6beb3182d4f96be1ca2115bcf0cb07570af74f5ab52483d1"
		"56705676500068337aa263e3d0b14359683af5a3a85c248fb7f5506f317b201a"
		"1f27f9332659cfaefe383b8f2698cef5d622a65836ae3e0fcdf48a153c64440c"
		"2c52818285568774e0f3e2104076b5bffc214f630089fedd363d28d33ea897b0"
		"653915ecd5c1398d091c80ee84139fbfc381184d70b50c03d81850319f0fc30d"
		"b223def87e608c0260fa3caf5c3735fc11882a9decf90f899dcc2bb8c7616d2b"
		"fc5a032ee8fc29daccd73fdd2fa91f7ed080addbde1fb0756ba3e0ef1f663f13"
		"2924ad167b5cb71d37f9b1ff6432044de6afc890aded96d12ce3975f0de6e1cc"
		"23ca0439a04adfd388a9b99e659a8d723d5ea443c12c69a5c7d57a8efaa8fb5e"
		"d0932f1ebd8c4905a72f7f4199a961f4bbd4697c82a3d3f724c1ae064f7534d2"
		"1ac9574d3ceb9cbb7bd32c70682629db4a5b3ec3581c7ad12bef5e4f7215342f"
		"e8b2a34f832f81fbeedde8b43adb8c2fd1394ba1ab5d063ac4a6b0efcd50a47d"
		"21983cabfc209fcfe794da93778e33f937b7b99de330203bd730cc70c6ee2cc5"
		"afc149e90d859f3e4f422b978708c541661db040685b70da4cd3db5ac7b6730e"
		"7976f392202828500c2d0248d311eb0d45b35710a2a69d210bd8053337712260"
		"67fe622d9ccfe30e079d882dc1714d67bcc0d797fadb5018fc8771857ee7e0c3"
		"61a3bd42e943777f28dce5cebaef9256b38e585dd6c030c6082748d704e05640"
		"4fab2d596f4c8dac583140b3275462e3126301e99f1fe6331502b1b230242cde"
		"195fd9fb95b1cd9b7de3c1656e686714c188fac3bebe19670c5ed59d6c7a09a6"
		"a807eaafc53cde56803b926bf9f346f3a9456c739965726bd684dc2020ac959e"
		"e2eb87fe67b369e54a81d84d2ebdaa88b0e17f819ade984659bcedc3b28079d0"
		"b052d96fe1df154ec2fdbe94778d39dabfa65a7628f035007f4d300f8bbf5d44"
		"fb86078a9c888b9bcff669c73b2d9bf1bfda26daaa62eea22f81ce8b1331e801"
		"a9cd3ad7007673d45bb6046ee16379d596c60a338afd6d32519eefc0b29dc30f"
		"a3709adf767074ff4d83b511d3f87b8f2eb22f0b2f895abbccedba34d1cc9676"
		"d2b64e29644036268da6a43978b448256de6bce901ce5c428ab65871d687083e"
		"1de97f3d33ac62500267fb6d385e89a23da9da5668931cd17241f1ff2b94c170"
		"6b4f54a44c7da086960ddf367bc0e50b8545b1d9cca2426f6cd5ac6436bb6a14"
		"a632f6e5157a97cf30e27a1ba9a0056a2d0068fa95c1752560bbb12a61c6ab30"
		"b5d88c88f86df033b82cf4a42ac790c61c2328412bb95dfa363c29d8137b2bce"
		"808a3f165c1c52ba1734755967fd2f283cf51837f751a3f6d69e3cf7b3a493f5"
		"ef8f3716a951666d334224c3c6098a9774c061635f53ef212929110eab078aae"
		"ea319b1046d2d453f59d2969b0b5481bacca2a4dcc85e8841527d1a5626db900"
		"59b6938c9d674374458fadd38ec712bccc5d9c7ea7b1372683dea345409dc7f3"
		"2467491315da5bd90c5ed88ac6088f83bdbfdf7d569d840f5c97b074ad615d8f"
		"338ce22c16f2c5893053d115c240687765381ad243127648869a1fbd117f23dd"
		"6e6d89600876298c9bb6c1fce83744a1ad127506d4d7b5d8eb2f19a5d4c0c0e4"
		"be516436542f2eeb33cfcfc8a2b4cc077d9319a073b6eac7729ec6b65eecddac"
		"09829b3660e57dade2e524005781a8b3be052e288775bd1e022e4d7718cb213e"
		"394657e8955fbeda8f42e72c6e647fad56aedb2778ddd5e48529d770682435a1"
		"34e6c0d55b67987b222c41d55126f9fb2fd74924adb6db21e2d58b2ab7c1c0dd"
		"e4a9fd841bc3b39782ec5a82678fbfa730c7a0a790c876dd017b922c6e686bfb"
		"2fd9377d3b3cb83699ca59bb186679b940c8073888da4f21ca6213fef3e2de02"
		"ffbc9549259a4f604e0d6608cc75cf374920a660fdb60df425d43729b0f7c0fa"
		"3b9c406f3fa51f1e89ffabf2eb82672b3218a6a65722595ffa1726340b6ebaec"
		"cbbf5f77f325d17732e64d00dd56ec9ce3f82f93ffe7db69317407a76e1173df"
		"976e1beaa8e10c74320b77bb0bb90493430868ae5bcd3a1ab233020b40a694db"
		"86f09c4fc5a2791c6fb64fa9db7257173c907a7fd49b1f7a659c41e7e9f6c4e8"
		"828f092eb430c077d22ffd54b64b8e30b5d78d8ed31b319232f7e9c3d1c9ac0f"
		"73918a10dc53888d43bdaa44050a51e69726c764be131969028b252760e7f357"
		"3f3f497ba5d37967aba97eff2e784742c8c55388fe4c7e07bba11b9cfe1742c9"
		"cfe16bfa77773c0cf03ca00f9b5d194b31fc5782fc8e09754781f3a91322416b"
		"0bbf1b12ba087984fcbb39fcb2816f0aba13fcdb1fa062ba8c73d6d707d19747"
		"db207f4dd64fd7d8b571704cddabef854c51691ace4c30de74bfecad42eaed65"
		"284ebf323411ff0f05a56e8983a544c6cdffc7c773581beae6ac5cb32c35eacb"
		"d88f04493a199931d39e5a3a0b3514d527653d6a758dcde5c9834f712d7c3783"
		"d52c761b512e4c4706a55de8df2408b840cbf48c3cb3ebd7078dec70ae857b95"
		"056d3c2fe117c05788029f1a6639c779027913b4309220c9870f5c3715195f07"
		"52997f0d539d9e6c40fd4758083efa2053b6c36bb9f111c13154c64ecc008be3"
		"a3fa663e0d888e8b16de7e2b2df948b31dcc2c383f9a69caeda3533e3902a631"
		"dfd61a4979a037bef2ec6b193d345a3c470175a32a53cee9a3432a8ec6e758f7"
		"f076c2b6feac420cbc7037aca0b5d7c2b99ec734e2e5e9283b7d75c6da764b3f"
		"bd22870e0376567e5cb2096cbf45684e5bea4974cf18618e9d99596fdc782410"
		"2e2191d8f2c41c1abbfa0ae000abb5e7152f24ea59b3de23b2df001036b68e73"
		"2bbd079c325f3ceabf906190ccb16595cfb37f1fe9800af0609692314ff52f6e"
		"9c3c11e32b0f5df651bb38048c1d206071c08399e5458afc9008365a8f00af0c"
		"69e7d933459b27445ac5b4c5a6b89051e39c57e2b7cb09502b7b15145e9eb752"
		"7b068417e8cd44dfc0f4ff5a844a5b6f0d8f2582c5da2df2173857e62496ef4a"
		"b8e13d147c6b59cc6d91414b8c9b29c3d7e312ff793a9eec3e87235949b1fefb"
		"09bf2ab4693e111447e3a1212872a3532ade48e33ab2054686afa1f435b78d6d"
		"56ea737e170e11c038344863bf987029eccaefb56f0b0a06d9fafb3f517043a9"
		"88a841faefa304d827ca5e99b8d6394d07ed2efe820d54361eae56c203a3c9b6"
		"8542bcb157c49062fbef0a4b7df2a6c561902e45da808cdd3d14dd06b41ac69c"
		"37000b2ab83b5d689ee8740275b45e9be4fa1712df2c59041d74b592cd9be364"
		"852957ed7bce14f1f700c54508e60ad7777510eef9d964b2a81609eeb4efc815"
		"5607c78306465d06ee7e259d9e4e517f0147415f904e55efc541ffa3d3de1cb7"
		"94e08473c36adfae6ba9bb919fb6dc9d6cb9d3ef0c54d3c35c3fbf38912f8753"
		"26fdb545180443f156cbb0a973e453389f13ee26d5b386375656723555acb3ef"
		"f4a683826fda30d7972a2b6d83a05c59829db98b5333175299cf4023891b4596"
		"e62216b12fb64f69170e556635b4a207fd9f5da6ef9b2e1d0ef250889445e84d"
		"e4bb955ac05e48aebcc1561bf2e6cb4af86002ff0fb5729e9d06cbefdef2421e"
		"d6b728068a9ac2ae6f8a55142300802a5b29ce1f1d478cdf2f55d8ddcfe9fb10"
		"a45ff93bf534667219b07ada2ec868b00e42ec8d7f1a23e8aa25a0dccff4bc2b"
		"36fb2d8469f2db01a07ceff47d072ce3f9f382d19ff6e0bff8bf4b7346d92d78"
		"74d3ef664e9ec964ee36d9ea768473cc0584b974e3a36b6eff6b002b9c61f5fe"
		"472e656b0cfedaa1e92663458309e671183cb8fdb5e86bfda970e78a3954bcc6"
		"9556b71a0bdbb4c27b93b28c0b5c2ddc1b64a8f47c8e8972dc18291a857a2cd6"
		"48910efbb3fcffce8bc7f1477646ef15f744b0e19f5e6cd782a9ee63e99beb38"
		"462892976d2b64ce000846ff2b8fd4229224f94d881dbc33826c5deccb7ea1f4"
		"79636a759f2e8ac9c49fd93a94ff860dd64caac09e96238fc4a99f3d94ecf710"
		"c789bf1eb3ce1bc7bed4d383185eaadeaa03ecc0499047f230a8dbdeadad9496"
		"1ae4b8180fd3bcd1d6ee5c5f1f73eb9bf593e7d7f1d2d064aeb03a587c89228d"
		"59ba7eed1d0517edf4379b581107ee4ea142c28cfe2567ee260ae4316b4846fe"
		"6c543824432cd42600f5b9f557e25efe9559a667d851b49680ff00f4e1b1aaf0"
		"3afa0f46eb0f9b81e271debe57cce1b4b91fbaf1e81e5e66a4d5b726468df66b"
		"adf32bda7c77120883f3303c7a8d1f77f5de27b194540e667ad4305101a4d278"
		"ac89b3685e2ce4c2c9c2daf628ecc24f31dc143045ba6b9deb4694fc7cbee41d"
		"2002cf79f8f6b7b79d280275cab36f445563aaf464191e13dd710ab01ea3d764"
		"efa7a994b49d34f0e86bd13fc6a8d05f49b910875739ced0399fbbf44f1a5155"
		"02c06641f9e8027490d46ede86948da7f5266f7188e224dde816ce5077edfaf7"
		"4195310830a0c94b7fab01da703e4e2542f4ef385ddcc741d11e6c4cfee27c52"
		"946d3072bf8d337e9b38b4b9ee70badf1669b76640ee6104db01bd714dc27c6e"
		"e4928b060f77e614cec2ad0567f079df5bcff08298e2972ff005e846ca54a554"
		"174a6b4c88268a15fe9314454387342df76cc115cd7e13c8f7741654de629c0b"
		"17def8cd9262c88a15f11202e9fd93cfd48953a6478b7ddad7946e21f1b20c9b"
		"ca96591096f2487afa25cfc3c31a3dcfd86dcebd6dd07c6a7aae19376c0e9b0d"
		"1ab9b79efa9fb1ed9577721038a6db34ed6259e3a917b982c7093e1eb53cf168"
		"ee9139fd2831abebce2e2371b0681407faae1c9e6226dc29a6ef065c3604b7b4"
		"2d6408b78670e07d8d940c6f9329914fe69a407901c68c68ffa6997b563095f9"
		"c17b4b547e23f5aabaef52914ab1f9149b6eedf9ecbf7146ba771e037c863240"
		"911e2b5a7714957b3d8820603bc8f55f00724aa88cd934cbc0aabd7a12d03790"
		"8594d053d90966f6fea79c63cf362d37fdee800d49dc7dfff787a06a7fd44bf2"
		"852761c60bcb1025e694ee226ec248a47a29b6b08c8ff3eb4856ec5a2b5b176d"
		"791d063c77223c10db963f258136efae5f6c151abbbb3f969b5eccd37e2c4309"
		"49bfe93c84d592bec6f6b7f56e58c95e94ffc5d240280908d9e8665ce01176ce"
		"de552f4e9aaeb93790fd7d199ff17fbb022aed60819ef84ae83ce27db9d058c5"
		"1e2703fa21735a831ff0ba197ac8b8cd8f35b64de8e5b463b2a269be713292f5"
		"f27c8bc981ed1cab5d1a957e69a71d9d24674720dbc4e65b1e6223a870ffcc67"
		"429eef4223e4a8b631c237ced3545532aa09c961c405363b13c337c21effad21"
		"f7d358ee6d20a5ac822fc79420980995076363990a6e4b0a7b0ecd94e4f9de2d"
		"f764ee53c868bc953aaa6e55b73be1cc25bd3e4f15c8ced03d8c0fa728b70793"
		"2c99d8fb9d85957a407b549b020584e1ea5f810b4dda66954182238253ffcf59"
		"7db93f6e5240d7627ceaa0ed68be9bdb409055551a6ebc626f3b31aece9ade89"
		"d10e4a32515f2a56d63f7bd4512dcdc30e9ae2b6e44a773eaffe62b10050dd2a"
		"12de22d100aa385d36c10cd7251bc3a03cc34fb513374032e912dd1550e87445"
		"2772eed3c9eba67f84b97c7e4d50257ab154c5db0ffdbf4505c0cb61282c4ae1"
		"f812d7be13e81fc4a86ff2512f949a5a57946bae40649b7feb50541eefe20806"
		"6d05051c456a49358a2b97d934afca4715cd6ab80f347de8830a9fd30cd355bc"
		"6e959f74c939ccd91335929dc4685e49d345e981e2340c89b635d508e9c7da0c"
		"e308cd4f061d51b929d40c254888fe687946118f222df1696a1b1d46ed863ffd"
		"b4a7b93464de80dbb5522dfa26d851adf016096c38e8d3908802a01380d72b98"
		"c9ba88ab4b430049a0f51ca3c81d001f1efdfaa08a2a5b07f93386fa0a8346e4"
		"0a89653c23167a0bd00602a89422b2c6ec450cb182be31d5a3f6f680f35339e9"
		"605b7670541d95272fcc0692f4ae10ab42346629876bfc027093182fa40cacaf"
		"b17ae3ce4621faa7a49151e84f88c2d50914319000f864974751158e8379463f"
		"e72cd5df62e95092169b0a320d796f4c272b946c572e139b0f791525f961b0a0"
		"e8ba74290e3f40f16f345af99549bf1986c2b847f3d5ae16b2533f7d6f8b92da"
		"9e6ce736b3e972cb96a269c351c05c430c20c5a83cb5e0111727bc1d4bc092f6"
		"ef89578ebab08d28732d5e1ba8a5ebd2a38fe2189a954e92263db48df6c85bfb"
		"c55bebb7895c3a11ee1f628602c217cf3255371e753ea3a4c7dc4e56d96b93f1"
		"0728cc3b8ab5208cefbe9c8ec7dd8541a1bbed423579854ce24eb2ff5b71e3e0"
		"9d3921a22482e8a45e5435ba60bfe030d8092c0c420c9d945fd90910e3a1f2d1"
		"6ed61372be8d395e232754923330cea5be871b0505bf928326c67b12dbc469cb"
		"6446ca35c29cbcc4267f229fa9f8f7a63d7de3b4e45c0c21205d2f8caaa2efd7"
		"66d36d72977818dd50a6c7682bde053e3c32aba148a9b57733e54e06b8032dfc"
		"5dc324b2a5e9f6b187e36a761fab9d72a4ef9c559a70328c48a8ff086dafca42"
		"2f5f197c54b7fe49b47d334fee27694c5bfcde5740772e6948ec6b1b316d6fb1"
		"c5ef71580ca9d7acc0bd4b7d011a11d34aa1982fa4874f1419fab9c66c07c452"
		"07bb57ce35882ae291ebda88bf4c3d0f5926f3662c673d97a51a12928643702c"
		"dd0af167371c9ef4114f07f68f85940971d2168342e1a1fad2939e06e7ea1c47"
		"302667aa7a2ddce92630fb51db8cbec878ee290e4dbb23438aaf84aaf7c46fac"
		"e655e22067838bc9bad8de200a2a645458c25690b5be6a7cb4b4ed061f981262"
		"e9e08a4f64e5549db48dd7ec84272eb6f796c390e1b21fac38eb00a3c530ac71"
		"1f0f86c1da1ddf6cfc980e3cb04bc3f53fb298963b5fe9dcfe9ce6085352e6e2"
		"7229fffe32f1d33e7a41ac98f85dcc19165dfe2a2a8c7113ed0fc6bd2fc768bc"
		"c9781c8cd22ad91b16cfd988c327f02b66e11dd516035f59ef8bc94bc356d907"
		"0b4206f52490980cb88cbc957a6fd83216841c1e678a5ab6eb5a173975c9e2cc"
		"22d0e4c18eeab91848be7e4683fe2b360e8f238e86ea0a33cac2d70fafe72a12"
		"f56adf767a02e348aeae4624479c9240364a5cabd9eb18d7720c3256d8775ae1"
		"6c571f9e4f9ebfa3d2a43db62e10b55676fced00c9542cabcc7f4f9557421941"
		"6fe1cbc07587f4319ce78b84a1243b83b6eefe12bfefedb5c06557549610103b"
		"e64e0b6554852bfaf5c15716069ecdccde69b86b218204ff3704711bfca8e6d6"
		"b9e70914545f0c07c378c9f5c647123bd6b3429258d6189117a6c673f1d4441b"
		"d1f4ea55dddf3e5ff0550ba84ae7b3d78614c50fcdb3d2714a917de3dd5ad210"
		"14bdd9b057cb6a0a62a042b7f94657a8d6d6696be7e0daa9b60dbff4290337bf"
		"6b89fcae2aec371103a199ab3a2ba7b7af40552d0d27d7414564b42c3b971c30"
		"bea27bd6be0a4e7bb9a0360a77604a0bf799b2dda94e723fdedc83167cde286a"
		"f64e7fb17bed56506ee4415f17abe9ac982aa703221e52ad68bf553754a00475"
		"f9d630c5ca5cf89809b6e32f82d52ca3783b5d28e05f1f92cd5351192ca45759"
		"b182b59d1120dc5c725e43041fa6baf78113fcd34bd983f7f4e1a0436ab3ca1e"
		"059937beb901a9a491248b6558e53cb099fcab8dcb5324e3c5b0693d789505cd"
		"dc65ddb22bc708764e4fe0db945c59d7aa3c92ddc897aa5e280ad590bc12af6e"
		"202cd000ce3aa0dc91296ced3cd1ba739b1cda4baa6bbe7105350cc3a0f17007"
		"b837373009221add42f85723b60d078c54e4ab5fd9980822447a355e8afcf2a2"
		"8cce3bca46461d814905c9056bd8e72bbddc2ca2bde62f7bcd2178e9e4f9da46"
		"84380457ec6f52d18e98e91cc3f90256be4c869bbe1cdc848872feed15b1d3fc"
		"88bfb95f636560d4f9f9dfef273a01183f7be0d34504b6445eb5eff285ec83cb"
		"80a9826812f0f193736fd406fd618c7628b263d0b86466c33531737e9c7292bb"
		"543f88fc63d8aa14e243f0eaae374a7a6139371c81059309f72fb01bc20aa9d4"
		"ecc9f3a2bde4356130be5a22a384e42bd258833f06afe61f8af7d1505f7e701f"
		"308febe388de3a8243253b364310019164576fbfb129060cd8d1fca5db948ea3"
		"09d897452d8c607d05c3baaff5a24ab5fd7d2526e93d9dd8c7055aa39e15ac68"
		"5dee1f5212b6505c5cdf00142304679e8613cafb15b1508c41da12d110c87177"
		"1617ac92a026b22732c034ed34fcff54e86189c79f4ec92e2d994cb89a7786d7"
		"1a9c668c3fa32de46eaf7fc39053bae009af8811eedcb0c9728b32dea2e89290"
		"53c574c858f4699df8f4091c9fd14249d345ef616a23ac62faf5e9cd92e43eab"
		"a7d9fece51e20f59b8d7f983c83d3c972d6ae73f7bea6603ac229c0dd033322f"
		"00222e279435c72196a0777d766053d3fe68983489fb86b370597124c69d1524"
		"45e62a5a87b538fc7a96ad940e032d04308529c7fc1cb37b2ee1909cdaea8f93"
		"5e6e1aef94290bf24c02c14ff9ec7232aa0ac2813c169561ce0322fd76e14a83"
		"3202276e225be70bf42cdb369fe4cb65543f8de9b1b1d57039074fcd014cebfc"
		"abe97960981175505a5c24d268b2e0a6166baf87c4b41bad55353e96e3f11d06"
		"b06d374d60145dc866dac3aabd2058fcd8d753e3dbe90e220bd418df839886aa"
		"2ad489bbe12c467b01ede14704f4db7082cc9f86601657d6442e04314b0bceef"
		"ff6798348320d87211dfa62fa7f71309fc90bbf7b9049ed1e6892b13a2119ede"
		"186e8c3faebabcb47ff639ec0cf1a5cf2e6bd0be507b8a1cda2eb50df0719e7d"
		"5d318d65cac09a49347bc3069daa3cca01a706648b43c3be0965c9a79ef475d6"
		"b6f7c12c3ffb193a17b56b03c0e97e035b8b8470d423f2bf5a768f6a1262cbf1"
		"0c0a531f7633e28e0fee5a6ddf781381265e736a92e4bf28b4a830ddb5834ad4"
		"45b069c3d5309d4d066cb7cb611da44c4869fada2c4ed1000144d489ef1e9889"
		"4b322ca2c5b9f180e379aba6aea1d96dabf442490c29d14f2892a2f429fd5d18"
		"04d8c343af98862e8e5b5e852ecb59eb3546733f993d661d11dac3a8c9e64287"
		"5ae9562ef993055fee5af7f04965cdced0a9b4423b523973a4645f2d39a2eee0"
		"34af0fec0d73161bedc09f6f6735dc1f63632ddc5a2ff158c9779d09dff90b2b"
		"7970140451ff606b72d37d8bf0052fe5d5bd07945e9d37d5685da5c625b23e6e"
		"13758dfe2f018c5666ddbacb4c9b6d2810ff6af2b064b3f1695ca0eb729731b3"
		"e906a3630e3f41e5af247db8e3bf3ff0fb717d7fb64c0cb4b4bdb6012d6e8c01"
		"e36a7db95583281f36f1efd81d3b4d467e5b69c2d91deb2631c80e8fc000f661"
		"e9eb458b6e93e90ce38b37b663d63e3181045544819ef750c9c4d11d921518d9"
		"e3cf205ec0372bb49f3c7fd71b57bbbaecb56a8b1798d93962fb26340b759a74"
		"b95f38bcb3399620504aecc5af876be8a7b6d02101d338e9e5b3365b93e72337"
		"54e3b52caf60d357dffea807852ef7c39b4fae8ea917bd693b35281a92345b2c"
		"9aa3bf371c738a6135a0db2507140653aec82c58752c10c04ac925f97024ec5a"
		"74e67c63623b62473878aca79b0041a1c9687409cfd9d8f6fcb65581957f7bc9"
		"caf6173be9800410d2cd4416abbb4fb4d578ab281ee7bd143846df396a0db382"
		"8519b6441a0918c4eae9cbfa9e0eda94b840fc3eca1f6921e5bfeca95596398c"
		"8b9882085ba0456c681268d9dcbe874a5c088dd23b468125ed6aa35abfe1b8ef"
		"c6bba20e150b330e3391433dcd9600dda718866cd827b029378f2dd311b7d6b4"
		"1dc93edeb1138bb535ae85add95ded5583b710950b899c33ab76b19cb1e03be2"
		"770c80019580f56655b056b268daf5bbd72f53d33c33ed4e3166583e09249081"
		"beca8efe2b1a182b7be1ddd3e2d6c1168bc676b1d1ee4c7fb1a94a407f4b7d9a"
		"d94c905ddaa99d0b8f874398af19f96e86c5a1b4338261d01385ae2a7d1ca933"
		"b0daafa709f42b0f7aebaf89376b44cbb274fe66cab7d3483f43ac856a60bd57"
		"2bbb126322c46b3d22554a2fe2944a36f61ab24efe554aef1e2a6ed8aedf600b"
		"3239e3198ce1059f700c3c11195bb4b63a00e8f4382370ce968419abb1613b59"
		"ad9a4751af13a03d4c5aacb7428a2a54666fc6e1deeaeaec9097d887daaef648"
		"84276894f322e41d9f85c2aac7e7531763ad749c5a726352f5add1f2938d38e0"
		"9f286e69c0d57b494fd6a8710e3bd80717021bad12838106ab0c2c7644c8a92a"
		"e6e581597ef50ac946958394814d602c6bb8e39d70e5ec129cfc129b5325f22d"
		"42a5c7eb954a3ca36a0a7e9c86e7948f4716f3f3da5f4d7daec7abe8296dbbf2"
		"99b26ba76d9cb6e1a57dbe1087cf1c3794637437babb4c50cbb41ee52e67ab7f"
		"d55293156eb3238bde356e78ebce9f2c38e88df277bf9092da0a941acadd6bde"
		"dcce68be015729a7fd7bb45d1aacc6771ded67ab7934c24bc31234106695a317"
		"986e11298c4f703fe997b8457c31381f29b929ea28e189846e14274e6859fa30"
		"ef79b6de7964a15a8cd1a3bb79259d2c4696fc37ec908e44c357945c3aef1833"
		"cb3981662e5e6401cd709d44794f9fa75bca081b2d077993aa25a4c3421fa627"
		"13f498481505603b94becd6ae478e497509e741d530ff1790bc47e0aeab34c15"
		"aff3230c94203e10c9015cb4226814040d5a69c6c6709effce7d4cb99971b104"
		"867e4b3b1579a588558272aa9be7d8f679460e9ceef2292cdb983359b6237efc"
		"82dc375cffd63eac1e8935d5b7bdd8767eaa8c29345d3a091a5d5d71ab8f5a06"
		"8a5711f7ba00b1830d5ed0bcdfb1bb8b03cd0af5fe78789c7314f289df7eee28"
		"8735fe94aebfa5150a4869e8798d293ef1f8b186b50c8cefcf041929bab7e26c"
		"5fbf28bc43dac36bfe9029dfef17cc962e73a966c2e11d0a1476fbdaa404ddda"
		"fb3db7f6e11bb28ccf7f372ba718499ba386191d8bbfd4f32cb2c023052b8779"
		"43f7d3cbf0481a80675bbc530b574b55387929317a6e59b4fd008f8d45f58951"
		"1f34a2c2d82aa550ac6cdfe0819e78cdd693032cf6b5535571a8909fcc2a8b6a"
		"783e4f630189f90388fcc95973b3780a631dcc96665e6bdc6ff1ede1039234cd"
		"345b0036d32dbea1e251a146485ff414c85faff5342f4853de25cbdb50f42d81"
		"3dd4dec4b7dd9d33a1b49030686a94f4eea1d2d3c7f193c1a88a55161c1a1d8e"
		"79f1109413633dc0af6dbe9e3b9cffb1bc2b5db7876bf32fb468b019d0caadfd"
		"d2f9be2e50854850f3c4521829bdde531944792adc6711a4ea09076cd2cd85d5"
		"2f36121bd70c63ec550174269a94d8e3ef364eb32eab942832b480988ceb4c1e"
		"77ee32e20fbf389abd6b4e51f6ea9667254703dae50125c374b0432464ebabe0"
		"946a460b5f686f64134b0520a587bfeaa3c0c027692f6c7e98467998c4974924"
		"6df2771f31cdb0523fe9c41c0f33fc7151e9af2323fd106086be4a7d13b5cff1"
		"eacdeca5ecb8a26b2a8db1cb9cb6f5061709f5557935ba722760dd59b90ee450"
		"f345cf25f7efedb7ba7ff4b7b5d751b0dd69bd45d49d11bb61735bb71e6a3148"
		"70a04527bc3a3a3ed806b668c05fb9788b522d7c9dffbe431d41eb1caa915de1"
		"49277834a26331096d6c1f652717d464090a6d813a2168124410b612c54a1123"
		"672290d31130791f5ff7563650c44b7f3fd9a6dc15cbb831bc29e420d75ef517"
		"b0d9b48d716bbb8898f08463a531c5ce1509001694c755a76fd49ccf4896b0c4"
		"0d930de92bda9e4dfe9fd0748c25eb5b74e1a2b621dce97c435906a580b8eb33"
		"669ac36fa546cb757b4b63f26f67652d42a8b54423d119b822ff4b2ce78c4d6a"
		"a434fda74876e908f63d6465b5c0da4c69a76049026f8f64f30f93ece5dc7f73"
		"adaae31a7c34a10f56befc53c6f8f2c1cf26cc4c257ef3889ed1056ce36e2856"
		"6b449f4faa469b90851453460ad756935e6c20d5f6c6ec2a0a8dca34470bf119"
		"c54956ce38757e966a8790c5e925aecafcc3856cdc0e2354218b09cc7b7b82c6"
		"a20333209089f226ed61dc59cba9a16f9371239a3f20400dca12ebbde5868264"
		"ecb85bcc184aa14af6e85e88182cd8880abf21e687c2ea5eed6c988deff49afc"
		"8ab1f95a3a8030096d663fdd3876fb2049f5a8d91dbdc94d73df37c7008c7195"
		"643633535df24a6c3a21a6dd934fb13c385bdff967d886e542b4f1f07f17b037"
		"628e313ee86995794662bc12917fa2e6bf39efd1ceddc92b4333ed92d65efeea"
		"6c031ca345adb93a7770a8039bcd7725c6d6ffe6bb9239295ea354346c2604b7"
		"6adb1c0adb865fb7b69593381702d802357b38c294c17fe67c4e4d5fa93a69a5"
		"445f58fc12bc2ff7ec17a53a6fe66c83f470c2ecc230436a837a019af561d6bd"
		"e2d7f9005216d002ff3f05900941dcb3ebfdc4ecaea82cbe5d70976db862f306"
		"2c8b269f035debe0d955dcc24fdbcf97036a664bbff0e2e9f07838605a066788"
		"0bc208608d59279a60a15159a77cee3922fed2905cd20ef326d90cfc4315db4b"
		"65c6c7cb59d22d367e6a8ddc7bebe1a031022d43ef1458e5e5dd3ac8dc57f658"
		"24dd8a68cd90a4bf1afab8d332f14fd419bea2ecdf7f67c617caeb4d8b9361b6"
		"2e5079c0525a353a1b97f9c63456e1dec07a561494dbe49ea3e94611b993c36d"
		"6d67be5a51fa88b16b8a783ee9e23ec5107e744276f076757182749ecf1dc586"
		"c7697ebe3036442bf11b5ec3b95c0e91f01122ffed85c65469dd9c7c33fa0f08"
		"26a0e47559d711b19591d3db0c8efb4a477d88d261647b427341e7314ff248fb"
		"7152150632a5994a3f36fe104a3eabf9ff08d0433a533e4877f87d478acc1867"
		"90c83cf9256781fed75008e9db35c6a6fffb1fdae01bb76d5d4885464b522955"
		"6a4a7fd798e774d5452818ee273bf5572f9ea020bb848db90d7a27b4fc4a20cc"
		"e91f0627f5eb18d8710657a89718e0167738789c335569346fd58d1b047da8d5"
		"f491fa71a33c150e4431ed9e91932eeabf13d2d7b158f2e76ca3dc02cbb36777"
		"73e6833e0aa21480a4f301587e7587dcef75d4579b53d1d9ea2a3ff2b9b305ba"
		"4f67c81492e4bd347a92bb5fc78695f2efa7a6a65b0fad12d2b4dc7236472ba6"
		"6e5cf27ea3ccb734af57443ad28efd36a7f1714c57542f9b0d87db0aaa358144"
		"b90d2801a520ab88298ac47109556ab0009a5dcff9e9ff7b82eb65427d46ae9b"
		"18c1932700a94036d273628dd3a28267e0ec91b9a898c4ba182aa2a317425bb3"
		"74c25b771c2f1f48915a4715973fed63312d3691cb272661b98bb9b4e0f12f95"
		"b356a779627aefc54d869b91bff254acd9a673e0cc5fcf774c55d2fd411bd348"
		"bfc69fb6385159b6f040858ab2845f4bc29f712d12086404b8d11707a087eed4"
		"7e5a6db5077d052261d02d87d8bdb547d25f570005ea9011e747ae5966fe2942"
		"da5936fe38c79a11887ebc109964ffa8f3304ee10dccf9a4c0febf7cfc482c99"
		"ba0d251a31f4c18c4d925aad5d43e4760c587e59927847c82b4073f6c82d9ee1"
		"05bc5f905ccf219998532ee78c200dba04200eeffcb423821053f15134752723"
		"a5af0fe8201f6343510a61458ec4217cc5d0272cb34935dc57806214a7e77066"
		"812e5babe4ab2e8f60ff1a50cbf7c9c236b0f0971fff24dde90feec8894c21b2"
		"81806b60123c2b87ad7a828eac80ad963f0892b8a99d988dac48bcf4416ce20f"
		"8def688f119a013221c3c189972974ffc81f3417b7ed3bf58973f520390f5986"
		"8dc17ac1498d5998a221fec9f5b8c706b93eff3db3b5b21c68d7c0d5d8fd311e"
		"693fc87c22dddbc219de62d42ff64db1faad1bb103bea80b32bd469986fd10e0"
		"09b17b4b04512eb76f401434ababaf0a74b4affb11d0c3c8cd6daff7abd99fd2"
		"565fbab357b3fb7f8a903c71d39f94190d9be3a443b3ab5d232f2274af5785fe"
		"3690ae3e83c9e923541504110e99a5e5aea9e033032e09d11b4bc79afb406a6c"
		"928e7f73f05ca1aab419929ec3638a764027ce30b80a852d9c08c7f0f55bf823"
		"539f54da0633ca1c91e20ea05cc3ead4a95dd523c90fc67890b04afe0672d52b"
		"5f0c55fc2e180d82d5b9a19d40826d08d3931b95a00575bade89774d964ba98c"
		"a01dac60ced112e367e6731fd768bc19a411cb0ea4b439fc6edc77640eb01d4e"
		"fd197e8f502780472fb1abad893c7f0f061e0b143de4bb4528f072cbd467d87a"
		"5d4af60f1ae200b6156271d0bec85df2e0040331d35ca39df40f8f0b52388318"
		"aaf6396a96ca39390140ef0eded2ffcb1909ddeccee5980cba7ff6abefedc62e"
		"cb6672272aa6d4d7db944af251230da19b76becd9747429b6289d033124c48c6"
		"a8e2c7cf404078998ba6ad017f832e7d4d93d05d944a4a51d475452c251fb2e7"
		"29b160e93f5ece85f9be3ec5d1b90a6617a73b232eb55837f88b7c1d8f2cab9a"
		"361d66fd8fc97da60e2425c5ad8f4a64e1fc27a8cd521353b6139e8eb83cdce6"
		"b76c019498492e01b01f8b897ccb967f93d8bb72dae724aff754d2070816edd3"
		"94e75835c1a689a0c8f9989aa73695c016841f0bbb3d3253a1974111e7848569"
		"b5d6946874a7358a3ff8737f9498f02e50487cfbda1ce6459e241233bd4c4cb1"
		"0281dcb51915dbc7fb6545c0adb94fd22a6bfac89e4ce88fd4436ef6f237ecb2"
		"642f59a516b82260e68835e6596058b28c37c0fc6e94df392d3c7de1ee0d0a74"
		"c12a33bfd458b35ce7a86c78ff57b6d85ff2f71eb4bd74499056667c19965100"
		"03b8918bbbbd35c3e50e11fe09640f4c89e5c6b7d7904ec9e4da524fdc99665d"
		"10229b9234ae519dca034d00de500c14f458564e3fd216c0131068e39de0f493"
		"d2b07b5ba5f5aff37dcd4807e6e2543a8692ce6b544e73370440d1bfc531a1ab"
		"2fa9566f7758f6cce6b4299a89e490c629dd57977dcb0e359fb2b46bbd5515ac"
		"1157575413a0cf31ed0219422f1c67bec47f195825108ec2ccae3a70ec14f99e"
		"5f00a394df95e1297afd3f864054822c3fc13b39b1e69ce6737b8b55b935f58a"
		"01ed65b745fed5bc75efc4ee2452881782ebe6bf8a15e0aa7c62cea28e82b077"
		"de66c343aca452f2c61ecf0243df22887445417418650115cfab2ce0d2c1d36d"
		"e0b2e5c27c5001d455d3894b06c2f886ff1775dfc39ea830559ecc96ecbb0574"
		"ee1bf4bb1cc889690a551950d3c5b1190aa8a988f4877c02f482d74c4638ef95"
		"f0e718b7f6d494baceeea89913aef5497e4106f811e9269395a1748a470039d7"
		"cf5f783d713ec7cd87e45eaf2f466e1f412ab4b6848c4deb2141ccd957da8a43"
		"71cb3dd5f5cdccac1f8062198d55c2a23cabda4ab3389a137eab06c0de8f8adf"
		"bf738e07ea484b5f7c0add5f97a399db570ca03d08b5b41296274bc844e8e2b5"
		"a19e945cb978ebec88caf60ab4f79cd07b942f16e9ca45f04ffcc377f2aa3acd"
		"0096775bc825555d2907d6a14b1a728b8e8caf5dc041f2b5937495584ea0392d"
		"c2a15e8d801631ba490ba4acc6d5c414793c489bf4e0656a49d5eaf0c19188df"
		"d108717849152609cf1c89b48cee3a7125ec2056ed7046175968e9c9b444cfeb"
		"1313daa68ce8dc54a383ad40052d7bac79e4621913b83cc2aa75bb6a8d82b557"
		"7209be9faf58fca2ad8837d8995c30cd5c6b3469ce82f0752644875bb613e22d"
		"d53448e91c2d2efcd5725004b04100dab8cbbed086940a37b41c762595bfff75"
		"23da9d0e392f1969038b1f4db2a694dd744a29d5a3b731113c47b04f944eb435"
		"4644e896702666f11f19cd3a075193dd78319d018db30d09a70b5c611987a877"
		"25ba4f0728d9bc9c11658154170aa6e3acc841daac50472adbb1a2e38e338442"
		"a883faebc811c473c1b764214b9b75f6f8563eea69568779c180ab5e5a1aef9f"
		"b7e912c9ba96267d17579e2b09cba71e4425bcb92a8c740041c29f5ae5049294"
		"3a32bf2a653089c2fc8c56faba61e563787be2cd58bbb7c644bda65d97b9142c"
		"19a7289531a7954b569fb414c726d6ce7ca1d8b05cabf8d3b0bbe6f1d8001f6c"
		"3c90769286c2f31f0fd8e10396e2236638dfc7ea9c24de306f028a9d10a3585e"
		"8c35d0a9cc4a4b460d7f054f915c7334947cd70182ee11e467dab8eaa7686909"
		"efdd5f636b0844c93adc477e1f5e6f3e79c22f7f75d03af7828d985e0518fa75"
		"4ed24b47cbc187af7c37d01aa7aebf8ecdf7f8ecdc940172a6625483927bb2ab"
		"925abbde5540bc00bdd7c8ab93150a2c7a6459ce21000d5cbda011e1b7583ab2"
		"a1bed7ae6f4c8ac5e40556b74a5bf81e66517bafabdd07bdae90fafeda783992"
		"6546c94182ac9905d909a2c83448326e7b058516e2f2969d617a346465a45854"
		"c539b61ff72992c8842bd565b9a460249fcaa08c2e096305bea6ea9bbea23fff"
		"a8e1c9ce348b1d16cdb3171741362a46bce6f498f7e815fcad5b42294f3a959b"
		"f88427d8a39ae1f89ce88f6434c736deb9a2a8c2a558558b16e264987e360331"
		"9c6bfbc5ab1d8775d91366d7fa1f2ff37e46e592a021cbb9e1837970b55d30c7"
		"7cde6b1bb3deb6966c7cc3f5fb06bb8ef31ad291510b1e8ef686a9375b76c568"
		"80249f6425a317623d6bcf48a04482b6006698461edef7123d331b77d74a6919"
		"9087c027683552e13428b2574fa02d738d715e397061fd4e9fd2f8b793a1c5e4"
		"944df6ede45c0e1b3afa93aa71e464cd82844df3b05dd94902aa6780f64280d0"
		"74bf683d01dff319352b9aca6fd6cecdc7e78dfb449b320b5004915968f743e5"
		"18253f9f2788aae20f01f13eaf3f147a44e245d996e0b19d6f289eca5186b62c"
		"68c7a29bbe1ddb7eaec5bd8e9be6dedde2bd9d160cf7fe06495eb55b1ab880ac"
		"4decbaba2e672ef6fcbe29439a95d3fc87bfbe3910a7c04ec4eefe9529554a6e"
		"addeaf83df2e4951df365ae413129be11c31d0ca09b79f7eca1fa2ffe725bb78"
		"72e3a87f3a3ad79741737bf97026df948a5bfa525ff0459d423bc922bcef7cd4"
		"8244cd34a5527ed009beb20a1899471bb7856558791a57b313889a84117d348a"
		"c749472c8940e6051f5f27a073337a808df73964c1fd80c9274f3eaf4c958ca0"
		"27393eef4fcab83e6b9e0442e9bc21cbf3f89dfe9e6066e565d7dd2bd7002c20"
		"8c5ed9035db99c81d4c36e79e2fbe302d0d2b9af780cb112b56a9d7e1886bb11"
		"ddfe41f21dd439d845158fccc6b9692f0ecbb6feb8ca0a55ff4ea93279eee27c"
		"02629e44f5e5384aa3dd8fc3fdbe5a59942cbc74c46019b82bcc27cf60024868"
		"e2d2177f4fb240dfd76496e6efd25f894a3df29705968542222c40db378896dd"
		"6795d42d9205faa0c9efcbbe05bd20c6184581f2e336f6fbcab61be0654973e4"
		"78f5fed526a40e9461c956d2a5464418e68e910ac70616ec0cb2e165520d8883"
		"fd38bd00735723c4883960aa383774879c5e496917d08a1cd167b9f3669c7cc4"
		"dfa73835e1e8e136248611cf2756571c22fed1963d5afd93ff1ecc1109bdf8af"
		"048a98fcd81df2f41ef990c8d96c96de60b652199f6d155a7f1f4147a33aa44b"
		"552904ddc0c0fb065fda061db540d8d63fcdf47ba7d07a783ab2411d9cd927a0"
		"bacba5610197a772ce719a57259cc60aa58dde43bb4dd5f5171ff41c5c632ab6"
		"1cbaa30f036b9b42520575fd8f4607847b3c39f945aacedafdad81cb4b9f5496"
		"613c25702e03827ed5dfbe975d07444caa232c25acb00c2ed6a511b2d2574e47"
		"739a530aeb29022c3e489eaef6a72568198ae050582738f9894fcb5a5751bfd1"
		"381c5668a0a3c35675863dc9c2ee51e2afb87c01b1d7f944fef3d84a4456503d"
		"9a09560fb73a6e0361e1c27029a471c256f729c11f87f8161dd95f0aff2ea992"
		"80ab7a8996b6ab3ceca3552b93902c0ef58d0f170a01dd77ce498923f2a171d8"
		"d148eb5ca7df2108fd122083687b2bd073c3558bda0b4f6ff98a7e1c83775017"
		"7729d113507d796f7d7848ff102d160fbae124a5f76ef60786e5657d1c77f058"
		"59965333fb575b79521bf828f46e94d4b12fa3eec9f27b465da266cf246bf6a2"
		"5fd699460f366d2f654456847a064d2640f5fbedb95e86356609ab9903190dfe"
		"7133ccd4f4e25a989e3a8a9d0bbcea0d4f7a532a2d7cbeda8a6159632049db73"
		"77f314631123c8bce547bdfb10591391c607d42e8e12cc3faff49bb6e5c50809"
		"595f987dd0c160a423b11724efa66fbb8de4a58045e9576cbe089718b9543dc8"
		"ffbf81a99883c9573ec1bfa21268a7928d59f0a9b8c90867a0e6751404bd22b9"
		"525bf670d232abdd20bfdefddf6a621eacaeda2f5179873a3bd65e2f2fc95ee3"
		"387a2058e496b03faff39bbbc0734968d32a8d9c77c37bed791f7af3a0409a4f"
		"9a6627eb37777e84d5a41f661c4a0477eb163177916d8d86410bf0e7c0ea7d03"
		"616532b1339dbdb4791c91855ab83a54dabaed490940640f7ae0e993f78eb009"
		"73c0693140d016d883a11aa1e48593058a5eea994604a98f0ee78c80aef6da69"
		"babff5f3c7d730f7da7ce2412179b994e14a50efb081030fe46802354be8a429"
		"1da9fe7f2e7bb51968f510ed795b5108c9c546d3af7e1b96e4ab723a382db553"
		"83c8ab5edf844a461453cd2e54f5066a2919f4ceabc5982cf6f70518db8db7ee"
		"d662251740ba9987c6e0408a1a0d7dc1e88c83670c1c23d90296e2569ecf4f03"
		"fdc09432bbe44ae366e2928b336c6115f0671b273a4c64a6f0ce337ce8bd2799"
		"e02a1f37b7cc0563dda2eab908da586f28f2e3959e1d029aa8e81d13201de7b8"
		"67e7eeaf9c38710e1168719bff1f0ad6787404399e56a6be132bcaa2b0b83768"
		"7a412a22d1f136eceb7c4eb981022152c837a69ba3c1f71817e162b1ff56bdb2"
		"017efb16c0bffd055325aa9bf74c42eb0081ef4416249eb39d500cc875bf249d"
		"e4e78815d0696e6232acadcac7c517aa099b0abb5d4842948ec2f1707aba1232"
		"0bc4faa669b9300a6e597ecd5b354896c9cd1d88e2f58cc5d07d393076103078"
		"5e5d7852f375ec05f174462c19647db7295e51340bf2234d4dca0b91d1892577"
		"c6f92b9fd666495ca1452c706b1a5d161198cd464209b134ebf08f1af3ed9937"
		"29e23b177b54f01668145920b81e90ba6ac1ba46ee00db829439ef53450436c1"
		"715ecf424807883b2d28f5c46739bfac1a223fbc76a04b402feb50c42d96a11c"
		"84b60fa7a646bad4d8ca27e4e23392f20b03853144b1a976a44fddf6146a8550"
		"4c3224cefeda2ee75042170990d4b09623acb32dbffb9c2adbadbb7063498866"
		"af19363fb68c8b7f7fd8eebad9e3c29f4c64f2364f45cd66bb4d15ba80fb5265"
		"97b56c83382279a14cd4d480252a6f166d746ad65c59e4312e76115dd5488c55"
		"eb4cef21ea64a2579f7df0e2dc6f60026e2442944efd88941c71d7e0c8f8de3e"
		"9327e7a1361caba8601c6b68667b3c6b36bca3f88efa61956b8790cbc3d2ef29"
		"768e7b8c83103f9d77f96c9a2c16ac5aaf84b48b8218183f04fd64a72d9f681d"
		"7ec8d3683809043ccd5c1c01940758d5c0c49ed4931e5597cf1e7afa6e27f023"
		"921f18c0bfcfa28f488da3240718e7e751c3885c29d6bfa7b431fb4fee323042"
		"9ad972197f2ac29ed1d3288bee0f02954bca9ba9ad06ff769c7d0e2b1488d082"
		"7f3f08fde0e20c6f5178d3bfafb550e99421fe458577bd0c6d4bdc184af077eb"
		"279903f34abe270daec2cd47b4d27aea1510dab81bf1a07211e38d9df834cd86"
		"7b2f8a842588bc7dd2fa3eab632e27a0b6df5788d63c50af6e8d4843841a7c5a"
		"6348c636d90672c8a3674e742690001460d59c3f1d1f76cb6e913590576b296f";

	size_t len = 0;
	int ret = -EINVAL;

	memset(&test, 0, sizeof(struct kcapi_cavs));

	test.enc = 1;
	strncpy(test.cipher, "ccm(aes)", CIPHERMAXNAME);

	len = strlen(msg);
	if (hex2bin_m(msg, len, &test.pt, len / 2))
		goto out;
	test.ptlen = len / 2;

	len = strlen(iv);
	if (hex2bin_m(iv, len, &nonce, len / 2))
		goto out;
	ret = kcapi_aead_ccm_nonce_to_iv(nonce, (uint32_t)(len / 2),
					 &test.iv,
					 &test.ivlen);
	free(nonce);
	if (ret)
		goto out;

	len = strlen(key);
	if (hex2bin_m(key, len, &test.key, len / 2))
		goto out;
	test.keylen = (uint32_t)(len / 2);

	len = strlen(aad);
	if (posix_memalign((void *)&test.assoc, pagesize, (16 * pagesize)))
		goto out;
	hex2bin(aad, len, test.assoc, (pagesize * 16));
	test.assoclen = len / 2;

	test.taglen = 16;

	/* expected: full AAD: 5b77260fcfd3ac8a714a7a6fe3795ed39d6abeda3b199c0de8e64b57569d75874d85cb992b7e7aeab81ba7cf77285969
	 * partial AAD: 5b77260fcfd3ac8a714a7a6fe3795ed39d6abeda3b199c0de8e64b57569d75874da5e05a23b8902677480ee92c7ff6bc
	 * small AAD: 5b77260fcfd3ac8a714a7a6fe3795ed39d6abeda3b199c0de8e64b57569d7587fa431e683949010ded4a091fa7b5bf0b
	 */

	if (stream) {
		/* for sendmsg, we can use the following: */
		/* test.assoclen -= test.taglen;
		ret = cavs_aead_stream(&test, loops);
		if (ret)
			goto out;
		test.assoclen -= (8192); */
		/* However, we now have vmsplice here */
		test.assoclen -= 12288 + test.taglen;
		ret = cavs_aead_stream(&test, loops, 0);
	} else {
		/*
		 * vmsplice: AAD must be at most 14 pages as otherwise the
		 * plaintext and tag cannot be sent - shrink the AAD by two
		 * pages - for sendmsg, this would not be necessary
		 *
		 * AAD is 65504 bytes (in stream mode together with the 32 bytes
		 * plaintext we have 65536 bytes, i.e. 16 pages). We shrink the
		 * AAD to 14 pages
		 */
		test.assoclen -= 8192 + test.taglen;
		ret = cavs_aead(&test, loops, splice, 0);
	}
out:
	if (test.pt)
		free(test.pt);
	if (test.ct)
		free(test.ct);
	if (test.iv)
		free(test.iv);
	if (test.key)
		free(test.key);
	if (test.assoc)
		free(test.assoc);
	if (test.tag)
		free(test.tag);
	return ret;
}

/*
 * Hash command line invocation:
 * $ ./kcapi -x 3 -c sha256 -p 38f86d
 * cc42f645c5aa76ac3154b023359b665375fc3ae42f025fe961fb0f65205ad70e
 * $ ./kcapi -x 3 -c sha256 -p bbb300ac5eda9d
 * 61f7b48577a613fbdfe0d6d90b49985e07a42c99e7a439b6efb76d5ec71b3d30
 * $ ./kcapi -x 3 -c sha512 -p 842006
 * c012cd78aaf71689cf411e4f76620c021ed650d2268dddf29121f49ffdeba7a642700eaf722aca09503c8f56a1388cbc3e4c8454b990180d354dd580ea702ac8
 *
 * HMAC command line invocation:
 * $ ./kcapi -x 3 -c "hmac(sha1)" -k 6e77ebd479da794707bc6cde3694f552ea892dab -p  31b62a797adbff6b8a358d2b5206e01fee079de8cdfc4695138bba163b4efbf30127343e7fd4fbc696c3d38d8f27f57c024b5056f726ceeb4c31d98e57751ec8cbe8904ee0f9b031ae6a0c55da5e062475b3d7832191d4057643ef5fa446801d59a04693e573a8159cd2416b7bd39c7f0fe63c599365e04d596c05736beaab58
 * 7f204ea665666f5bd2b370e546d1b408005e4d85
 */
static int cavs_hash(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	struct kcapi_handle *handle = NULL;
#define MAXMD 64
	uint8_t md[MAXMD];
#define MAXMDHEX (MAXMD * 2 + 1)
	char mdhex[MAXMDHEX];
	size_t i = 0;

	if (cavs_test->outlen > MAXMD)
		return -EINVAL;

	memset(md, 0, MAXMD);
	memset(mdhex, 0, MAXMDHEX);

	if (kcapi_md_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of hash %s failed\n", cavs_test->cipher);
		return 1;
	}
	/* HMAC */
	if (cavs_test->keylen) {
		if (kcapi_md_setkey(handle, cavs_test->key,
				    cavs_test->keylen)) {
			printf("HMAC setkey failed\n");
			kcapi_md_destroy(handle);
			return 1;
		}
	}

	for(i = 0; i < loops; i++) {
		ssize_t rc = 0;

		rc = kcapi_md_digest(handle, cavs_test->pt, cavs_test->ptlen,
			md, cavs_test->outlen ? cavs_test->outlen : MAXMD);
		if (0 > rc) {
			printf("Message digest generation failed\n");
			kcapi_md_destroy(handle);
			return 1;
		}
		bin2hex(md, (size_t)rc, mdhex, MAXMDHEX, 0);
		printf("%s\n", mdhex);
	}
	kcapi_md_destroy(handle);

	return 0;
}

static int cavs_hash_stream(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	struct kcapi_handle *handle = NULL;
#define MAXMD 64
	uint8_t md[MAXMD];
#define MAXMDHEX (MAXMD * 2 + 1)
	char mdhex[MAXMDHEX];
	size_t i = 0;

	if (cavs_test->outlen > MAXMD)
		return -EINVAL;

	memset(md, 0, MAXMD);
	memset(mdhex, 0, MAXMDHEX);

	if (kcapi_md_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of hash %s failed\n", cavs_test->cipher);
		return 1;
	}
	/* HMAC */
	if (cavs_test->keylen) {
		if (kcapi_md_setkey(handle, cavs_test->key,
					cavs_test->keylen)) {
			printf("HMAC setkey failed\n");
			kcapi_md_destroy(handle);
			return 1;
		}
	}

	for(i = 0; i < loops; i++) {
		ssize_t rc = 0;

		if (kcapi_md_update(handle, cavs_test->pt, cavs_test->ptlen)) {
			printf("Hash update of buffer failed\n");
			kcapi_md_destroy(handle);
			return 1;
		}
		rc = kcapi_md_final(handle, md,
				cavs_test->outlen ? cavs_test->outlen : MAXMD);
		if (0 > rc) {
			printf("Hash final failed\n");
			kcapi_md_destroy(handle);
			return 1;
		}
		bin2hex(md, (size_t)rc, mdhex, MAXMDHEX, 0);
		printf("%s\n", mdhex);
	}
	kcapi_md_destroy(handle);

	return 0;
}

/*
 * Encryption command line with private key:
 * $ ./kcapi -x 4 -o 0 -c "rsa" -k 3082021F02010102820100DB101AC2A3F1DCFF136BED44DFF0026D13C788DA706B54F1E827DCC30F996AFAC667FF1D1E3C1DC1B55F6CC0B2073A6D41E42599ACFCD20F02D3D154061A5177BDB6BFEAA75C06A95D698445D7F505BA47F01BD72B24ECCB9B1B108D81A0BEB18C33E436B843EB192A818DDE810A9948B6F6BCCD49343A8F2694E328821A7C8F599F45E85D1A4576045605A1D01B8C776DAF53FA71E267E09AFE03A985D2C9AABA2ABCF4A008F51398135DF0D933342A61C38955F0AE1A9C22EE19058D32FEEC9C84BAB7F96C3A4F07FC45EB12E57BFD55E62969D1C2E8B97859F67910C64EEB6A5EB99AC7C45B63DAA33F5E927A815ED6B0E2628F7426C20CD39A1747E68EAB0203010001028201005241F4DA7BB75955CAD42F0F3ACBA40D936CCC9DC1B2FBFDAE4031AC69522192B327DFEAEE2C82BBF74032D514C49412ECB81FCA59E3C178F385D847A5D7021A6579970D24F4F0676E752DBF103DA87DEF7F60E4E60582895DDFC6D26C0791339842F002002538C585698A7D2F956C439AB881E2D00735AA0541C91EAFE4043B19B873A2AC4B1E6648D8721FACF6CBBC9009CAEC0CDCF92CD7EBAEA3A447D7332F8ACABC5EF077E4979897C710917D2AA6FF468397DEE9E217030614E2D7B11D77AF51275B5E69B881E611C54323810462FFE946B8D844DBA5CC315434CE3E82D6BF7A0B64216D887E5B45121E638D49A71DD91E06CDE8BA2C8C6932EABE6071020100020100020100020100020100 -p 54859b342c49ea2a
 * b29776b4ae3e383c7e641fcca27ff6becf49bc48d36c8f0a0ec173bd7b5579360ea18788b92c90a6535ee9efc4e24dddf7a669823f56a47bfb62e0aeb8d304b3ac5a152ae3199b039a0b41da64ec0a69fcf21092f3c1bf847ffd2caec8b5f64170c547038af8ff6f3fd26f09b422f330bea985cb9c8df98feb3291a225848ff5dcc7069c2de5112c09098709a9f6337390f160f265dd30a566ce627bd0f82d3d198277e30a5f752f8eb1e5e891351b3b33b76692d1f28e6fe5750cad36fb4ed06661bd49fef41aa22b49fe034c74478d9a66b249464d77ea334d6b3cb4494ac67d3db5b9564115670f943c936527e0215d59c362d5a6da3826225e341c94af98
 *
 * Encryption command line with public key:
 * $ ./kcapi -x 4 -o 0 -c "rsa" -r 3082010902820100DB101AC2A3F1DCFF136BED44DFF0026D13C788DA706B54F1E827DCC30F996AFAC667FF1D1E3C1DC1B55F6CC0B2073A6D41E42599ACFCD20F02D3D154061A5177BDB6BFEAA75C06A95D698445D7F505BA47F01BD72B24ECCB9B1B108D81A0BEB18C33E436B843EB192A818DDE810A9948B6F6BCCD49343A8F2694E328821A7C8F599F45E85D1A4576045605A1D01B8C776DAF53FA71E267E09AFE03A985D2C9AABA2ABCF4A008F51398135DF0D933342A61C38955F0AE1A9C22EE19058D32FEEC9C84BAB7F96C3A4F07FC45EB12E57BFD55E62969D1C2E8B97859F67910C64EEB6A5EB99AC7C45B63DAA33F5E927A815ED6B0E2628F7426C20CD39A1747E68EAB0203010001 -p 54859b342c49ea2a
 * b29776b4ae3e383c7e641fcca27ff6becf49bc48d36c8f0a0ec173bd7b5579360ea18788b92c90a6535ee9efc4e24dddf7a669823f56a47bfb62e0aeb8d304b3ac5a152ae3199b039a0b41da64ec0a69fcf21092f3c1bf847ffd2caec8b5f64170c547038af8ff6f3fd26f09b422f330bea985cb9c8df98feb3291a225848ff5dcc7069c2de5112c09098709a9f6337390f160f265dd30a566ce627bd0f82d3d198277e30a5f752f8eb1e5e891351b3b33b76692d1f28e6fe5750cad36fb4ed06661bd49fef41aa22b49fe034c74478d9a66b249464d77ea334d6b3cb4494ac67d3db5b9564115670f943c936527e0215d59c362d5a6da3826225e341c94af98
 *
 * Decryption command line:
 * $ ./kcapi -x 4 -o 1 -c "rsa" -k 3082021F02010102820100DB101AC2A3F1DCFF136BED44DFF0026D13C788DA706B54F1E827DCC30F996AFAC667FF1D1E3C1DC1B55F6CC0B2073A6D41E42599ACFCD20F02D3D154061A5177BDB6BFEAA75C06A95D698445D7F505BA47F01BD72B24ECCB9B1B108D81A0BEB18C33E436B843EB192A818DDE810A9948B6F6BCCD49343A8F2694E328821A7C8F599F45E85D1A4576045605A1D01B8C776DAF53FA71E267E09AFE03A985D2C9AABA2ABCF4A008F51398135DF0D933342A61C38955F0AE1A9C22EE19058D32FEEC9C84BAB7F96C3A4F07FC45EB12E57BFD55E62969D1C2E8B97859F67910C64EEB6A5EB99AC7C45B63DAA33F5E927A815ED6B0E2628F7426C20CD39A1747E68EAB0203010001028201005241F4DA7BB75955CAD42F0F3ACBA40D936CCC9DC1B2FBFDAE4031AC69522192B327DFEAEE2C82BBF74032D514C49412ECB81FCA59E3C178F385D847A5D7021A6579970D24F4F0676E752DBF103DA87DEF7F60E4E60582895DDFC6D26C0791339842F002002538C585698A7D2F956C439AB881E2D00735AA0541C91EAFE4043B19B873A2AC4B1E6648D8721FACF6CBBC9009CAEC0CDCF92CD7EBAEA3A447D7332F8ACABC5EF077E4979897C710917D2AA6FF468397DEE9E217030614E2D7B11D77AF51275B5E69B881E611C54323810462FFE946B8D844DBA5CC315434CE3E82D6BF7A0B64216D887E5B45121E638D49A71DD91E06CDE8BA2C8C6932EABE6071020100020100020100020100020100 -p b29776b4ae3e383c7e641fcca27ff6becf49bc48d36c8f0a0ec173bd7b5579360ea18788b92c90a6535ee9efc4e24dddf7a669823f56a47bfb62e0aeb8d304b3ac5a152ae3199b039a0b41da64ec0a69fcf21092f3c1bf847ffd2caec8b5f64170c547038af8ff6f3fd26f09b422f330bea985cb9c8df98feb3291a225848ff5dcc7069c2de5112c09098709a9f6337390f160f265dd30a566ce627bd0f82d3d198277e30a5f752f8eb1e5e891351b3b33b76692d1f28e6fe5750cad36fb4ed06661bd49fef41aa22b49fe034c74478d9a66b249464d77ea334d6b3cb4494ac67d3db5b9564115670f943c936527e0215d59c362d5a6da3826225e341c94af98
 * 54859b342c49ea2a
 *
 * ./kcapi -x 4 -o 2 -c "pkcs1pad(rsa-generic,sha256)" -k 308202200201100282010100d71e77828c9231e76902a2d55c78dea20c8ffe285931df409c606106b92f62408076cb674ab55956691707faf94cbd6c377a467d70a76722b34d7a94c3ba4b7c4ba9327cb738954564a405a89f127c4ec6c82d400630f460a691bb9bca0479111375f0aed35189c574b9aa3fb683e4786bcdf95c4c85ea523b5193fc146b335d3070fa501b1b3881138df7a50cc08ef96352184ea9f9f85c5dcd7a0dd48e7bee917bad7db492d5ab163b0a8ace8ede471a1701867bab99f14b0c3a0d8247c1918cbb2e229e49636e02c1c93a9ba5221b0795d6100250fdfdd19bbeabc2c074d7ec00fb1171cb7adc81799f86684663824db7f1e6166f4263f494a0ca33cc751302031000100282010062b560314f3f6616c160ac472aff6b69004ab25ce150b91874a8e4dca8eccd30bbc1c6e3c6ac202a3e5e8b12e6820809380bab7cb3cc9cce9767ddef95404e92e244e91dc114fda9b1dc719c4621bd58886e221556c1efe0c98de5803eda7e930f52f6f5c191909e42494f8d9cba3883e933c2504fecc2f0a8b76e2825566b6267fe08f156e56f0e99f1e5957befeb0a2c92975723333607ddfbaef1b1d833b796714236c5a4a9194b1b524c506991f00efa80374bb5d02fb7440dd4f8398dab71675905883deb484833884efef8271bd655605e48b76d9aa837f97ade1bcd5d1a30d4e99e5b3c15f89c1fdad1864855ce83ee8e51c7de3212477d46b835df41020130020130020130020130020130 -p 3ec8a12620544452480de566f3b3f504be10a84894222dddba7ab4768d799889
 * c7a398eb43d108c23d78450470c901eef885377c0bf919705c457b2f3a0bb78bc40d7b3a640b0fdb78a90bfd8d82a48639bf21b884c4ce9fc2e8b6614617b94e0b5705b44ff99c932d9bd5481d8012ef3a777fbcb58e2b6b7cfc9f8c9da2c485b087e9179bb62362d2a99f57e8f70445243a45ebeb6a088eafc8a084bc5d1338f5178ca3969ba9388df035ad328a725bdf21ab4b0ea829bb6154bf05db8484dedd163631daf3426d7a90229b1129a6f83061dad38b541e42d1471d6fd1cd420bd1e415857e08d659644c0134919226e8b0258cf8f4fa8bc931337672fb64929fda628de12a71914340613c5abe86fc5be6f9a916311faf256dc24a236e6302a2
 *
 */
#ifdef WITH_LIB_ASYM
static int cavs_asym(struct kcapi_cavs *cavs_test, uint32_t loops,
		     int splice)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	int maxsize = 0;
	ssize_t ret = -EINVAL;
	uint32_t i = 0;

	if (!cavs_test->ptlen)
		return -EINVAL;

	if (kcapi_akcipher_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		return -EFAULT;
	}

	/* Set key */
	if (cavs_test->keylen && cavs_test->key) {
		maxsize = kcapi_akcipher_setkey(handle, cavs_test->key,
						cavs_test->keylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set pivate key failed\n");
			goto out;
		}
	}
	if (cavs_test->pubkeylen && cavs_test->pubkey) {
		maxsize = kcapi_akcipher_setpubkey(handle, cavs_test->pubkey,
						   cavs_test->pubkeylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set public key failed\n");
			goto out;
		}
	}

	if (!maxsize) {
		printf("Zero output buffer size!\n");
		goto out;
	}

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, (size_t)maxsize))
			goto out;
		memset(outbuf, 0, (size_t)maxsize);
	} else {
		outbuf = calloc(1, (size_t)maxsize);
		if (!outbuf)
			goto out;
	}


	for (i = 0; i < loops; i++) {
		if (cavs_test->enc == 0) {
			ret = kcapi_akcipher_encrypt(handle,
					cavs_test->pt, cavs_test->ptlen,
					outbuf, (size_t)maxsize, splice);
		} else if (cavs_test->enc == 1) {
			ret = kcapi_akcipher_decrypt(handle,
					cavs_test->pt, cavs_test->ptlen,
					outbuf, (size_t)maxsize, splice);
		} else if (cavs_test->enc == 2) {
			ret = kcapi_akcipher_sign(handle,
					cavs_test->pt, cavs_test->ptlen,
					outbuf, (size_t)maxsize, splice);
		} else if (cavs_test->enc == 3) {
			ret = kcapi_akcipher_verify(handle,
					cavs_test->pt, cavs_test->ptlen,
					outbuf, (size_t)maxsize, splice);
		} else
			ret = -EINVAL;

		if (0 > ret && -EBADMSG != ret) {
			printf("Cipher operation of buffer failed: %zd\n", ret);
			goto out;
		}

		if (-EBADMSG == ret) {
			printf("EBADMSG\n");
		} else {
			char *outhex = NULL;

			outhex = calloc(1, (size_t)ret * 2 + 1);
			if (!outhex) {
				ret = -ENOMEM;
				goto out;
			}
			bin2hex(outbuf, (size_t)maxsize, outhex, (size_t)ret * 2 + 1, 0);
			printf("%s\n", outhex);
			free(outhex);
		}
	}

	ret = 0;

out:
	kcapi_akcipher_destroy(handle);
	if (outbuf)
		free(outbuf);
	return (int)ret;
}

static int cavs_asym_aio(struct kcapi_cavs *cavs_test, uint32_t loops,
			 int splice)
{
	struct kcapi_handle *handle = NULL;
	struct iovec *iniov_p, *outiov_p, *iniov = NULL, *outiov = NULL;
	uint8_t *outbuf = NULL;
	uint8_t *inbuf = NULL;
	int maxsize = 0;
	ssize_t ret = -ENOMEM;
	struct timespec begin, end;
	size_t i;

	if (!cavs_test->ptlen)
		return -EINVAL;

	iniov = calloc(loops, sizeof(struct iovec));
	if (!iniov)
		goto out;
	outiov = calloc(loops, sizeof(struct iovec));
	if (!outiov)
		goto out;

	if (kcapi_akcipher_init(&handle, cavs_test->cipher, KCAPI_INIT_AIO)) {
		printf("Allocation of %s cipher failed\n", cavs_test->cipher);
		goto out;
	}

	/* Set key */
	if (cavs_test->keylen && cavs_test->key) {
		maxsize = kcapi_akcipher_setkey(handle, cavs_test->key,
						cavs_test->keylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set pivate key failed\n");
			goto out;
		}
	}
	if (cavs_test->pubkeylen && cavs_test->pubkey) {
		maxsize = kcapi_akcipher_setpubkey(handle, cavs_test->pubkey,
						   cavs_test->pubkeylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set public key failed\n");
			goto out;
		}
	}

	if (!maxsize) {
		printf("Zero output buffer size!\n");
		goto out;
	}

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize,
				   (size_t)maxsize * loops))
			goto out;
		memset(outbuf, 0, (size_t)maxsize * loops);
		if (posix_memalign((void *)&inbuf, pagesize,
		    cavs_test->ptlen * loops))
			goto out;
		memset(outbuf, 0, cavs_test->ptlen * loops);
	} else {
		outbuf = calloc(loops, (size_t)maxsize);
		if (!outbuf)
			goto out;
		inbuf = calloc(loops, cavs_test->ptlen);
		if (!inbuf)
			goto out;
	}
	
	iniov_p = iniov;
	outiov_p = outiov;
	for (i = 0; i < loops; i++) {
		memcpy(inbuf + (i * cavs_test->ptlen), cavs_test->pt,
		       cavs_test->ptlen);
		iniov_p->iov_base = inbuf + (i * cavs_test->ptlen);
		iniov_p->iov_len = cavs_test->ptlen;
		iniov_p++;
		outiov_p->iov_base = outbuf + (i * (size_t)maxsize);
		outiov_p->iov_len = (size_t)maxsize;
		outiov_p++;
	}

	_get_time(&begin);
	if (cavs_test->enc == 0) {
		ret = kcapi_akcipher_encrypt_aio(handle, iniov, outiov,
						 loops, splice);
	} else if (cavs_test->enc == 1) {
		ret = kcapi_akcipher_decrypt_aio(handle, iniov,
						 outiov, loops, splice);
	} else if (cavs_test->enc == 2) {
		ret = kcapi_akcipher_sign_aio(handle, iniov, outiov,
					      loops, splice);
	} else if (cavs_test->enc == 3) {
		ret = kcapi_akcipher_verify_aio(handle, iniov, outiov,
						loops, splice);
	} else
		ret = -EINVAL;
	_get_time(&end);

	if (0 > ret && -EBADMSG != ret) {
		printf("Cipher operation of buffer failed: %zd\n", ret);
		goto out;
	}

	if (-EBADMSG == ret) {
		printf("EBADMSG\n");
	} else {
		for (i = 0; i < loops; i++) {
			/* ret returns the total number of returned bytes */
			bin2print(outbuf + (i * (size_t)maxsize),
				  (size_t)ret / loops);
			printf("\n");
		}
	}

	if (cavs_test->timing)
		printf("duration %lu\n", (unsigned long)_time_delta(&begin, &end));

	ret = 0;

out:
	kcapi_akcipher_destroy(handle);
	if (inbuf)
		free(inbuf);
	if (outbuf)
		free(outbuf);
	if (iniov)
		free(iniov);
	if (outiov)
		free(outiov);
	return (int)ret;
}

static int cavs_asym_stream(struct kcapi_cavs *cavs_test, uint32_t loops,
			    int splice)
{
	struct kcapi_handle *handle = NULL;
#define NUMIOVECS 16
#define OUTBUFBLOCKSIZE 5
	uint8_t *outbuf = NULL;
	int maxsize = 0;
	uint8_t *inbuf = NULL;
	size_t inbuflen = 1024 * NUMIOVECS;
	size_t index = 0;
	size_t numiovecs = 0;
	ssize_t ret = -EINVAL;
	struct iovec iniov[NUMIOVECS];
	struct iovec outiov[NUMIOVECS];
	size_t i = 0;
	size_t inputiovlen = NUMIOVECS;

	if (!cavs_test->ptlen)
		return -EINVAL;

	if (kcapi_akcipher_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of cipher failed\n");
		return -EFAULT;
	}

	/* Set key */
	if (cavs_test->keylen && cavs_test->key) {
		maxsize = kcapi_akcipher_setkey(handle, cavs_test->key,
						cavs_test->keylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set pivate key failed\n");
			goto out;
		}
	}
	if (cavs_test->pubkeylen && cavs_test->pubkey) {
		maxsize = kcapi_akcipher_setpubkey(handle, cavs_test->pubkey,
						   cavs_test->pubkeylen);
		if (maxsize <= 0) {
			printf("Asymmetric cipher set public key failed\n");
			goto out;
		}
	}

	if (!maxsize) {
		printf("Zero output buffer size!\n");
		goto out;
	}

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize,
				   (size_t)maxsize * NUMIOVECS))
			goto out;
		memset(outbuf, 0, (size_t)maxsize);
		if (posix_memalign((void *)&inbuf, pagesize, inbuflen))
			goto out;
		memset(inbuf, 0, inbuflen);
	} else {
		outbuf = calloc(1, (size_t)maxsize * NUMIOVECS);
		if (!outbuf)
			goto out;
		inbuf = calloc(1, inbuflen);
		if (!inbuf)
			goto out;
	}

	if (cavs_test->enc == 0)
		ret = kcapi_akcipher_stream_init_enc(handle, NULL, 0);
	else if (cavs_test->enc == 1)
		ret = kcapi_akcipher_stream_init_dec(handle, NULL, 0);
	else if (cavs_test->enc == 2)
		ret = kcapi_akcipher_stream_init_sgn(handle, NULL, 0);
	else if (cavs_test->enc == 3)
		ret = kcapi_akcipher_stream_init_vfy(handle, NULL, 0);
	else {
		printf("Wrong cipher type\n");
		goto out;
	}
	if (0 > ret) {
		printf("Initialization of cipher buffer failed: %zd\n", ret);
		goto out;
	}

	/* 
	 * This check is aligned with the branch in
	 * kcapi_akcipher_stream_update[|_last].
	 */
	if (splice)
		inputiovlen = (inputiovlen > 15) ? 15 : inputiovlen;

	/* fill scatter lists */
	for (i = 0; i < inputiovlen; i++) {
		uint8_t *inbuf_working = inbuf + (i * 1024);
		/* copy one byte of input into each iovec */
		size_t size = 1;

		if (((i + 1) * size) > cavs_test->ptlen)
			break;
		/* last iovec gets rest */
		if (i == (inputiovlen - 1))
			size = cavs_test->ptlen - (i * size);

		memcpy(inbuf_working, cavs_test->pt + index, size);
		index += size;
		iniov[i].iov_base = inbuf_working;
		iniov[i].iov_len = size;
		numiovecs++;
	}

	for (i = 0; i < NUMIOVECS; i++) {
		uint8_t *outbuf_working = outbuf + (i * (size_t)maxsize);
		/* use some bytes in each iovec for output */
		size_t outsize = OUTBUFBLOCKSIZE;

		/* last iovec gets rest */
		if (i == (NUMIOVECS - 1))
			outsize = ((size_t)maxsize) - (i * outsize);

		outiov[i].iov_base = outbuf_working;
		outiov[i].iov_len = outsize;
	}

	for (i = 0; i < loops; i++) {
		ret = kcapi_akcipher_stream_update_last(handle, iniov, numiovecs);
		if (ret < 0) {
			printf("asym update failed\n");
			goto out;
		}

		ret = kcapi_akcipher_stream_op(handle, outiov, NUMIOVECS);

		if (0 > ret && -EBADMSG != ret) {
			printf("Cipher operation of buffer failed: %zd\n", ret);
			goto out;
		}

		if (-EBADMSG == ret) {
			printf("EBADMSG\n");
		} else {
			size_t j = 0;
			/* use some bytes in each iovec for output */
			size_t outsize = OUTBUFBLOCKSIZE;
			char *outhex = NULL;
			size_t processed = 0;

			outhex = calloc(1, (size_t)ret * 2 + 1);
			if (!outhex) {
				ret = -ENOMEM;
				goto out;
			}

			for (j = 0; j < NUMIOVECS; j++) {
				if (j * OUTBUFBLOCKSIZE > (uint32_t)ret)
					break;

				if (((size_t)ret - (j * outsize)) < outsize)
					outsize = (size_t)ret - (j * outsize);

				/* last IOVEC has remaineder */
				if (j == (NUMIOVECS - 1))
					outsize = (size_t)ret - processed;

				bin2hex(outbuf + (j * (size_t)maxsize), outsize,
					outhex + (2 * j * OUTBUFBLOCKSIZE),
					(size_t)ret * 2 + 1 - (processed * 2), 0);
				processed += outsize;
			}
			printf("%s\n", outhex);
			free(outhex);
		}
	}

	ret = 0;

out:
	kcapi_aead_destroy(handle);
	if (outbuf)
		free(outbuf);
	if (inbuf)
		free(inbuf);
	return (int)ret;
}

#else /* WITH_LIB_ASYM */
static int cavs_asym(struct kcapi_cavs *cavs_test, uint32_t loops,
		     int splice)
{
	(void)cavs_test;
	(void)loops;
	(void)splice;

	fprintf(stderr, "Asymmetric support not implemented\n");

	return -EOPNOTSUPP;
}

static int cavs_asym_aio(struct kcapi_cavs *cavs_test, uint32_t loops,
			 int splice)
{
	(void)cavs_test;
	(void)loops;
	(void)splice;

	fprintf(stderr, "Asymmetric support not implemented\n");

	return -EOPNOTSUPP;
}

static int cavs_asym_stream(struct kcapi_cavs *cavs_test, uint32_t loops,
			    int splice)
{
	(void)cavs_test;
	(void)loops;
	(void)splice;

	fprintf(stderr, "Asymmetric support not implemented\n");

	return -EOPNOTSUPP;
}

#endif /* WITH_LIB_ASYM */
/*
 * KDF
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/CounterMode.zip
 * ./kcapi -x 5 -c "hmac(sha256)" -k dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0 -p 01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b864a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac -b 16
 * 10621342bfb0fd40046c0e29f2cfdbf0
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/FeedbackModeNOzeroiv.zip
 * ./kcapi -x 6 -c "hmac(sha256)" -k 93f698e842eed75394d629d957e2e89c6e741f810b623c8b901e38376d068e7b -p 9f575d9059d3e0c0803f08112f8a806de3c3471912cdf42b095388b14b33508e53b89c18690e2057a1d167822e636de50be0018532c431f7f5e37f77139220d5e042599ebe266af5767ee18cd2c5c19a1f0f80 -b 64
 * bd1476f43a4e315747cf5918e0ea5bc0d98769457477c3ab18b742def0e079a933b756365afb5541f253fee43c6fd788a44041038509e9eeb68f7d65ffbb5f95
 *
 * http://csrc.nist.gov/groups/STM/cavp/documents/KBKDF800-108/PipelineModewithCounter.zip
 * ./kcapi -x 7 -c "hmac(sha256)" -k 02d36fa021c20ddbdee469f0579468bae5cb13b548b6c61cdf9d3ec419111de2 -b 64 -p 85abe38bf265fbdc6445ae5c71159f1548c73b7d526a623104904a0f8792070b3df9902b9669490425a385eadb0f9c76e46f0f
 * d69f74f518c9f64f90a0beebab69f689b73b5c13eb0f860a95cad7d9814f8c506eb7b179a5c5b4466a9ec154c3bf1c13efd6ec0d82b02c29af2c690299edc453
 */
static int cavs_kdf_common(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	char *mdhex = NULL;
	size_t mdhexlen = cavs_test->outlen * 2 + 1;
	ssize_t ret = 1;
	size_t i = 0;

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, cavs_test->outlen))
			return -ENOMEM;
		memset(outbuf, 0, cavs_test->outlen);
	} else {
		outbuf = calloc(1, cavs_test->outlen);
		if (!outbuf)
			return -ENOMEM;
	}
	mdhex = calloc(1, mdhexlen);
	if (!mdhex) {
		ret = -ENOMEM;
		goto out;
	}

	if (kcapi_md_init(&handle, cavs_test->cipher, 0)) {
		printf("Allocation of KDF hash %s failed\n", cavs_test->cipher);
		goto out;
	}
	/* HMAC */
	if (cavs_test->keylen) {
		if (kcapi_md_setkey(handle, cavs_test->key,
				    cavs_test->keylen)) {
			printf("KDF HMAC setkey failed\n");
			goto out;
		}
	}

	for (i = 0; i < loops; i++) {
		if (cavs_test->type == KDF_CTR)
			ret = kcapi_kdf_ctr(handle, cavs_test->pt,
					    cavs_test->ptlen,
					    outbuf, cavs_test->outlen);
		else if (cavs_test->type == KDF_FB)
			ret = kcapi_kdf_fb(handle, cavs_test->pt,
					   cavs_test->ptlen,
					   outbuf, cavs_test->outlen);
		else if (cavs_test->type == KDF_DPI)
			ret = kcapi_kdf_dpi(handle, cavs_test->pt,
					    cavs_test->ptlen,
					    outbuf, cavs_test->outlen);
		else
			ret = -EOPNOTSUPP;
		if (0 > ret) {
			printf("KDF generation failed\n");
			goto out;
		}
		bin2hex(outbuf, cavs_test->outlen, mdhex, mdhexlen, 0);
		printf("%s\n", mdhex);
	}

	ret = 0;

out:
	kcapi_md_destroy(handle);
	if (outbuf)
		free(outbuf);
	if (mdhex)
		free(mdhex);

	return (int)ret;
}

/*
 * RFC5869
 * ./kcapi -x 12 -c "hmac(sha256)" -k 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -i 000102030405060708090a0b0c -p f0f1f2f3f4f5f6f7f8f9 -b 42
 * 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
 */
static int cavs_hkdf(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	uint8_t *outbuf = NULL;
	char *mdhex = NULL;
	size_t mdhexlen = cavs_test->outlen * 2 + 1;
	ssize_t ret = 1;

	if (!loops) {
		printf("PBKDF suggested iteration count: %u\n",
		       kcapi_pbkdf_iteration_count(cavs_test->cipher, 0));
		return 0;
	}

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, cavs_test->outlen))
			return -ENOMEM;
		memset(outbuf, 0, cavs_test->outlen);
	} else {
		outbuf = calloc(1, cavs_test->outlen);
		if (!outbuf)
			return -ENOMEM;
	}
	mdhex = calloc(1, mdhexlen);
	if (!mdhex) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kcapi_hkdf(cavs_test->cipher,
			 cavs_test->key, cavs_test->keylen,
			 cavs_test->iv, cavs_test->ivlen,
			 cavs_test->pt, cavs_test->ptlen,
			 outbuf, cavs_test->outlen);
	if (0 > ret) {
		printf("KDF generation failed\n");
		goto out;
	}
	bin2hex(outbuf, cavs_test->outlen, mdhex, mdhexlen, 0);
	printf("%s\n", mdhex);

	ret = 0;

out:
	if (outbuf)
		free(outbuf);
	if (mdhex)
		free(mdhex);

	return (int)ret;
}
/*
 * Test vectors taken from RFC6070
 *
 * String "password" is 70617373776f7264 in hex
 * String "salt" is 73616c74 in hex
 *
 * $ ./kcapi -x 8 -c "hmac(sha1)" -k 73616c74 -p 70617373776f7264 -d 1 -b 20
 * 0c60c80f961f0e71f3a9b524af6012062fe037a6
 *
 * ./kcapi -x 8 -c "hmac(sha1)" -k 73616c74 -p 70617373776f7264 -d 2 -b 20
 * ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
 *
 * ./kcapi -x 8 -c "hmac(sha1)" -k 73616c74 -p 70617373776f7264 -d 4096 -b 20
 * 4b007901b765489abead49d926f721d065a429c1
 *
 * ./kcapi -x 8 -c "hmac(sha1)" -k 73616c74 -p 70617373776f7264 -d 16777216 -b 20 
 * eefe3d61cd4da4e4e9945b3d6ba2158c2634e984
 *
 * ./kcapi -x 8 -c "hmac(sha1)" -k 73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74 -p 70617373776f726450415353574f524470617373776f7264 -d 4096 -b 25
 * 3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038
 *
 * ./kcapi -x 8 -c "hmac(sha1)" -k 7361006c74 -p 7061737300776f7264 -d 4096 -b 16
 * 56fa6aa75548099dcc37d7f03425e0c3
 *
 *
 * Test vector from libgcrypt (tests/t-kdf.c):
 * ./kcapi -x 8 -c "hmac(sha1)" -k 73616c74 -p "" -d 2 -b 20
 * 133a4ce837b4d2521ee2bf03e11c71ca794e0797
 *
 *
 * Private test vectors:
 * ./kcapi -x 8 -c "hmac(sha256)" -k 73616c74 -p 70617373776f7264 -d 4096 -b 20
 * c5e478d59288c841aa530db6845c4c8d962893a0
 *
 * ./kcapi -x 8 -c "hmac(sha224)" -k 73616c74 -p 70617373776f7264 -d 4096 -b 20
 * 218c453bf90635bd0a21a75d172703ff6108ef60
 *
 * ./kcapi -x 8 -c "hmac(sha384)" -k 73616c74 -p 70617373776f7264 -d 4096 -b 20
 * 559726be38db125bc85ed7895f6e3cf574c7a01c
 *
 * ./kcapi -x 8 -c "hmac(sha512)" -k 73616c74 -p 70617373776f7264 -d 4096 -b 20
 * d197b1b33db0143e018b12f3d1d1479e6cdebdcc
 *
 * Note, cmac(aes) requires AES keys (128, 192, or 256 bits in size) and will
 * cause an error otherwise. That means, the password must be exactly the
 * length of an AES key.
 * ./kcapi -x 8 -c "cmac(aes)" -k 73616c74 -p 70617373776f726470617373776f7264 -d 4096 -b 20
 * c4c112c6e1e3b8757640603dec78825ff87605a7
 */
static int cavs_pbkdf(struct kcapi_cavs *cavs_test, uint32_t loops)
{
	uint8_t *outbuf = NULL;
	char *mdhex = NULL;
	size_t mdhexlen = cavs_test->outlen * 2 + 1;
	ssize_t ret = 1;

	if (!loops) {
		printf("PBKDF suggested iteration count: %u\n",
		       kcapi_pbkdf_iteration_count(cavs_test->cipher, 0));
		return 0;
	}

	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, cavs_test->outlen))
			return -ENOMEM;
		memset(outbuf, 0, cavs_test->outlen);
	} else {
		outbuf = calloc(1, cavs_test->outlen);
		if (!outbuf)
			return -ENOMEM;
	}
	mdhex = calloc(1, mdhexlen);
	if (!mdhex) {
		ret = -ENOMEM;
		goto out;
	}

	ret = kcapi_pbkdf(cavs_test->cipher,
			  cavs_test->pt, (uint32_t)cavs_test->ptlen,
			  cavs_test->key, cavs_test->keylen,
			  loops,
			  outbuf, cavs_test->outlen);
	if (0 > ret) {
		printf("KDF generation failed\n");
		goto out;
	}
	bin2hex(outbuf, cavs_test->outlen, mdhex, mdhexlen, 0);
	printf("%s\n", mdhex);

	ret = 0;

out:
	if (outbuf)
		free(outbuf);
	if (mdhex)
		free(mdhex);

	return (int)ret;
}

/*
 * Public key generation where private key stays in kernel attached to TFM:
 * kcapi -x 13 -c "ecdh" -l 2
 *
 * Public key generation from given private key -- Verification of kernel
 * with openssl
 * ----------------------------------------------------------------------
 *
 * 1. Generate parameter set (use this in hex for as IV for kcapi-main)
 *    openssl dhparam -outform DER -out dhparam.der 2048
 * 2. Convert DER into PEM format (openssl genpkey only works with PEM)
 *    openssl dhparam -inform DER -in dhparam.der -outform PEM -out dhparam.pem
 * 3. Generate private and public key
 *    openssl genpkey -paramfile dhparam.pem -out dhkey1.pem
 *    openssl pkey -in dhkey1.pem -text -noout
 * 4. Use private key from step 3 for -k parameter of kcapi-main
 * 5. Verify that kcapi-main returns the same public key as in step 3.
 * (in case of leading zeros, openssl pkey prints them whereas this app does
 * not)
 *
 * Example test run verified with OpenSSL:
 *
$ openssl pkey -in dhkey1.pem -text -noout
DH Private-Key: (2048 bit)
    private-key:
        53:7d:f8:4c:6c:e2:23:48:6c:bd:da:3a:ef:2b:81:
        9a:57:a7:4b:fc:ab:09:c6:3d:1c:a1:43:27:b3:27:
        e8:d5:d7:64:21:74:f4:11:08:22:87:8e:b2:ee:dd:
        6d:37:8e:ff:3b:1a:d2:7e:91:97:bc:1a:d8:a0:8b:
        f6:f2:8f:5b:4b:5f:8e:03:f7:33:21:f7:85:0f:10:
        7f:68:e5:ad:3b:ad:97:e4:4e:79:7a:79:89:5b:e9:
        bc:f9:15:86:db:e9:ae:b4:70:96:c8:21:35:d8:7c:
        cb:d5:aa:d1:95:7f:bf:9d:91:70:01:40:84:9d:c5:
        11:6f:91:bd:02:de:01:10:5b:61:bc:ab:d6:8c:55:
        fa:31:7b:6d:d2:4b:8c:c9:79:41:7c:a4:80:a5:c2:
        17:09:c4:32:a0:b9:b4:54:9a:78:fb:f0:38:cf:d9:
        67:b1:03:4d:68:97:bc:1a:37:c5:c5:70:3d:15:2a:
        e6:f6:b9:2c:f9:9c:4c:b4:b2:77:a4:23:f0:b2:63:
        f4:ed:64:ce:8a:c7:d2:62:8d:5c:d5:ae:24:a0:3d:
        3a:5e:10:37:eb:dd:24:2f:b9:95:3a:d2:b6:a3:da:
        4b:20:95:40:01:61:a4:d2:0c:5e:b9:9b:d6:71:08:
        70:04:e7:0e:bd:7b:83:5b:56:c6:a4:c7:cf:3a:54:
        44
    public-key:
        00:ab:3b:f8:9a:2c:17:5b:34:76:2a:84:76:ca:fa:
        d3:61:b6:77:b0:02:5c:aa:77:38:c6:81:6f:8e:1a:
        f2:84:13:4e:f8:6c:e9:e3:7b:f7:59:c9:11:e6:ae:
        f3:08:5e:84:85:9b:0d:07:ef:5f:cd:81:c4:f4:24:
        eb:b4:58:ea:96:89:b5:8d:b5:75:06:eb:2e:93:f0:
        f0:93:05:f3:3e:01:d6:f0:f3:fd:2d:15:e0:59:f4:
        88:36:56:6b:a3:40:aa:24:5b:11:36:9a:5f:bd:a2:
        1c:d6:bc:e3:2d:00:b3:8c:09:f0:ba:b8:9b:0d:5b:
        a9:94:1b:c0:11:c2:ed:48:df:ad:a5:42:fe:a7:6b:
        6a:dd:5e:fc:7d:08:96:c9:e2:7d:0c:03:d8:88:2b:
        ee:e5:42:82:03:4c:75:cf:7a:3c:5a:ba:2d:1e:8c:
        0e:e1:c8:47:2c:07:52:da:2b:b8:69:d1:8d:dd:f1:
        a3:42:ea:e8:1f:03:54:a7:f8:97:3b:fb:6d:53:04:
        a0:f6:b5:25:6f:70:b8:4d:8c:21:e6:80:c3:8d:3f:
        2f:e9:0d:a7:48:99:d8:97:ae:13:c3:7e:4f:1e:fc:
        67:15:3b:46:ce:fd:0d:7e:da:da:ac:1f:84:a7:d0:
        43:27:95:27:95:6b:5a:e6:4c:ef:c0:0f:9e:48:a4:
        a8:3a
    prime:
        00:e0:ea:4b:21:b7:6a:07:61:f6:d5:5d:db:c8:c5:
        10:8a:3e:73:f1:58:0c:29:ba:41:9b:6b:aa:4a:91:
        30:cc:17:d8:d9:45:dd:1c:c9:2c:9a:0a:69:0f:e5:
        2a:18:4d:20:21:dc:03:9e:6a:9d:54:e1:5a:4f:c0:
        40:d5:db:39:2e:6b:ca:d7:92:6e:b3:84:79:3c:b2:
        53:a7:6d:25:0b:6c:cc:d5:52:3c:a7:5c:85:94:2c:
        2a:55:02:be:36:c1:13:f9:af:d9:73:99:c5:ba:6d:
        8c:c4:a4:07:ee:e8:2b:f7:b9:d7:6a:7b:a6:a2:56:
        0f:f1:7f:4f:bd:b2:86:1a:5d:44:01:e1:84:81:77:
        ae:ae:5f:a9:3e:cb:1b:1a:d8:88:0c:85:e0:59:f8:
        ea:39:09:ab:7f:23:f7:60:61:29:e5:52:80:e8:cc:
        53:74:1a:64:65:39:9f:d6:e9:3b:ff:68:d5:2d:71:
        51:38:11:1d:94:43:24:62:14:08:34:16:2f:1a:5e:
        3c:d2:30:cc:f8:2e:2c:2d:f6:28:65:d1:75:3b:f8:
        30:01:ab:b2:26:0d:2a:d4:57:44:1b:aa:bc:02:3d:
        91:41:36:68:a2:a3:60:3c:6e:d7:75:d1:5c:9d:9e:
        cb:36:fb:d2:85:c1:ae:c0:3f:b9:67:3a:f9:b9:33:
        c4:53
    generator: 2 (0x2)

 * Invocation of same parameters with kernel crypto API:
 *
 * kcapi -x 13 -c "dh" -i 308201080282010100e0ea4b21b76a0761f6d55ddbc8c5108a3e73f1580c29ba419b6baa4a9130cc17d8d945dd1cc92c9a0a690fe52a184d2021dc039e6a9d54e15a4fc040d5db392e6bcad7926eb384793cb253a76d250b6cccd5523ca75c85942c2a5502be36c113f9afd97399c5ba6d8cc4a407eee82bf7b9d76a7ba6a2560ff17f4fbdb2861a5d4401e1848177aeae5fa93ecb1b1ad8880c85e059f8ea3909ab7f23f7606129e55280e8cc53741a6465399fd6e93bff68d52d715138111d94432462140834162f1a5e3cd230ccf82e2c2df62865d1753bf83001abb2260d2ad457441baabc023d91413668a2a3603c6ed775d15c9d9ecb36fbd285c1aec03fb9673af9b933c453020102 -k 537df84c6ce223486cbdda3aef2b819a57a74bfcab09c63d1ca14327b327e8d5d7642174f4110822878eb2eedd6d378eff3b1ad27e9197bc1ad8a08bf6f28f5b4b5f8e03f73321f7850f107f68e5ad3bad97e44e797a79895be9bcf91586dbe9aeb47096c82135d87ccbd5aad1957fbf9d91700140849dc5116f91bd02de01105b61bcabd68c55fa317b6dd24b8cc979417ca480a5c21709c432a0b9b4549a78fbf038cfd967b1034d6897bc1a37c5c5703d152ae6f6b92cf99c4cb4b277a423f0b263f4ed64ce8ac7d2628d5cd5ae24a03d3a5e1037ebdd242fb9953ad2b6a3da4b2095400161a4d20c5eb99bd671087004e70ebd7b835b56c6a4c7cf3a5444
ab3bf89a2c175b34762a8476cafad361b677b0025caa7738c6816f8e1af284134ef86ce9e37bf759c911e6aef3085e84859b0d07ef5fcd81c4f424ebb458ea9689b58db57506eb2e93f0f09305f33e01d6f0f3fd2d15e059f48836566ba340aa245b11369a5fbda21cd6bce32d00b38c09f0bab89b0d5ba9941bc011c2ed48dfada542fea76b6add5efc7d0896c9e27d0c03d8882beee54282034c75cf7a3c5aba2d1e8c0ee1c8472c0752da2bb869d18dddf1a342eae81f0354a7f8973bfb6d5304a0f6b5256f70b84d8c21e680c38d3f2fe90da74899d897ae13c37e4f1efc67153b46cefd0d7edadaac1f84a7d043279527956b5ae64cefc00f9e48a4a83a
 *
 * --> public key from OpenSSL matches result of key generation
 *
 * Generation of shared secret -- verification with OpenSSL
 * --------------------------------------------------------
 *
 * Prerequisite: OpenSSL generated data for key gen.
 *
 * Note: Example derives shared secret from public/private key pair of
 * *one* key (not two) -- the purpose is to demonstrate the correctness of
 * the kernel implementation.
 *
 * 1. Extract public key from priv/pub key combo
 *    openssl pkey -in dhkey1.pem -pubout -out dhpub1.pem
 * 2. Generate shared secret
 *    openssl pkeyutl -derive -inkey dhkey1.pem -peerkey dhpub1.pem -out secret.bin
 * 3. Use same private key from above for -k and public key for -p and verify
 *    that result matches secret.bin
 *
 * Example test run verified with OpenSSL:
 *
$ $ openssl pkey -pubin -in dhpub1.pem -text
-----BEGIN PUBLIC KEY-----
MIICJTCCARcGCSqGSIb3DQEDATCCAQgCggEBAODqSyG3agdh9tVd28jFEIo+c/FY
DCm6QZtrqkqRMMwX2NlF3RzJLJoKaQ/lKhhNICHcA55qnVThWk/AQNXbOS5ryteS
brOEeTyyU6dtJQtszNVSPKdchZQsKlUCvjbBE/mv2XOZxbptjMSkB+7oK/e512p7
pqJWD/F/T72yhhpdRAHhhIF3rq5fqT7LGxrYiAyF4Fn46jkJq38j92BhKeVSgOjM
U3QaZGU5n9bpO/9o1S1xUTgRHZRDJGIUCDQWLxpePNIwzPguLC32KGXRdTv4MAGr
siYNKtRXRBuqvAI9kUE2aKKjYDxu13XRXJ2eyzb70oXBrsA/uWc6+bkzxFMCAQID
ggEGAAKCAQEAqzv4miwXWzR2KoR2yvrTYbZ3sAJcqnc4xoFvjhryhBNO+Gzp43v3
WckR5q7zCF6EhZsNB+9fzYHE9CTrtFjqlom1jbV1Busuk/DwkwXzPgHW8PP9LRXg
WfSINlZro0CqJFsRNppfvaIc1rzjLQCzjAnwuribDVuplBvAEcLtSN+tpUL+p2tq
3V78fQiWyeJ9DAPYiCvu5UKCA0x1z3o8WrotHowO4chHLAdS2iu4adGN3fGjQuro
HwNUp/iXO/ttUwSg9rUlb3C4TYwh5oDDjT8v6Q2nSJnYl64Tw35PHvxnFTtGzv0N
ftrarB+Ep9BDJ5UnlWta5kzvwA+eSKSoOg==
-----END PUBLIC KEY-----
DH Public-Key: (2048 bit)
    public-key:
        00:ab:3b:f8:9a:2c:17:5b:34:76:2a:84:76:ca:fa:
        d3:61:b6:77:b0:02:5c:aa:77:38:c6:81:6f:8e:1a:
        f2:84:13:4e:f8:6c:e9:e3:7b:f7:59:c9:11:e6:ae:
        f3:08:5e:84:85:9b:0d:07:ef:5f:cd:81:c4:f4:24:
        eb:b4:58:ea:96:89:b5:8d:b5:75:06:eb:2e:93:f0:
        f0:93:05:f3:3e:01:d6:f0:f3:fd:2d:15:e0:59:f4:
        88:36:56:6b:a3:40:aa:24:5b:11:36:9a:5f:bd:a2:
        1c:d6:bc:e3:2d:00:b3:8c:09:f0:ba:b8:9b:0d:5b:
        a9:94:1b:c0:11:c2:ed:48:df:ad:a5:42:fe:a7:6b:
        6a:dd:5e:fc:7d:08:96:c9:e2:7d:0c:03:d8:88:2b:
        ee:e5:42:82:03:4c:75:cf:7a:3c:5a:ba:2d:1e:8c:
        0e:e1:c8:47:2c:07:52:da:2b:b8:69:d1:8d:dd:f1:
        a3:42:ea:e8:1f:03:54:a7:f8:97:3b:fb:6d:53:04:
        a0:f6:b5:25:6f:70:b8:4d:8c:21:e6:80:c3:8d:3f:
        2f:e9:0d:a7:48:99:d8:97:ae:13:c3:7e:4f:1e:fc:
        67:15:3b:46:ce:fd:0d:7e:da:da:ac:1f:84:a7:d0:
        43:27:95:27:95:6b:5a:e6:4c:ef:c0:0f:9e:48:a4:
        a8:3a
    prime:
        00:e0:ea:4b:21:b7:6a:07:61:f6:d5:5d:db:c8:c5:
        10:8a:3e:73:f1:58:0c:29:ba:41:9b:6b:aa:4a:91:
        30:cc:17:d8:d9:45:dd:1c:c9:2c:9a:0a:69:0f:e5:
        2a:18:4d:20:21:dc:03:9e:6a:9d:54:e1:5a:4f:c0:
        40:d5:db:39:2e:6b:ca:d7:92:6e:b3:84:79:3c:b2:
        53:a7:6d:25:0b:6c:cc:d5:52:3c:a7:5c:85:94:2c:
        2a:55:02:be:36:c1:13:f9:af:d9:73:99:c5:ba:6d:
        8c:c4:a4:07:ee:e8:2b:f7:b9:d7:6a:7b:a6:a2:56:
        0f:f1:7f:4f:bd:b2:86:1a:5d:44:01:e1:84:81:77:
        ae:ae:5f:a9:3e:cb:1b:1a:d8:88:0c:85:e0:59:f8:
        ea:39:09:ab:7f:23:f7:60:61:29:e5:52:80:e8:cc:
        53:74:1a:64:65:39:9f:d6:e9:3b:ff:68:d5:2d:71:
        51:38:11:1d:94:43:24:62:14:08:34:16:2f:1a:5e:
        3c:d2:30:cc:f8:2e:2c:2d:f6:28:65:d1:75:3b:f8:
        30:01:ab:b2:26:0d:2a:d4:57:44:1b:aa:bc:02:3d:
        91:41:36:68:a2:a3:60:3c:6e:d7:75:d1:5c:9d:9e:
        cb:36:fb:d2:85:c1:ae:c0:3f:b9:67:3a:f9:b9:33:
        c4:53
    generator: 2 (0x2)

$ openssl pkeyutl -derive -inkey dhkey1.pem -peerkey dhpub1.pem -out secret.bin
$ bin2hex.pl secret.bin /dev/stdout
78fbd4d1ed7ea6fc8f1e1a6f8a5c750845401589ad3c135088b4ec78f54c57b436d1a7a25ef3f807f72b71387f6f3624b008024fa655cf902daf11e487181ab0f59aa46ff5d0ea41574a524cc07d6d8510dcef4d550718b042fb140fb166ade62669305380377f3958f0d91c81deda0c9c5fddea4f8dd4792629407dfc2c45622099a5fa4facd78adea5c4dc32daff9fc37e3b0248576376d2e5884a7b0f7af8d7a1d308dbcbf95fee99cc336be9e5dd9ea3874806a1b3fb390a737caf37dc884f6c0a61d3ab5a420ecb9ca34069a36264cb418d4d4520ba12170b849762f6bc2f31cbfbfe6eadac3c3739daa49d2a96fd76b553e7e1198837df41c59f9b7f54
 *
 * Invocation of same parameters with kernel crypto API:
 *
 * kcapi -x 13 -c "dh" -i 308201080282010100e0ea4b21b76a0761f6d55ddbc8c5108a3e73f1580c29ba419b6baa4a9130cc17d8d945dd1cc92c9a0a690fe52a184d2021dc039e6a9d54e15a4fc040d5db392e6bcad7926eb384793cb253a76d250b6cccd5523ca75c85942c2a5502be36c113f9afd97399c5ba6d8cc4a407eee82bf7b9d76a7ba6a2560ff17f4fbdb2861a5d4401e1848177aeae5fa93ecb1b1ad8880c85e059f8ea3909ab7f23f7606129e55280e8cc53741a6465399fd6e93bff68d52d715138111d94432462140834162f1a5e3cd230ccf82e2c2df62865d1753bf83001abb2260d2ad457441baabc023d91413668a2a3603c6ed775d15c9d9ecb36fbd285c1aec03fb9673af9b933c453020102 -k 537df84c6ce223486cbdda3aef2b819a57a74bfcab09c63d1ca14327b327e8d5d7642174f4110822878eb2eedd6d378eff3b1ad27e9197bc1ad8a08bf6f28f5b4b5f8e03f73321f7850f107f68e5ad3bad97e44e797a79895be9bcf91586dbe9aeb47096c82135d87ccbd5aad1957fbf9d91700140849dc5116f91bd02de01105b61bcabd68c55fa317b6dd24b8cc979417ca480a5c21709c432a0b9b4549a78fbf038cfd967b1034d6897bc1a37c5c5703d152ae6f6b92cf99c4cb4b277a423f0b263f4ed64ce8ac7d2628d5cd5ae24a03d3a5e1037ebdd242fb9953ad2b6a3da4b2095400161a4d20c5eb99bd671087004e70ebd7b835b56c6a4c7cf3a5444 -p 00ab3bf89a2c175b34762a8476cafad361b677b0025caa7738c6816f8e1af284134ef86ce9e37bf759c911e6aef3085e84859b0d07ef5fcd81c4f424ebb458ea9689b58db57506eb2e93f0f09305f33e01d6f0f3fd2d15e059f48836566ba340aa245b11369a5fbda21cd6bce32d00b38c09f0bab89b0d5ba9941bc011c2ed48dfada542fea76b6add5efc7d0896c9e27d0c03d8882beee54282034c75cf7a3c5aba2d1e8c0ee1c8472c0752da2bb869d18dddf1a342eae81f0354a7f8973bfb6d5304a0f6b5256f70b84d8c21e680c38d3f2fe90da74899d897ae13c37e4f1efc67153b46cefd0d7edadaac1f84a7d043279527956b5ae64cefc00f9e48a4a83a
78fbd4d1ed7ea6fc8f1e1a6f8a5c750845401589ad3c135088b4ec78f54c57b436d1a7a25ef3f807f72b71387f6f3624b008024fa655cf902daf11e487181ab0f59aa46ff5d0ea41574a524cc07d6d8510dcef4d550718b042fb140fb166ade62669305380377f3958f0d91c81deda0c9c5fddea4f8dd4792629407dfc2c45622099a5fa4facd78adea5c4dc32daff9fc37e3b0248576376d2e5884a7b0f7af8d7a1d308dbcbf95fee99cc336be9e5dd9ea3874806a1b3fb390a737caf37dc884f6c0a61d3ab5a420ecb9ca34069a36264cb418d4d4520ba12170b849762f6bc2f31cbfbfe6eadac3c3739daa49d2a96fd76b553e7e1198837df41c59f9b7f54

 * --> shared secret from OpenSSL matches result of kernel
 */
#ifdef WITH_LIB_KPP
static int kpp(struct kcapi_cavs *cavs_test, uint32_t loops, int splice)
{
	struct kcapi_handle *handle = NULL;
	uint8_t *outbuf = NULL;
	size_t outbuflen;
	ssize_t ret;

	(void)loops;

	if (!cavs_test->ivlen && !cavs_test->taglen)
		return -EINVAL;

	if (kcapi_kpp_init(&handle, cavs_test->cipher, 0)) {
		ret = -EINVAL;
		printf("Allocation of cipher failed\n");
		goto out;
	}

	if (cavs_test->ivlen) {
		ret = kcapi_kpp_dh_setparam_pkcs3(handle, cavs_test->iv,
						  cavs_test->ivlen);
		if (ret < 0) {
			printf("Setting PKCS3 DH parameters failed: %zd\n", ret);
			goto out;
		}
	}
	if (cavs_test->taglen) {
		ret = kcapi_kpp_ecdh_setcurve(handle,
					      (unsigned short)cavs_test->taglen);
		if (ret < 0) {
			printf("Setting ECDH curve failed: %zd\n", ret);
			goto out;
		}
	}

	ret = kcapi_kpp_setkey(handle, cavs_test->key, cavs_test->keylen);
	if (ret < 0) {
		printf("Having kernel generating keys failed %zd\n", ret);
		goto out;
	}

	outbuflen = (size_t)ret;
	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, (size_t)ret))
			return -ENOMEM;
		memset(outbuf, 0, (size_t)ret);
	} else {
		outbuf = calloc(1, (size_t)ret);
		if (!outbuf)
			return -ENOMEM;
	}

	if (cavs_test->pt && cavs_test->ptlen)
		ret = kcapi_kpp_ssgen(handle, cavs_test->pt, cavs_test->ptlen,
				      outbuf, outbuflen, splice);
	else
		ret = kcapi_kpp_keygen(handle, outbuf, outbuflen, splice);
	if (ret < 0)
		goto out;

	bin2print(outbuf, (size_t)ret);
	printf("\n");

	ret = 0;

out:
	if (outbuf)
		free(outbuf);
	kcapi_kpp_destroy(handle);
	return (int)ret;
}

static int kpp_aio(struct kcapi_cavs *cavs_test, uint32_t loops, int splice)
{
	struct kcapi_handle *handle = NULL;
	struct iovec iniov, outiov;
	uint8_t *outbuf = NULL;
	size_t outbuflen;
	ssize_t ret;

	(void)loops;

	if (!cavs_test->ivlen && !cavs_test->taglen)
		return -EINVAL;

	if (kcapi_kpp_init(&handle, cavs_test->cipher, KCAPI_INIT_AIO)) {
		ret = -EINVAL;
		printf("Allocation of cipher failed\n");
		goto out;
	}

	if (cavs_test->ivlen) {
		ret = kcapi_kpp_dh_setparam_pkcs3(handle, cavs_test->iv,
						  cavs_test->ivlen);
		if (ret < 0) {
			printf("Setting PKCS3 DH parameters failed: %zd\n", ret);
			goto out;
		}
	}
	if (cavs_test->taglen) {
		ret = kcapi_kpp_ecdh_setcurve(handle,
					      (unsigned short)cavs_test->taglen);
		if (ret < 0) {
			printf("Setting ECDH curve failed: %zd\n", ret);
			goto out;
		}
	}

	ret = kcapi_kpp_setkey(handle, cavs_test->key, cavs_test->keylen);
	if (ret < 0) {
		printf("Having kernel generating keys failed %zd\n", ret);
		goto out;
	}

	outbuflen = (size_t)ret;
	if (cavs_test->aligned) {
		if (posix_memalign((void *)&outbuf, pagesize, (size_t)ret))
			return -ENOMEM;
		memset(outbuf, 0, (size_t)ret);
	} else {
		outbuf = calloc(1, (size_t)ret);
		if (!outbuf)
			return -ENOMEM;
	}

	iniov.iov_base = cavs_test->pt;
	iniov.iov_len = cavs_test->ptlen;
	outiov.iov_base = outbuf;
	outiov.iov_len = outbuflen;
	if (cavs_test->pt && cavs_test->ptlen)
		ret = kcapi_kpp_ssgen_aio(handle, &iniov, &outiov, 1, splice);
	else
		ret = kcapi_kpp_keygen_aio(handle, &outiov, 1, splice);
	if (ret < 0)
		goto out;

	bin2print(outbuf, (size_t)ret);
	printf("\n");

	ret = 0;

out:
	if (outbuf)
		free(outbuf);
	kcapi_kpp_destroy(handle);
	return (int)ret;
}
#else /* WITH_LIB_KPP */
static int kpp(struct kcapi_cavs *cavs_test, uint32_t loops, int splice)
{
	(void)cavs_test;
	(void)loops;
	(void)splice;

	fprintf(stderr, "KPP support disabled\n");

	return -EOPNOTSUPP;
}

static int kpp_aio(struct kcapi_cavs *cavs_test, uint32_t loops, int splice)
{
	(void)cavs_test;
	(void)loops;
	(void)splice;

	fprintf(stderr, "KPP support disabled\n");

	return -EOPNOTSUPP;
}

#endif /* WITH_LIB_KPP */

int main(int argc, char *argv[])
{
	int c = 0;
	int ret = 1;
	int rc = 1;
	int stream = 0;
	int multithreaded = 0;
	int printaad = 0;
	int large = 0;
	int aiofallback = 0;
	int fuzztests = 0;
	uint32_t loops = 1;
	int splice = KCAPI_ACCESS_SENDMSG;
	struct kcapi_cavs cavs_test;

	pagesize = (size_t)sysconf(_SC_PAGESIZE);
	if (pagesize > ULONG_MAX)
		return 1;

	memset(&cavs_test, 0, sizeof(struct kcapi_cavs));
	kcapi_set_verbosity(KCAPI_LOG_WARN);

	while (1)
	{
		int opt_index = 0;
		size_t len = 0;
		static struct option opts[] =
		{
			{"enc", 0, 0, 'e'},
			{"cipher", 1, 0, 'c'},
			{"pt", 1, 0, 'p'},
			{"ct", 1, 0, 'q'},
			{"iv", 1, 0, 'i'},
			{"nonce", 1, 0, 'n'},
			{"key", 1, 0, 'k'},
			{"pubkey", 1, 0, 'r'},
			{"assoc", 1, 0, 'a'},
			{"taglen", 1, 0, 'l'},
			{"tag", 1, 0, 't'},
			{"ciphertype", 1, 0, 'x'},
			{"aux", 0, 0, 'z'},
			{"stream", 0, 0, 's'},
			{"largeinput", 0, 0, 'y'},
			{"execloops", 0, 0, 'd'},
			{"vmsplice", 0, 0, 'v'},
			{"aligned", 0, 0, 'm'},
			{"operation", 0, 0, 'o'},
			{"outlen", 0, 0, 'b'},
			{"timing", 0, 0, 'f'},
			{"aiofallback", 0, 0, 'g'},
			{"fuzztest", 0, 0, 'h'},
			{"multithreaded", 0, 0, 'j'},
			{"printaad", 0, 0, 'u'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "ec:p:q:i:mn:k:a:l:t:x:zsyd:vo:r:b:fghju", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c)
		{
			case 'm':
				cavs_test.aligned = 1;
				break;
			case 'e':
				cavs_test.enc = 1;
				break;
			case 'c':
				strncpy(cavs_test.cipher, optarg,
					CIPHERMAXNAME - 1);
				break;
			case 'p':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.pt, len / 2);
				if (ret)
					goto out;
				cavs_test.ptlen = len / 2;
				break;
			case 'q':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.ct, len / 2);
				if (ret)
					goto out;
				cavs_test.ctlen = len / 2;
				break;
			case 'i':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.iv, len / 2);
				if (ret)
					goto out;
				cavs_test.ivlen = (uint32_t)len / 2;
				break;
			case 'n':
			{
				uint8_t *nonce;
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len, &nonce, len / 2);
				if (ret)
					goto out;
				ret = kcapi_aead_ccm_nonce_to_iv(nonce,
								 (uint32_t)(len / 2),
								 &cavs_test.iv,
								 &cavs_test.ivlen);
				free(nonce);
				if (ret)
					goto out;
				break;
			}
			case 'k':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.key, len / 2);
				if (ret)
					goto out;
				cavs_test.keylen = (uint32_t)(len / 2);
				break;
			case 'r':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.pubkey, len / 2);
				if (ret)
					goto out;
				cavs_test.pubkeylen = (uint32_t)(len / 2);
				break;
			case 'a':
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len,
						&cavs_test.assoc, len / 2);
				if (ret)
					goto out;
				cavs_test.assoclen = len / 2;
				break;
			case 'l':
				len = (uint32_t)atoi(optarg);
				if (cavs_test.taglen &&
				    len != cavs_test.taglen) {
					printf("Set taglen != tag size\n");
					goto out;
				}
				cavs_test.taglen = (uint32_t)len;
				break;
			case 't':
				len = strlen(optarg);
				if (cavs_test.taglen &&
				    len != cavs_test.taglen) {
					printf("Set taglen != tag size\n");
					goto out;
				}
				ret = hex2bin_m(optarg, len,
						&cavs_test.tag, len / 2);
				if (ret)
					goto out;
				cavs_test.taglen = (uint32_t)(len / 2);
				break;
			case 'x':
				cavs_test.type = atoi(optarg);
				break;
			case 'o':
				cavs_test.enc = atoi(optarg);
				if (cavs_test.enc < 0 || cavs_test.enc > 3) {
					usage();
					goto out;
				}
				break;
			case 'z':
				rc = auxiliary_tests();
				goto out;
				break;
			case 's':
				stream = 1;
				break;
			case 'j':
				multithreaded = 1;
				break;
			case 'y':
				large = 1;
				break;
			case 'd':
				loops = (uint32_t)strtoul(optarg, NULL, 10);
				break;
			case 'v':
				splice = KCAPI_ACCESS_VMSPLICE;
				break;
			case 'b':
				cavs_test.outlen = (size_t)atoi(optarg);
				break;
			case 'f':
				cavs_test.timing = 1;
				break;
			case 'g':
				aiofallback = 1;
				break;
			case 'h':
				fuzztests = 1;
				break;
			case 'u':
				printaad = 1;
				break;

			default:
				usage();
				goto out;
		}
	}

	if (fuzztests) {
		rc = fuzz_tests(&cavs_test, loops);
		goto out;
	}

	if (large) {
		rc = cavs_aead_large(stream, loops, splice);
	} else if (SYM == cavs_test.type) {
		if (stream)
			rc = cavs_sym_stream(&cavs_test, loops, multithreaded);
		else
			rc = cavs_sym(&cavs_test, loops, splice);
	} else if (SYM_AIO == cavs_test.type)
		rc = cavs_sym_aio(&cavs_test, loops, splice, aiofallback);
	else if (AEAD == cavs_test.type) {
		if (stream)
			rc = cavs_aead_stream(&cavs_test, loops, printaad);
		else
			rc = cavs_aead(&cavs_test, loops, splice, printaad);
	} else if (AEAD_AIO == cavs_test.type)
		rc = cavs_aead_aio(&cavs_test, loops, splice, printaad,
				   aiofallback);
	else if (HASH == cavs_test.type) {
		if (stream)
			rc = cavs_hash_stream(&cavs_test, loops);
		else
			rc = cavs_hash(&cavs_test, loops);
	} else if (ASYM == cavs_test.type) {
		if (stream)
			rc = cavs_asym_stream(&cavs_test, loops, splice);
		else
			rc = cavs_asym(&cavs_test, loops, splice);
	} else if (ASYM_AIO == cavs_test.type) {
		rc = cavs_asym_aio(&cavs_test, loops, splice);
	} else if (KDF_CTR == cavs_test.type ||
		   KDF_FB == cavs_test.type ||
		   KDF_DPI == cavs_test.type) {
		rc = cavs_kdf_common(&cavs_test, loops);
	} else if (KDF_HKDF == cavs_test.type) {
		rc = cavs_hkdf(&cavs_test, loops);
	} else if (PBKDF == cavs_test.type) {
		rc = cavs_pbkdf(&cavs_test, loops);
	} else if (KPP == cavs_test.type) {
		rc = kpp(&cavs_test, loops, splice);
	} else if (KPP_AIO == cavs_test.type) {
		rc = kpp_aio(&cavs_test, loops, splice);
	} else
		goto out;
	if (rc)
		printf("Failed to invoke testing\n");
	rc = 0;

out:
	if (cavs_test.pt)
		free(cavs_test.pt);
	if (cavs_test.ct)
		free(cavs_test.ct);
	if (cavs_test.iv)
		free(cavs_test.iv);
	if (cavs_test.key)
		free(cavs_test.key);
	if (cavs_test.pubkey)
		free(cavs_test.pubkey);
	if (cavs_test.assoc)
		free(cavs_test.assoc);
	if (cavs_test.tag)
		free(cavs_test.tag);
	return rc;
}
