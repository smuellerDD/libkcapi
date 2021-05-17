/*
 * Copyright (C) 2015 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include "cryptoperf.h"
#include <limits.h>
#include <stdlib.h>
#include <sys/user.h>

/****************************************************************************
 * Synchronous symmetric ciphers
 ****************************************************************************/

static int cp_skcipher_init_test(struct cp_test *test)
{
	unsigned char *scratchpad = NULL;
	struct cp_test_param *params = test->test_params;
#define MAX_KEYLEN 64
	unsigned char data[MAX_KEYLEN];
	unsigned char *ivdata = NULL;
	unsigned int bs;
	int err;
	size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);

	if (pagesize > ULONG_MAX) {
		printf(DRIVER_NAME": unable to determine the page size\n");
		return -errno;
	}

	dbg("Initializing symmetric test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing test definition information for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_cipher_init(&test->u.skcipher.handle, test->driver_name,
			      params->aio ? KCAPI_INIT_AIO : 0)) {
		printf(DRIVER_NAME": could not allocate skcipher handle for "
		       "%s\n", test->driver_name);
		goto out;
	}

	if (test->u.skcipher.keysize > MAX_KEYLEN) {
		printf(DRIVER_NAME": key length for cipher %s too large\n",
		       test->driver_name);
		goto out;
	}

	cp_read_random(data, test->u.skcipher.keysize);
	if (kcapi_cipher_setkey(test->u.skcipher.handle, data,
				test->u.skcipher.keysize)) {
		printf(DRIVER_NAME": key could not be set\n");
		goto out;
	}

	bs = kcapi_cipher_blocksize(test->u.skcipher.handle);
	/* handle stream ciphers */
	if (bs == 1)
		bs = 16;
	err = posix_memalign((void *)&ivdata, bs, bs);
	if (err) {
		printf(DRIVER_NAME": could not allocate ivdata for "
		       "%s (error: %d)\n", test->driver_name, err);
		goto out;
	}
	cp_read_random(ivdata, kcapi_cipher_blocksize(test->u.skcipher.handle));
	test->u.skcipher.iv = ivdata;

	err = posix_memalign((void *)&scratchpad, pagesize,
		kcapi_cipher_blocksize(test->u.skcipher.handle) * params->len *
				       (params->aio ? params->aio : 1));
	if (err) {
		printf(DRIVER_NAME": could not allocate scratchpad for "
		       "%s (error %d)\n", test->driver_name, err);
		goto out;
	}

	cp_read_random(scratchpad,
		       kcapi_cipher_blocksize(test->u.skcipher.handle) *
					      params->len *
					      (params->aio ? params->aio : 1));

	test->u.skcipher.inputlen =
		params->len * kcapi_cipher_blocksize(test->u.skcipher.handle);
	test->u.skcipher.scratchpad = scratchpad;

	if (params->aio) {
		unsigned int i;

		err = posix_memalign((void *)&test->u.skcipher.iovec, bs,
				     params->aio * sizeof(struct iovec));
		if (err) {
			printf(DRIVER_NAME": could not allocate iovec buffer\n");
			goto out;
		}

		for (i = 0; i < params->aio; i++) {
			test->u.skcipher.iovec[i].iov_base = scratchpad;
			test->u.skcipher.iovec[i].iov_len = test->u.skcipher.inputlen;
			scratchpad += test->u.skcipher.inputlen;
		}
	}

	return 0;

out:
	kcapi_cipher_destroy(test->u.skcipher.handle);
	if (scratchpad)
		free(scratchpad);
	if (ivdata)
		free(ivdata);
	return -ENOMEM;
}

static void cp_skcipher_fini_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	dbg("Cleaning up asynchronous symmetric test %s\n", test->testname);
	free(test->u.skcipher.scratchpad);
	free(test->u.skcipher.iv);
	if (params->aio)
		free(test->u.skcipher.iovec);
	kcapi_cipher_destroy(test->u.skcipher.handle);
}

static size_t cp_skcipher_enc_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	if (params->aio)
		kcapi_cipher_encrypt_aio(test->u.skcipher.handle,
					 test->u.skcipher.iovec,
					 test->u.skcipher.iovec,
					 params->aio,
					 test->u.skcipher.iv,
					 params->accesstype);
	else
		kcapi_cipher_encrypt(test->u.skcipher.handle,
				     test->u.skcipher.scratchpad,
				     test->u.skcipher.inputlen,
				     test->u.skcipher.iv,
				     test->u.skcipher.scratchpad,
				     test->u.skcipher.inputlen,
				     params->accesstype);
	return test->u.skcipher.inputlen;
}

static size_t cp_skcipher_dec_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	if (params->aio)
		kcapi_cipher_decrypt_aio(test->u.skcipher.handle,
					 test->u.skcipher.iovec,
					 test->u.skcipher.iovec,
					 params->aio,
					 test->u.skcipher.iv,
					 params->accesstype);
	else
		kcapi_cipher_decrypt(test->u.skcipher.handle,
				     test->u.skcipher.scratchpad,
				     test->u.skcipher.inputlen,
				     test->u.skcipher.iv,
				     test->u.skcipher.scratchpad,
				     test->u.skcipher.inputlen,
				     params->accesstype);
	return test->u.skcipher.inputlen;
}

struct cp_skcipher_tests {
	char *testname;
	char *driver_name;
	unsigned int keysize;
};

static const struct cp_skcipher_tests testcases[] = {

	{ "AES(G) CBC(G) 128", "cbc(aes-generic)", 16 },
	{ "AES(G) CBC(G) 192", "cbc(aes-generic)", 24 },
	{ "AES(G) CBC(G) 256", "cbc(aes-generic)", 32 },
	{ "AES(AESNI) CBC(ASM) 128", "cbc-aes-aesni", 16 },
	{ "AES(AESNI) CBC(ASM) 192", "cbc-aes-aesni", 24 },
	{ "AES(AESNI) CBC(ASM) 256", "cbc-aes-aesni", 32 },
	{ "AES(AESNI) CBC(G) 128", "cbc(aes-aesni)", 16 },
	{ "AES(AESNI) CBC(G) 192", "cbc(aes-aesni)", 24 },
	{ "AES(AESNI) CBC(G) 256", "cbc(aes-aesni)", 32 },
	{ "AES(i586) CBC(G) 128", "cbc(aes-asm)", 16 },
	{ "AES(i586) CBC(G) 192", "cbc(aes-asm)", 24 },
	{ "AES(i586) CBC(G) 256", "cbc(aes-asm)", 32 },

	{ "AES(MV-CESA) CBC(MV-CESA) 128", "mv-cbc-aes", 16 },
	{ "AES(MV-CESA) CBC(MV-CESA) 192", "mv-cbc-aes", 24 },
	{ "AES(MV-CESA) CBC(MV-CESA) 256", "mv-cbc-aes", 32 },

	{ "AES(hisi) CBC 128", "hisi_sec_aes_cbc", 16 },
	{ "AES(hisi) CBC 192", "hisi_sec_aes_cbc", 24 },
	{ "AES(hisi) CBC 256", "hisi_sec_aes_cbc", 32 },

	{ "AES(G) CTR(G) 128", "ctr(aes-generic)", 16 },
	{ "AES(G) CTR(G) 192", "ctr(aes-generic)", 24 },
	{ "AES(G) CTR(G) 256", "ctr(aes-generic)", 32 },
	{ "AES(AESNI) CTR(ASM) 128", "ctr-aes-aesni", 16 },
	{ "AES(AESNI) CTR(ASM) 192", "ctr-aes-aesni", 24 },
	{ "AES(AESNI) CTR(ASM) 256", "ctr-aes-aesni", 32 },
	{ "AES(AESNI) CTR(G) 128", "ctr(aes-aesni)", 16 },
	{ "AES(AESNI) CTR(G) 192", "ctr(aes-aesni)", 24 },
	{ "AES(AESNI) CTR(G) 256", "ctr(aes-aesni)", 32 },
	{ "AES(i586) CTR(G) 128", "ctr(aes-asm)", 16 },
	{ "AES(i586) CTR(G) 192", "ctr(aes-asm)", 24 },
	{ "AES(i586) CTR(G) 256", "ctr(aes-asm)", 32 },

	{ "AES(G) XTS(G) 128", "xts(aes-generic)", 32 },
	{ "AES(G) XTS(G) 192", "xts(aes-generic)", 48 },
	{ "AES(G) XTS(G) 256", "xts(aes-generic)", 64 },
	{ "AES(AESNI) XTS(ASM) 128", "xts-aes-aesni", 32 },
	{ "AES(AESNI) XTS(ASM) 192", "xts-aes-aesni", 48 },
	{ "AES(AESNI) XTS(ASM) 256", "xts-aes-aesni", 64 },
	{ "AES(AESNI) XTS(G) 128", "xts(aes-aesni)", 32 },
	{ "AES(AESNI) XTS(G) 192", "xts(aes-aesni)", 48 },
	{ "AES(AESNI) XTS(G) 256", "xts(aes-aesni)", 64 },
	{ "AES(i586) XTS(G) 128", "xts(aes-asm)", 32 },
	{ "AES(i586) XTS(G) 192", "xts(aes-asm)", 48 },
	{ "AES(i586) XTS(G) 256", "xts(aes-asm)", 64 },

	{ "AES(G) LRW(G) 128", "lrw(aes-generic)", 32 },
	{ "AES(G) LRW(G) 192", "lrw(aes-generic)", 40 },
	{ "AES(G) LRW(G) 256", "lrw(aes-generic)", 48 },
	{ "AES(AESNI) LRW(ASM) 128", "lrw-aes-aesni", 32 },
	{ "AES(AESNI) LRW(ASM) 192", "lrw-aes-aesni", 40 },
	{ "AES(AESNI) LRW(ASM) 256", "lrw-aes-aesni", 48 },
	{ "AES(AESNI) LRW(G) 128", "lrw(aes-aesni)", 32 },
	{ "AES(AESNI) LRW(G) 192", "lrw(aes-aesni)", 40 },
	{ "AES(AESNI) LRW(G) 256", "lrw(aes-aesni)", 48 },
	{ "AES(i586) LRW(G) 128", "lrw(aes-asm)", 32 },
	{ "AES(i586) LRW(G) 192", "lrw(aes-asm)", 40 },
	{ "AES(i586) LRW(G) 256", "lrw(aes-asm)", 48 },

	{ "AES(G) ECB(G) 128", "ecb(aes-generic)", 16 },
	{ "AES(G) ECB(G) 192", "ecb(aes-generic)", 24 },
	{ "AES(G) ECB(G) 256", "ecb(aes-generic)", 32 },
	{ "AES(AESNI) ECB(ASM) 128", "ecb-aes-aesni", 16 },
	{ "AES(AESNI) ECB(ASM) 192", "ecb-aes-aesni", 24 },
	{ "AES(AESNI) ECB(ASM) 256", "ecb-aes-aesni", 32 },
	{ "AES(AESNI) ECB(G) 128", "ecb(aes-aesni)", 16 },
	{ "AES(AESNI) ECB(G) 192", "ecb(aes-aesni)", 24 },
	{ "AES(AESNI) ECB(G) 256", "ecb(aes-aesni)", 32 },
	{ "AES(i586) ECB(G) 128", "ecb(aes-asm)", 16 },
	{ "AES(i586) ECB(G) 192", "ecb(aes-asm)", 24 },
	{ "AES(i586) ECB(G) 256", "ecb(aes-asm)", 32 },
	{ "AES(MV-CESA) ECB(MV-CESA) 128", "mv-ecb-aes", 16 },
	{ "AES(MV-CESA) ECB(MV-CESA) 192", "mv-ecb-aes", 24 },
	{ "AES(MV-CESA) ECB(MV-CESA) 256", "mv-ecb-aes", 32 },

	{ "DES(MV-CESA) CBC(MV-CESA) 56", "mv-cbc-des", 8 },
	{ "DES(MV-CESA) ECB(MV-CESA) 56", "mv-ecb-des", 8 },

	{ "DES3(MV-CESA) CBC(MV-CESA) EDE 168", "mv-cbc-des3-ede", 24 },
	{ "DES3(MV-CESA) ECB(MV-CESA) EDE 168", "mv-ecb-des3-ede", 24 },

	{ "Serpent(AVX) XTS(AVX) 128", "xts-serpent-avx", 32 },
	{ "Serpent(AVX) XTS(AVX) 192", "xts-serpent-avx", 48 },
	{ "Serpent(AVX) XTS(AVX) 256", "xts-serpent-avx", 64 },
	{ "Serpent(AVX2) XTS(AVX2) 128", "xts-serpent-avx2", 32 },
	{ "Serpent(AVX2) XTS(AVX2) 192", "xts-serpent-avx2", 48 },
	{ "Serpent(AVX2) XTS(AVX2) 256", "xts-serpent-avx2", 64 },
	{ "Serpent(SSE2) XTS(SSE2) 128", "xts-serpent-sse2", 32 },
	{ "Serpent(SSE2) XTS(SSE2) 192", "xts-serpent-sse2", 48 },
	{ "Serpent(SSE2) XTS(SSE2) 256", "xts-serpent-sse2", 64 },
	{ "Serpent(G) XTS(G) 128", "xts(serpent-generic)", 32 },
	{ "Serpent(G) XTS(G) 192", "xts(serpent-generic)", 48 },
	{ "Serpent(G) XTS(G) 256", "xts(serpent-generic)", 64 },

	{ "Serpent(AVX) LRW(AVX) 128", "lrw-serpent-avx", 32 },
	{ "Serpent(AVX) LRW(AVX) 192", "lrw-serpent-avx", 40 },
	{ "Serpent(AVX) LRW(AVX) 256", "lrw-serpent-avx", 48 },
	{ "Serpent(AVX2) LRW(AVX2) 128", "lrw-serpent-avx2", 32 },
	{ "Serpent(AVX2) LRW(AVX2) 192", "lrw-serpent-avx2", 40 },
	{ "Serpent(AVX2) LRW(AVX2) 256", "lrw-serpent-avx2", 48 },
	{ "Serpent(SSE2) LRW(SSE2) 128", "lrw-serpent-sse2", 32 },
	{ "Serpent(SSE2) LRW(SSE2) 192", "lrw-serpent-sse2", 40 },
	{ "Serpent(SSE2) LRW(SSE2) 256", "lrw-serpent-sse2", 48 },
	{ "Serpent(G) LRW(G) 128", "lrw(serpent-generic)", 32 },
	{ "Serpent(G) LRW(G) 192", "lrw(serpent-generic)", 40 },
	{ "Serpent(G) LRW(G) 256", "lrw(serpent-generic)", 48 },

	{ "Serpent(AVX) CTR(AVX) 128", "ctr-serpent-avx", 16 },
	{ "Serpent(AVX) CTR(AVX) 192", "ctr-serpent-avx", 24 },
	{ "Serpent(AVX) CTR(AVX) 256", "ctr-serpent-avx", 32 },
	{ "Serpent(AVX2) CTR(AVX2) 128", "ctr-serpent-avx2", 16 },
	{ "Serpent(AVX2) CTR(AVX2) 192", "ctr-serpent-avx2", 24 },
	{ "Serpent(AVX2) CTR(AVX2) 256", "ctr-serpent-avx2", 32 },
	{ "Serpent(SSE2) CTR(SSE2) 128", "ctr-serpent-sse2", 16 },
	{ "Serpent(SSE2) CTR(SSE2) 192", "ctr-serpent-sse2", 24 },
	{ "Serpent(SSE2) CTR(SSE2) 256", "ctr-serpent-sse2", 32 },
	{ "Serpent(G) CTR(G) 128", "ctr(serpent-generic)", 16 },
	{ "Serpent(G) CTR(G) 192", "ctr(serpent-generic)", 24 },
	{ "Serpent(G) CTR(G) 256", "ctr(serpent-generic)", 32 },

	{ "Serpent(AVX) CBC(AVX) 128", "cbc-serpent-avx", 16 },
	{ "Serpent(AVX) CBC(AVX) 192", "cbc-serpent-avx", 24 },
	{ "Serpent(AVX) CBC(AVX) 256", "cbc-serpent-avx", 32 },
	{ "Serpent(AVX2) CBC(AVX2) 128", "cbc-serpent-avx2", 16 },
	{ "Serpent(AVX2) CBC(AVX2) 192", "cbc-serpent-avx2", 24 },
	{ "Serpent(AVX2) CBC(AVX2) 256", "cbc-serpent-avx2", 32 },
	{ "Serpent(SSE2) CBC(SSE2) 128", "cbc-serpent-sse2", 16 },
	{ "Serpent(SSE2) CBC(SSE2) 192", "cbc-serpent-sse2", 24 },
	{ "Serpent(SSE2) CBC(SSE2) 256", "cbc-serpent-sse2", 32 },
	{ "Serpent(G) CBC(G) 128", "cbc(serpent-generic)", 16 },
	{ "Serpent(G) CBC(G) 192", "cbc(serpent-generic)", 24 },
	{ "Serpent(G) CBC(G) 256", "cbc(serpent-generic)", 32 },

	{ "Serpent(AVX) ECB(AVX) 128", "ecb-serpent-avx", 16 },
	{ "Serpent(AVX) ECB(AVX) 192", "ecb-serpent-avx", 24 },
	{ "Serpent(AVX) ECB(AVX) 256", "ecb-serpent-avx", 32 },
	{ "Serpent(AVX2) ECB(AVX2) 128", "ecb-serpent-avx2", 16 },
	{ "Serpent(AVX2) ECB(AVX2) 192", "ecb-serpent-avx2", 24 },
	{ "Serpent(AVX2) ECB(AVX2) 256", "ecb-serpent-avx2", 32 },
	{ "Serpent(SSE2) ECB(SSE2) 128", "ecb-serpent-sse2", 16 },
	{ "Serpent(SSE2) ECB(SSE2) 192", "ecb-serpent-sse2", 24 },
	{ "Serpent(SSE2) ECB(SSE2) 256", "ecb-serpent-sse2", 32 },
	{ "Serpent(G) ECB(G) 128", "ecb(serpent-generic)", 16 },
	{ "Serpent(G) ECB(G) 192", "ecb(serpent-generic)", 24 },
	{ "Serpent(G) ECB(G) 256", "ecb(serpent-generic)", 32 },

	{ "Blowfish(G) ECB(G) 128", "ecb(blowfish-generic)", 16 },
	{ "Blowfish(G) ECB(G) 192", "ecb(blowfish-generic)", 24 },
	{ "Blowfish(G) ECB(G) 256", "ecb(blowfish-generic)", 32 },
	{ "Blowfish(x86_64) ECB(G) 128", "ecb(blowfish-asm)", 16 },
	{ "Blowfish(x86_64) ECB(G) 192", "ecb(blowfish-asm)", 24 },
	{ "Blowfish(x86_64) ECB(G) 256", "ecb(blowfish-asm)", 32 },
	{ "Blowfish(x86_64) ECB(x86_64) 128", "ecb-blowfish-asm", 16 },
	{ "Blowfish(x86_64) ECB(x86_64) 192", "ecb-blowfish-asm", 24 },
	{ "Blowfish(x86_64) ECB(x86_64) 256", "ecb-blowfish-asm", 32 },

	{ "Blowfish(G) CBC(G) 128", "cbc(blowfish-generic)", 16 },
	{ "Blowfish(G) CBC(G) 192", "cbc(blowfish-generic)", 24 },
	{ "Blowfish(G) CBC(G) 256", "cbc(blowfish-generic)", 32 },
	{ "Blowfish(x86_64) CBC(G) 128", "cbc(blowfish-asm)", 16 },
	{ "Blowfish(x86_64) CBC(G) 192", "cbc(blowfish-asm)", 24 },
	{ "Blowfish(x86_64) CBC(G) 256", "cbc(blowfish-asm)", 32 },
	{ "Blowfish(x86_64) CBC(x86_64) 128", "cbc-blowfish-asm", 16 },
	{ "Blowfish(x86_64) CBC(x86_64) 192", "cbc-blowfish-asm", 24 },
	{ "Blowfish(x86_64) CBC(x86_64) 256", "cbc-blowfish-asm", 32 },

	{ "Blowfish(G) CTR(G) 128", "ctr(blowfish-generic)", 16 },
	{ "Blowfish(G) CTR(G) 192", "ctr(blowfish-generic)", 24 },
	{ "Blowfish(G) CTR(G) 256", "ctr(blowfish-generic)", 32 },
	{ "Blowfish(x86_64) CTR(G) 128", "ctr(blowfish-asm)", 16 },
	{ "Blowfish(x86_64) CTR(G) 192", "ctr(blowfish-asm)", 24 },
	{ "Blowfish(x86_64) CTR(G) 256", "ctr(blowfish-asm)", 32 },
	{ "Blowfish(x86_64) CTR(x86_64) 128", "ctr-blowfish-asm", 16 },
	{ "Blowfish(x86_64) CTR(x86_64) 192", "ctr-blowfish-asm", 24 },
	{ "Blowfish(x86_64) CTR(x86_64) 256", "ctr-blowfish-asm", 32 },

	// I guess the XTS / LRW pre-requisites are not met by blowfish
//	{ "Blowfish(G) XTS(G) 128", "xts(blowfish-generic)", 32 },
//	{ "Blowfish(G) XTS(G) 192", "xts(blowfish-generic)", 48 },
//	{ "Blowfish(G) XTS(G) 256", "xts(blowfish-generic)", 64 },
//	{ "Blowfish(x86_64) XTS(G) 128", "xts(blowfish-asm)", 32 },
//	{ "Blowfish(x86_64) XTS(G) 192", "xts(blowfish-asm)", 48 },
//	{ "Blowfish(x86_64) XTS(G) 256", "xts(blowfish-asm)", 64 },

//	{ "Blowfish(G) LRW(G) 128", "lrw(blowfish-generic)", 32 },
//	{ "Blowfish(G) LRW(G) 192", "lrw(blowfish-generic)", 40 },
//	{ "Blowfish(G) LRW(G) 256", "lrw(blowfish-generic)", 48 },
//	{ "Blowfish(x86_64) LRW(G) 128", "lrw(blowfish-asm)", 32 },
//	{ "Blowfish(x86_64) LRW(G) 192", "lrw(blowfish-asm)", 40 },
//	{ "Blowfish(x86_64) LRW(G) 256", "lrw(blowfish-asm)", 48 },

	{ "Twofish(G) ECB(G) 128", "ecb(twofish-generic)", 16 },
	{ "Twofish(G) ECB(G) 192", "ecb(twofish-generic)", 24 },
	{ "Twofish(G) ECB(G) 256", "ecb(twofish-generic)", 32 },
	{ "Twofish(x86_64) ECB(G) 128", "ecb(twofish-asm)", 16 },
	{ "Twofish(x86_64) ECB(G) 192", "ecb(twofish-asm)", 24 },
	{ "Twofish(x86_64) ECB(G) 256", "ecb(twofish-asm)", 32 },
	{ "Twofish(3way) ECB(3way) 128", "ecb-twofish-3way", 16 },
	{ "Twofish(3way) ECB(3way) 192", "ecb-twofish-3way", 24 },
	{ "Twofish(3way) ECB(3way) 256", "ecb-twofish-3way", 32 },
	{ "Twofish(AVX) ECB(AVX) 128", "ecb-twofish-avx", 16 },
	{ "Twofish(AVX) ECB(AVX) 192", "ecb-twofish-avx", 24 },
	{ "Twofish(AVX) ECB(AVX) 256", "ecb-twofish-avx", 32 },

	{ "Twofish(G) CBC(G) 128", "cbc(twofish-generic)", 16 },
	{ "Twofish(G) CBC(G) 192", "cbc(twofish-generic)", 24 },
	{ "Twofish(G) CBC(G) 256", "cbc(twofish-generic)", 32 },
	{ "Twofish(x86_64) CBC(G) 128", "cbc(twofish-asm)", 16 },
	{ "Twofish(x86_64) CBC(G) 192", "cbc(twofish-asm)", 24 },
	{ "Twofish(x86_64) CBC(G) 256", "cbc(twofish-asm)", 32 },
	{ "Twofish(3way) CBC(3way) 128", "cbc-twofish-3way", 16 },
	{ "Twofish(3way) CBC(3way) 192", "cbc-twofish-3way", 24 },
	{ "Twofish(3way) CBC(3way) 256", "cbc-twofish-3way", 32 },
	{ "Twofish(AVX) CBC(AVX) 128", "cbc-twofish-avx", 16 },
	{ "Twofish(AVX) CBC(AVX) 192", "cbc-twofish-avx", 24 },
	{ "Twofish(AVX) CBC(AVX) 256", "cbc-twofish-avx", 32 },

	{ "Twofish(G) CTR(G) 128", "ctr(twofish-generic)", 16 },
	{ "Twofish(G) CTR(G) 192", "ctr(twofish-generic)", 24 },
	{ "Twofish(G) CTR(G) 256", "ctr(twofish-generic)", 32 },
	{ "Twofish(x86_64) CTR(G) 128", "ctr(twofish-asm)", 16 },
	{ "Twofish(x86_64) CTR(G) 192", "ctr(twofish-asm)", 24 },
	{ "Twofish(x86_64) CTR(G) 256", "ctr(twofish-asm)", 32 },
	{ "Twofish(3way) CTR(3way) 128", "ctr-twofish-3way", 16 },
	{ "Twofish(3way) CTR(3way) 192", "ctr-twofish-3way", 24 },
	{ "Twofish(3way) CTR(3way) 256", "ctr-twofish-3way", 32 },
	{ "Twofish(AVX) CTR(AVX) 128", "ctr-twofish-avx", 16 },
	{ "Twofish(AVX) CTR(AVX) 192", "ctr-twofish-avx", 24 },
	{ "Twofish(AVX) CTR(AVX) 256", "ctr-twofish-avx", 32 },

	{ "Twofish(G) XTS(G) 128", "xts(twofish-generic)", 32 },
	{ "Twofish(G) XTS(G) 192", "xts(twofish-generic)", 48 },
	{ "Twofish(G) XTS(G) 256", "xts(twofish-generic)", 64 },
	{ "Twofish(x86_64) XTS(G) 128", "xts(twofish-asm)", 32 },
	{ "Twofish(x86_64) XTS(G) 192", "xts(twofish-asm)", 48 },
	{ "Twofish(x86_64) XTS(G) 256", "xts(twofish-asm)", 64 },
	{ "Twofish(3way) XTS(3way) 128", "xts-twofish-3way", 32 },
	{ "Twofish(3way) XTS(3way) 192", "xts-twofish-3way", 48 },
	{ "Twofish(3way) XTS(3way) 256", "xts-twofish-3way", 64 },
	{ "Twofish(AVX) XTS(AVX) 128", "xts-twofish-avx", 32 },
	{ "Twofish(AVX) XTS(AVX) 192", "xts-twofish-avx", 48 },
	{ "Twofish(AVX) XTS(AVX) 256", "xts-twofish-avx", 64 },

	{ "Twofish(G) LRW(G) 128", "lrw(twofish-generic)", 32 },
	{ "Twofish(G) LRW(G) 192", "lrw(twofish-generic)", 40 },
	{ "Twofish(G) LRW(G) 256", "lrw(twofish-generic)", 48 },
	{ "Twofish(x86_64) LRW(G) 128", "lrw(twofish-asm)", 32 },
	{ "Twofish(x86_64) LRW(G) 192", "lrw(twofish-asm)", 40 },
	{ "Twofish(x86_64) LRW(G) 256", "lrw(twofish-asm)", 48 },
	{ "Twofish(3way) LRW(3way) 128", "lrw-twofish-3way", 32 },
	{ "Twofish(3way) LRW(3way) 192", "lrw-twofish-3way", 40 },
	{ "Twofish(3way) LRW(3way) 256", "lrw-twofish-3way", 48 },
	{ "Twofish(AVX) LRW(AVX) 128", "lrw-twofish-avx", 32 },
	{ "Twofish(AVX) LRW(AVX) 192", "lrw-twofish-avx", 40 },
	{ "Twofish(AVX) LRW(AVX) 256", "lrw-twofish-avx", 48 },

	{ "Salsa20(G) 128", "salsa20-generic", 16 },
	{ "Salsa20(G) 192", "salsa20-generic", 24 },
	{ "Salsa20(G) 256", "salsa20-generic", 32 },
	{ "Salsa20(x86) 128", "salsa20-asm", 16 },
	{ "Salsa20(x86) 192", "salsa20-asm", 24 },
	{ "Salsa20(x86) 256", "salsa20-asm", 32 },
};

static struct cp_test cp_skcipher_testdef[2 * (ARRAY_SIZE(testcases))];

void cp_skcipher_register(struct cp_test **skcipher_test, size_t *entries)
{
	size_t i, j;

	for (i = 0, j = 0;
	     i < (ARRAY_SIZE(testcases)) && j < (2 * ARRAY_SIZE(testcases));
	     i++, j++) {
		int enc = 0;
		for (enc = 0; enc < 2; enc++) {
			j += (size_t)enc;
			cp_skcipher_testdef[j].enc = enc;
			cp_skcipher_testdef[j].testname = testcases[i].testname;
			cp_skcipher_testdef[j].driver_name =
				testcases[i].driver_name;
			cp_skcipher_testdef[j].type = "skcipher";
			cp_skcipher_testdef[j].exectime = DFLT_EXECTIME;
			cp_skcipher_testdef[j].u.skcipher.keysize =
				testcases[i].keysize;
			cp_skcipher_testdef[j].init_test = cp_skcipher_init_test;
			cp_skcipher_testdef[j].fini_test = cp_skcipher_fini_test;
			if (enc)
				cp_skcipher_testdef[j].exec_test = cp_skcipher_enc_test;
			else
				cp_skcipher_testdef[j].exec_test = cp_skcipher_dec_test;
		}
	}
	*skcipher_test = &cp_skcipher_testdef[0];
	*entries = j;
}
