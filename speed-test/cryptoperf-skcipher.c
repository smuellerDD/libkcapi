/*
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
 * the GNU General Public License, in which case the provisions of the GPL are
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

#include "cryptoperf.h"
#include <stdlib.h>

/****************************************************************************
 * Synchronous symmetric ciphers
 ****************************************************************************/

static int cp_skcipher_init_test(struct cp_test *test, size_t len)
{
	unsigned char *scratchpad = NULL;
#define MAX_KEYLEN 64
	unsigned char data[MAX_KEYLEN];
	unsigned char ivdata[MAX_KEYLEN];

	dbg("Initializing symmetric test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing test definition information for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_cipher_init(&test->u.skcipher.handle, test->driver_name)) {
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
	if (kcapi_cipher_setkey(&test->u.skcipher.handle, data,
				test->u.skcipher.keysize)) {
		printf(DRIVER_NAME": key could not be set\n");
		goto out;
	}

	cp_read_random(ivdata, kcapi_cipher_blocksize(&test->u.skcipher.handle));
	if (kcapi_cipher_setiv(&test->u.skcipher.handle, ivdata,
				kcapi_cipher_blocksize(&test->u.skcipher.handle))) {
		printf(DRIVER_NAME": key could not be set\n");
		goto out;
	}

	if (posix_memalign((void *)&scratchpad,
			   kcapi_cipher_blocksize(&test->u.skcipher.handle),
			   kcapi_cipher_blocksize(&test->u.skcipher.handle) * len)) {
		printf(DRIVER_NAME": could not allocate scratchpad for "
		       "%s\n", test->driver_name);
		goto out;
	}

	cp_read_random(scratchpad,
		       kcapi_cipher_blocksize(&test->u.skcipher.handle) * len);

	test->u.skcipher.inputlen =
		len * kcapi_cipher_blocksize(&test->u.skcipher.handle);
	test->u.skcipher.scratchpad = scratchpad;

	return 0;

out:
	kcapi_cipher_destroy(&test->u.skcipher.handle);
	if (scratchpad)
		free(scratchpad);
	return -ENOMEM;
}

static void cp_skcipher_fini_test(struct cp_test *test)
{
	dbg("Cleaning up asynchronous symmetric test %s\n", test->testname);
	free(test->u.skcipher.scratchpad);
	kcapi_cipher_destroy(&test->u.skcipher.handle);
}

static unsigned int cp_ablkcipher_enc_test(struct cp_test *test)
{
	kcapi_cipher_encrypt(&test->u.skcipher.handle,
			     test->u.skcipher.scratchpad,
			     test->u.skcipher.inputlen,
			     test->u.skcipher.scratchpad,
			     test->u.skcipher.inputlen);
	return test->u.skcipher.inputlen;
}

static unsigned int cp_ablkcipher_dec_test(struct cp_test *test)
{
	kcapi_cipher_decrypt(&test->u.skcipher.handle,
			     test->u.skcipher.scratchpad,
			     test->u.skcipher.inputlen,
			     test->u.skcipher.scratchpad,
			     test->u.skcipher.inputlen);
	return test->u.skcipher.inputlen;
}

struct cp_skcipher_tests {
	char *testname;
	char *driver_name;
	unsigned int keysize;
	unsigned int enc;
};

static const struct cp_skcipher_tests testcases[] = {

	{ "AES(G) CBC(G) 128 e cd-ablk", "cryptd(cbc(aes-generic))", 16, 1 },
	{ "AES(G) CBC(G) 192 e cd-ablk", "cryptd(cbc(aes-generic))", 24, 1 },
	{ "AES(G) CBC(G) 256 e cd-ablk", "cryptd(cbc(aes-generic))", 32, 1 },
	{ "AES(G) CBC(G) 128 d cd-ablk", "cryptd(cbc(aes-generic))", 16, 0 },
	{ "AES(G) CBC(G) 192 d cd-ablk", "cryptd(cbc(aes-generic))", 24, 0 },
	{ "AES(G) CBC(G) 256 d cd-ablk", "cryptd(cbc(aes-generic))", 32, 0 },
	{ "AES(AESNI) CBC(ASM) 128 e ablk", "cbc-aes-aesni", 16, 1 },
	{ "AES(AESNI) CBC(ASM) 192 e ablk", "cbc-aes-aesni", 24, 1 },
	{ "AES(AESNI) CBC(ASM) 256 e ablk", "cbc-aes-aesni", 32, 1 },
	{ "AES(AESNI) CBC(ASM) 128 d ablk", "cbc-aes-aesni", 16, 0 },
	{ "AES(AESNI) CBC(ASM) 192 d ablk", "cbc-aes-aesni", 24, 0 },
	{ "AES(AESNI) CBC(ASM) 256 d ablk", "cbc-aes-aesni", 32, 0 },
	{ "AES(AESNI) CBC(ASM) 128 e cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 16, 1 },
	{ "AES(AESNI) CBC(ASM) 192 e cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 24, 1 },
	{ "AES(AESNI) CBC(ASM) 256 e cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 32, 1 },
	{ "AES(AESNI) CBC(ASM) 128 d cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 16, 0 },
	{ "AES(AESNI) CBC(ASM) 192 d cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 24, 0 },
	{ "AES(AESNI) CBC(ASM) 256 d cd-ablk", "cryptd(__driver-cbc-aes-aesni)", 32, 0 },
	{ "AES(AESNI) CBC(G) 128 e cd-ablk", "cryptd(cbc(aes-aesni))", 16, 1 },
	{ "AES(AESNI) CBC(G) 192 e cd-ablk", "cryptd(cbc(aes-aesni))", 24, 1 },
	{ "AES(AESNI) CBC(G) 256 e cd-ablk", "cryptd(cbc(aes-aesni))", 32, 1 },
	{ "AES(AESNI) CBC(G) 128 d cd-ablk", "cryptd(cbc(aes-aesni))", 16, 0 },
	{ "AES(AESNI) CBC(G) 192 d cd-ablk", "cryptd(cbc(aes-aesni))", 24, 0 },
	{ "AES(AESNI) CBC(G) 256 d cd-ablk", "cryptd(cbc(aes-aesni))", 32, 0 },
	{ "AES(i586) CBC(G) 128 e cd-ablk", "cryptd(cbc(aes-asm))", 16, 1 },
	{ "AES(i586) CBC(G) 192 e cd-ablk", "cryptd(cbc(aes-asm))", 24, 1 },
	{ "AES(i586) CBC(G) 256 e cd-ablk", "cryptd(cbc(aes-asm))", 32, 1 },
	{ "AES(i586) CBC(G) 128 d cd-ablk", "cryptd(cbc(aes-asm))", 16, 0 },
	{ "AES(i586) CBC(G) 192 d cd-ablk", "cryptd(cbc(aes-asm))", 24, 0 },
	{ "AES(i586) CBC(G) 256 d cd-ablk", "cryptd(cbc(aes-asm))", 32, 0 },

	{ "AES(G) CTR(G) 128 e cd-ablk", "cryptd(ctr(aes-generic))", 16, 1 },
	{ "AES(G) CTR(G) 192 e cd-ablk", "cryptd(ctr(aes-generic))", 24, 1 },
	{ "AES(G) CTR(G) 256 e cd-ablk", "cryptd(ctr(aes-generic))", 32, 1 },
	{ "AES(G) CTR(G) 128 d cd-ablk", "cryptd(ctr(aes-generic))", 16, 0 },
	{ "AES(G) CTR(G) 192 d cd-ablk", "cryptd(ctr(aes-generic))", 24, 0 },
	{ "AES(G) CTR(G) 256 d cd-ablk", "cryptd(ctr(aes-generic))", 32, 0 },
	{ "AES(AESNI) CTR(ASM) 128 e cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 16, 1 },
	{ "AES(AESNI) CTR(ASM) 192 e cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 24, 1 },
	{ "AES(AESNI) CTR(ASM) 256 e cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 32, 1 },
	{ "AES(AESNI) CTR(ASM) 128 d cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 16, 0 },
	{ "AES(AESNI) CTR(ASM) 192 d cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 24, 0 },
	{ "AES(AESNI) CTR(ASM) 256 d cd-ablk", "cryptd(__driver-ctr-aes-aesni)", 32, 0 },
	{ "AES(AESNI) CTR(ASM) 128 e ablk", "ctr-aes-aesni", 16, 1 },
	{ "AES(AESNI) CTR(ASM) 192 e ablk", "ctr-aes-aesni", 24, 1 },
	{ "AES(AESNI) CTR(ASM) 256 e ablk", "ctr-aes-aesni", 32, 1 },
	{ "AES(AESNI) CTR(ASM) 128 d ablk", "ctr-aes-aesni", 16, 0 },
	{ "AES(AESNI) CTR(ASM) 192 d ablk", "ctr-aes-aesni", 24, 0 },
	{ "AES(AESNI) CTR(ASM) 256 d ablk", "ctr-aes-aesni", 32, 0 },
	{ "AES(AESNI) CTR(G) 128 e cd-ablk", "cryptd(ctr(aes-aesni))", 16, 1 },
	{ "AES(AESNI) CTR(G) 192 e cd-ablk", "cryptd(ctr(aes-aesni))", 24, 1 },
	{ "AES(AESNI) CTR(G) 256 e cd-ablk", "cryptd(ctr(aes-aesni))", 32, 1 },
	{ "AES(AESNI) CTR(G) 128 d cd-ablk", "cryptd(ctr(aes-aesni))", 16, 0 },
	{ "AES(AESNI) CTR(G) 192 d cd-ablk", "cryptd(ctr(aes-aesni))", 24, 0 },
	{ "AES(AESNI) CTR(G) 256 d cd-ablk", "cryptd(ctr(aes-aesni))", 32, 0 },
	{ "AES(i586) CTR(G) 128 e cd-ablk", "cryptd(ctr(aes-asm))", 16, 1 },
	{ "AES(i586) CTR(G) 192 e cd-ablk", "cryptd(ctr(aes-asm))", 24, 1 },
	{ "AES(i586) CTR(G) 256 e cd-ablk", "cryptd(ctr(aes-asm))", 32, 1 },
	{ "AES(i586) CTR(G) 128 d cd-ablk", "cryptd(ctr(aes-asm))", 16, 0 },
	{ "AES(i586) CTR(G) 192 d cd-ablk", "cryptd(ctr(aes-asm))", 24, 0 },
	{ "AES(i586) CTR(G) 256 d cd-ablk", "cryptd(ctr(aes-asm))", 32, 0 },

	{ "AES(G) XTS(G) 128 e cd-ablk", "cryptd(xts(aes-generic))", 32, 1 },
	{ "AES(G) XTS(G) 192 e cd-ablk", "cryptd(xts(aes-generic))", 48, 1 },
	{ "AES(G) XTS(G) 256 e cd-ablk", "cryptd(xts(aes-generic))", 64, 1 },
	{ "AES(G) XTS(G) 128 d cd-ablk", "cryptd(xts(aes-generic))", 32, 0 },
	{ "AES(G) XTS(G) 192 d cd-ablk", "cryptd(xts(aes-generic))", 48, 0 },
	{ "AES(G) XTS(G) 256 d cd-ablk", "cryptd(xts(aes-generic))", 64, 0 },
	{ "AES(AESNI) XTS(ASM) 128 e cd-ablk", "cryptd(__driver-xts-aes-aesni)", 32, 1 },
	{ "AES(AESNI) XTS(ASM) 192 e cd-ablk", "cryptd(__driver-xts-aes-aesni)", 48, 1 },
	{ "AES(AESNI) XTS(ASM) 256 e cd-ablk", "cryptd(__driver-xts-aes-aesni)", 64, 1 },
	{ "AES(AESNI) XTS(ASM) 128 d cd-ablk", "cryptd(__driver-xts-aes-aesni)", 32, 0 },
	{ "AES(AESNI) XTS(ASM) 192 d cd-ablk", "cryptd(__driver-xts-aes-aesni)", 48, 0 },
	{ "AES(AESNI) XTS(ASM) 256 d cd-ablk", "cryptd(__driver-xts-aes-aesni)", 64, 0 },
	{ "AES(AESNI) XTS(ASM) 128 e ablk", "xts-aes-aesni", 32, 1 },
	{ "AES(AESNI) XTS(ASM) 192 e ablk", "xts-aes-aesni", 48, 1 },
	{ "AES(AESNI) XTS(ASM) 256 e ablk", "xts-aes-aesni", 64, 1 },
	{ "AES(AESNI) XTS(ASM) 128 d ablk", "xts-aes-aesni", 32, 0 },
	{ "AES(AESNI) XTS(ASM) 192 d ablk", "xts-aes-aesni", 48, 0 },
	{ "AES(AESNI) XTS(ASM) 256 d ablk", "xts-aes-aesni", 64, 0 },
	{ "AES(AESNI) XTS(G) 128 e cd-ablk", "cryptd(xts(aes-aesni))", 32, 1 },
	{ "AES(AESNI) XTS(G) 192 e cd-ablk", "cryptd(xts(aes-aesni))", 48, 1 },
	{ "AES(AESNI) XTS(G) 256 e cd-ablk", "cryptd(xts(aes-aesni))", 64, 1 },
	{ "AES(AESNI) XTS(G) 128 d cd-ablk", "cryptd(xts(aes-aesni))", 32, 0 },
	{ "AES(AESNI) XTS(G) 192 d cd-ablk", "cryptd(xts(aes-aesni))", 48, 0 },
	{ "AES(AESNI) XTS(G) 256 d cd-ablk", "cryptd(xts(aes-aesni))", 64, 0 },
	{ "AES(i586) XTS(G) 128 e cd-ablk", "cryptd(xts(aes-asm))", 32, 1 },
	{ "AES(i586) XTS(G) 192 e cd-ablk", "cryptd(xts(aes-asm))", 48, 1 },
	{ "AES(i586) XTS(G) 256 e cd-ablk", "cryptd(xts(aes-asm))", 64, 1 },
	{ "AES(i586) XTS(G) 128 d cd-ablk", "cryptd(xts(aes-asm))", 32, 0 },
	{ "AES(i586) XTS(G) 192 d cd-ablk", "cryptd(xts(aes-asm))", 48, 0 },
	{ "AES(i586) XTS(G) 256 d cd-ablk", "cryptd(xts(aes-asm))", 64, 0 },

	{ "AES(G) LRW(G) 128 e cd-ablk", "cryptd(lrw(aes-generic))", 32, 1 },
	{ "AES(G) LRW(G) 192 e cd-ablk", "cryptd(lrw(aes-generic))", 40, 1 },
	{ "AES(G) LRW(G) 256 e cd-ablk", "cryptd(lrw(aes-generic))", 48, 1 },
	{ "AES(G) LRW(G) 128 d cd-ablk", "cryptd(lrw(aes-generic))", 32, 0 },
	{ "AES(G) LRW(G) 192 d cd-ablk", "cryptd(lrw(aes-generic))", 40, 0 },
	{ "AES(G) LRW(G) 256 d cd-ablk", "cryptd(lrw(aes-generic))", 48, 0 },
	{ "AES(AESNI) LRW(ASM) 128 e cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 32, 1 },
	{ "AES(AESNI) LRW(ASM) 192 e cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 40, 1 },
	{ "AES(AESNI) LRW(ASM) 256 e cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 48, 1 },
	{ "AES(AESNI) LRW(ASM) 128 d cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 32, 0 },
	{ "AES(AESNI) LRW(ASM) 192 d cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 40, 0 },
	{ "AES(AESNI) LRW(ASM) 256 d cd-ablk", "cryptd(__driver-lrw-aes-aesni)", 48, 0 },
	{ "AES(AESNI) LRW(ASM) 128 e ablk", "lrw-aes-aesni", 32, 1 },
	{ "AES(AESNI) LRW(ASM) 192 e ablk", "lrw-aes-aesni", 40, 1 },
	{ "AES(AESNI) LRW(ASM) 256 e ablk", "lrw-aes-aesni", 48, 1 },
	{ "AES(AESNI) LRW(ASM) 128 d ablk", "lrw-aes-aesni", 32, 0 },
	{ "AES(AESNI) LRW(ASM) 192 d ablk", "lrw-aes-aesni", 40, 0 },
	{ "AES(AESNI) LRW(ASM) 256 d ablk", "lrw-aes-aesni", 48, 0 },
	{ "AES(AESNI) LRW(G) 128 e cd-ablk", "cryptd(lrw(aes-aesni))", 32, 1 },
	{ "AES(AESNI) LRW(G) 192 e cd-ablk", "cryptd(lrw(aes-aesni))", 40, 1 },
	{ "AES(AESNI) LRW(G) 256 e cd-ablk", "cryptd(lrw(aes-aesni))", 48, 1 },
	{ "AES(AESNI) LRW(G) 128 d cd-ablk", "cryptd(lrw(aes-aesni))", 32, 0 },
	{ "AES(AESNI) LRW(G) 192 d cd-ablk", "cryptd(lrw(aes-aesni))", 40, 0 },
	{ "AES(AESNI) LRW(G) 256 d cd-ablk", "cryptd(lrw(aes-aesni))", 48, 0 },
	{ "AES(i586) LRW(G) 128 e cd-ablk", "cryptd(lrw(aes-asm))", 32, 1 },
	{ "AES(i586) LRW(G) 192 e cd-ablk", "cryptd(lrw(aes-asm))", 40, 1 },
	{ "AES(i586) LRW(G) 256 e cd-ablk", "cryptd(lrw(aes-asm))", 48, 1 },
	{ "AES(i586) LRW(G) 128 d cd-ablk", "cryptd(lrw(aes-asm))", 32, 0 },
	{ "AES(i586) LRW(G) 192 d cd-ablk", "cryptd(lrw(aes-asm))", 40, 0 },
	{ "AES(i586) LRW(G) 256 d cd-ablk", "cryptd(lrw(aes-asm))", 48, 0 },

	{ "AES(G) ECB(G) 128 e cd-ablk", "cryptd(ecb(aes-generic))", 16, 1 },
	{ "AES(G) ECB(G) 192 e cd-ablk", "cryptd(ecb(aes-generic))", 24, 1 },
	{ "AES(G) ECB(G) 256 e cd-ablk", "cryptd(ecb(aes-generic))", 32, 1 },
	{ "AES(G) ECB(G) 128 d cd-ablk", "cryptd(ecb(aes-generic))", 16, 0 },
	{ "AES(G) ECB(G) 192 d cd-ablk", "cryptd(ecb(aes-generic))", 24, 0 },
	{ "AES(G) ECB(G) 256 d cd-ablk", "cryptd(ecb(aes-generic))", 32, 0 },
	{ "AES(AESNI) ECB(ASM) 128 e cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 16, 1 },
	{ "AES(AESNI) ECB(ASM) 192 e cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 24, 1 },
	{ "AES(AESNI) ECB(ASM) 256 e cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 32, 1 },
	{ "AES(AESNI) ECB(ASM) 128 d cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 16, 0 },
	{ "AES(AESNI) ECB(ASM) 192 d cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 24, 0 },
	{ "AES(AESNI) ECB(ASM) 256 d cd-ablk", "cryptd(__driver-ecb-aes-aesni)", 32, 0 },
	{ "AES(AESNI) ECB(ASM) 128 e ablk", "ecb-aes-aesni", 16, 1 },
	{ "AES(AESNI) ECB(ASM) 192 e ablk", "ecb-aes-aesni", 24, 1 },
	{ "AES(AESNI) ECB(ASM) 256 e ablk", "ecb-aes-aesni", 32, 1 },
	{ "AES(AESNI) ECB(ASM) 128 d ablk", "ecb-aes-aesni", 16, 0 },
	{ "AES(AESNI) ECB(ASM) 192 d ablk", "ecb-aes-aesni", 24, 0 },
	{ "AES(AESNI) ECB(ASM) 256 d ablk", "ecb-aes-aesni", 32, 0 },
	{ "AES(AESNI) ECB(G) 128 e cd-ablk", "cryptd(ecb(aes-aesni))", 16, 1 },
	{ "AES(AESNI) ECB(G) 192 e cd-ablk", "cryptd(ecb(aes-aesni))", 24, 1 },
	{ "AES(AESNI) ECB(G) 256 e cd-ablk", "cryptd(ecb(aes-aesni))", 32, 1 },
	{ "AES(AESNI) ECB(G) 128 d cd-ablk", "cryptd(ecb(aes-aesni))", 16, 0 },
	{ "AES(AESNI) ECB(G) 192 d cd-ablk", "cryptd(ecb(aes-aesni))", 24, 0 },
	{ "AES(AESNI) ECB(G) 256 d cd-ablk", "cryptd(ecb(aes-aesni))", 32, 0 },
	{ "AES(i586) ECB(G) 128 e cd-ablk", "cryptd(ecb(aes-asm))", 16, 1 },
	{ "AES(i586) ECB(G) 192 e cd-ablk", "cryptd(ecb(aes-asm))", 24, 1 },
	{ "AES(i586) ECB(G) 256 e cd-ablk", "cryptd(ecb(aes-asm))", 32, 1 },
	{ "AES(i586) ECB(G) 128 d cd-ablk", "cryptd(ecb(aes-asm))", 16, 0 },
	{ "AES(i586) ECB(G) 192 d cd-ablk", "cryptd(ecb(aes-asm))", 24, 0 },
	{ "AES(i586) ECB(G) 256 d cd-ablk", "cryptd(ecb(aes-asm))", 32, 0 },

	{ "Serpent(AVX) XTS(AVX) 128 e cd-ablk", "cryptd(__driver-xts-serpent-avx)", 32, 1 },
	{ "Serpent(AVX) XTS(AVX) 192 e cd-ablk", "cryptd(__driver-xts-serpent-avx)", 48, 1 },
	{ "Serpent(AVX) XTS(AVX) 256 e cd-ablk", "cryptd(__driver-xts-serpent-avx)", 64, 1 },
	{ "Serpent(AVX) XTS(AVX) 128 d cd-ablk", "cryptd(__driver-xts-serpent-avx)", 32, 0 },
	{ "Serpent(AVX) XTS(AVX) 192 d cd-ablk", "cryptd(__driver-xts-serpent-avx)", 48, 0 },
	{ "Serpent(AVX) XTS(AVX) 256 d cd-ablk", "cryptd(__driver-xts-serpent-avx)", 64, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 128 e cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 32, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 192 e cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 48, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 256 e cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 64, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 128 d cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 32, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 192 d cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 48, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 256 d cd-ablk", "cryptd(__driver-xts-serpent-avx2)", 64, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 128 e cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 32, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 192 e cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 48, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 256 e cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 64, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 128 d cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 32, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 192 d cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 48, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 256 d cd-ablk", "cryptd(__driver-xts-serpent-sse2)", 64, 0 },
	{ "Serpent(AVX) XTS(AVX) 128 e ablk", "xts-serpent-avx", 32, 1 },
	{ "Serpent(AVX) XTS(AVX) 192 e ablk", "xts-serpent-avx", 48, 1 },
	{ "Serpent(AVX) XTS(AVX) 256 e ablk", "xts-serpent-avx", 64, 1 },
	{ "Serpent(AVX) XTS(AVX) 128 d ablk", "xts-serpent-avx", 32, 0 },
	{ "Serpent(AVX) XTS(AVX) 192 d ablk", "xts-serpent-avx", 48, 0 },
	{ "Serpent(AVX) XTS(AVX) 256 d ablk", "xts-serpent-avx", 64, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 128 e ablk", "xts-serpent-avx2", 32, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 192 e ablk", "xts-serpent-avx2", 48, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 256 e ablk", "xts-serpent-avx2", 64, 1 },
	{ "Serpent(AVX2) XTS(AVX2) 128 d ablk", "xts-serpent-avx2", 32, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 192 d ablk", "xts-serpent-avx2", 48, 0 },
	{ "Serpent(AVX2) XTS(AVX2) 256 d ablk", "xts-serpent-avx2", 64, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 128 e ablk", "xts-serpent-sse2", 32, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 192 e ablk", "xts-serpent-sse2", 48, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 256 e ablk", "xts-serpent-sse2", 64, 1 },
	{ "Serpent(SSE2) XTS(SSE2) 128 d ablk", "xts-serpent-sse2", 32, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 192 d ablk", "xts-serpent-sse2", 48, 0 },
	{ "Serpent(SSE2) XTS(SSE2) 256 d ablk", "xts-serpent-sse2", 64, 0 },
	{ "Serpent(G) XTS(G) 128 e cd-ablk", "cryptd(xts(serpent-generic))", 32, 1 },
	{ "Serpent(G) XTS(G) 192 e cd-ablk", "cryptd(xts(serpent-generic))", 48, 1 },
	{ "Serpent(G) XTS(G) 256 e cd-ablk", "cryptd(xts(serpent-generic))", 64, 1 },
	{ "Serpent(G) XTS(G) 128 d cd-ablk", "cryptd(xts(serpent-generic))", 32, 0 },
	{ "Serpent(G) XTS(G) 192 d cd-ablk", "cryptd(xts(serpent-generic))", 48, 0 },
	{ "Serpent(G) XTS(G) 256 d cd-ablk", "cryptd(xts(serpent-generic))", 64, 0 },

	{ "Serpent(AVX) LRW(AVX) 128 e cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 32, 1 },
	{ "Serpent(AVX) LRW(AVX) 192 e cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 40, 1 },
	{ "Serpent(AVX) LRW(AVX) 256 e cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 48, 1 },
	{ "Serpent(AVX) LRW(AVX) 128 d cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 32, 0 },
	{ "Serpent(AVX) LRW(AVX) 192 d cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 40, 0 },
	{ "Serpent(AVX) LRW(AVX) 256 d cd-ablk", "cryptd(__driver-lrw-serpent-avx)", 48, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 128 e cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 32, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 192 e cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 40, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 256 e cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 48, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 128 d cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 32, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 192 d cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 40, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 256 d cd-ablk", "cryptd(__driver-lrw-serpent-avx2)", 48, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 128 e cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 32, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 192 e cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 40, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 256 e cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 48, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 128 d cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 32, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 192 d cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 40, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 256 d cd-ablk", "cryptd(__driver-lrw-serpent-sse2)", 48, 0 },
	{ "Serpent(AVX) LRW(AVX) 128 e ablk", "lrw-serpent-avx", 32, 1 },
	{ "Serpent(AVX) LRW(AVX) 192 e ablk", "lrw-serpent-avx", 40, 1 },
	{ "Serpent(AVX) LRW(AVX) 256 e ablk", "lrw-serpent-avx", 48, 1 },
	{ "Serpent(AVX) LRW(AVX) 128 d ablk", "lrw-serpent-avx", 32, 0 },
	{ "Serpent(AVX) LRW(AVX) 192 d ablk", "lrw-serpent-avx", 40, 0 },
	{ "Serpent(AVX) LRW(AVX) 256 d ablk", "lrw-serpent-avx", 48, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 128 e ablk", "lrw-serpent-avx2", 32, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 192 e ablk", "lrw-serpent-avx2", 40, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 256 e ablk", "lrw-serpent-avx2", 48, 1 },
	{ "Serpent(AVX2) LRW(AVX2) 128 d ablk", "lrw-serpent-avx2", 32, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 192 d ablk", "lrw-serpent-avx2", 40, 0 },
	{ "Serpent(AVX2) LRW(AVX2) 256 d ablk", "lrw-serpent-avx2", 48, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 128 e ablk", "lrw-serpent-sse2", 32, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 192 e ablk", "lrw-serpent-sse2", 40, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 256 e ablk", "lrw-serpent-sse2", 48, 1 },
	{ "Serpent(SSE2) LRW(SSE2) 128 d ablk", "lrw-serpent-sse2", 32, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 192 d ablk", "lrw-serpent-sse2", 40, 0 },
	{ "Serpent(SSE2) LRW(SSE2) 256 d ablk", "lrw-serpent-sse2", 48, 0 },
	{ "Serpent(G) LRW(G) 128 e cd-ablk", "cryptd(lrw(serpent-generic))", 32, 1 },
	{ "Serpent(G) LRW(G) 192 e cd-ablk", "cryptd(lrw(serpent-generic))", 40, 1 },
	{ "Serpent(G) LRW(G) 256 e cd-ablk", "cryptd(lrw(serpent-generic))", 48, 1 },
	{ "Serpent(G) LRW(G) 128 d cd-ablk", "cryptd(lrw(serpent-generic))", 32, 0 },
	{ "Serpent(G) LRW(G) 192 d cd-ablk", "cryptd(lrw(serpent-generic))", 40, 0 },
	{ "Serpent(G) LRW(G) 256 d cd-ablk", "cryptd(lrw(serpent-generic))", 48, 0 },

	{ "Serpent(AVX) CTR(AVX) 128 e cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 16, 1 },
	{ "Serpent(AVX) CTR(AVX) 192 e cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 24, 1 },
	{ "Serpent(AVX) CTR(AVX) 256 e cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 32, 1 },
	{ "Serpent(AVX) CTR(AVX) 128 d cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 16, 0 },
	{ "Serpent(AVX) CTR(AVX) 192 d cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 24, 0 },
	{ "Serpent(AVX) CTR(AVX) 256 d cd-ablk", "cryptd(__driver-ctr-serpent-avx)", 32, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 128 e cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 16, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 192 e cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 24, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 256 e cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 32, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 128 d cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 16, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 192 d cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 24, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 256 d cd-ablk", "cryptd(__driver-ctr-serpent-avx2)", 32, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 128 e cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 16, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 192 e cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 24, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 256 e cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 32, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 128 d cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 16, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 192 d cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 24, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 256 d cd-ablk", "cryptd(__driver-ctr-serpent-sse2)", 32, 0 },
	{ "Serpent(AVX) CTR(AVX) 128 e ablk", "ctr-serpent-avx", 16, 1 },
	{ "Serpent(AVX) CTR(AVX) 192 e ablk", "ctr-serpent-avx", 24, 1 },
	{ "Serpent(AVX) CTR(AVX) 256 e ablk", "ctr-serpent-avx", 32, 1 },
	{ "Serpent(AVX) CTR(AVX) 128 d ablk", "ctr-serpent-avx", 16, 0 },
	{ "Serpent(AVX) CTR(AVX) 192 d ablk", "ctr-serpent-avx", 24, 0 },
	{ "Serpent(AVX) CTR(AVX) 256 d ablk", "ctr-serpent-avx", 32, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 128 e ablk", "ctr-serpent-avx2", 16, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 192 e ablk", "ctr-serpent-avx2", 24, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 256 e ablk", "ctr-serpent-avx2", 32, 1 },
	{ "Serpent(AVX2) CTR(AVX2) 128 d ablk", "ctr-serpent-avx2", 16, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 192 d ablk", "ctr-serpent-avx2", 24, 0 },
	{ "Serpent(AVX2) CTR(AVX2) 256 d ablk", "ctr-serpent-avx2", 32, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 128 e ablk", "ctr-serpent-sse2", 16, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 192 e ablk", "ctr-serpent-sse2", 24, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 256 e ablk", "ctr-serpent-sse2", 32, 1 },
	{ "Serpent(SSE2) CTR(SSE2) 128 d ablk", "ctr-serpent-sse2", 16, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 192 d ablk", "ctr-serpent-sse2", 24, 0 },
	{ "Serpent(SSE2) CTR(SSE2) 256 d ablk", "ctr-serpent-sse2", 32, 0 },
	{ "Serpent(G) CTR(G) 128 e cd-ablk", "cryptd(ctr(serpent-generic))", 16, 1 },
	{ "Serpent(G) CTR(G) 192 e cd-ablk", "cryptd(ctr(serpent-generic))", 24, 1 },
	{ "Serpent(G) CTR(G) 256 e cd-ablk", "cryptd(ctr(serpent-generic))", 32, 1 },
	{ "Serpent(G) CTR(G) 128 d cd-ablk", "cryptd(ctr(serpent-generic))", 16, 0 },
	{ "Serpent(G) CTR(G) 192 d cd-ablk", "cryptd(ctr(serpent-generic))", 24, 0 },
	{ "Serpent(G) CTR(G) 256 d cd-ablk", "cryptd(ctr(serpent-generic))", 32, 0 },

	{ "Serpent(AVX) CBC(AVX) 128 e cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 16, 1 },
	{ "Serpent(AVX) CBC(AVX) 192 e cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 24, 1 },
	{ "Serpent(AVX) CBC(AVX) 256 e cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 32, 1 },
	{ "Serpent(AVX) CBC(AVX) 128 d cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 16, 0 },
	{ "Serpent(AVX) CBC(AVX) 192 d cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 24, 0 },
	{ "Serpent(AVX) CBC(AVX) 256 d cd-ablk", "cryptd(__driver-cbc-serpent-avx)", 32, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 128 e cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 16, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 192 e cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 24, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 256 e cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 32, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 128 d cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 16, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 192 d cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 24, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 256 d cd-ablk", "cryptd(__driver-cbc-serpent-avx2)", 32, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 128 e cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 16, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 192 e cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 24, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 256 e cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 32, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 128 d cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 16, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 192 d cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 24, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 256 d cd-ablk", "cryptd(__driver-cbc-serpent-sse2)", 32, 0 },
	{ "Serpent(AVX) CBC(AVX) 128 e ablk", "cbc-serpent-avx", 16, 1 },
	{ "Serpent(AVX) CBC(AVX) 192 e ablk", "cbc-serpent-avx", 24, 1 },
	{ "Serpent(AVX) CBC(AVX) 256 e ablk", "cbc-serpent-avx", 32, 1 },
	{ "Serpent(AVX) CBC(AVX) 128 d ablk", "cbc-serpent-avx", 16, 0 },
	{ "Serpent(AVX) CBC(AVX) 192 d ablk", "cbc-serpent-avx", 24, 0 },
	{ "Serpent(AVX) CBC(AVX) 256 d ablk", "cbc-serpent-avx", 32, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 128 e ablk", "cbc-serpent-avx2", 16, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 192 e ablk", "cbc-serpent-avx2", 24, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 256 e ablk", "cbc-serpent-avx2", 32, 1 },
	{ "Serpent(AVX2) CBC(AVX2) 128 d ablk", "cbc-serpent-avx2", 16, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 192 d ablk", "cbc-serpent-avx2", 24, 0 },
	{ "Serpent(AVX2) CBC(AVX2) 256 d ablk", "cbc-serpent-avx2", 32, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 128 e ablk", "cbc-serpent-sse2", 16, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 192 e ablk", "cbc-serpent-sse2", 24, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 256 e ablk", "cbc-serpent-sse2", 32, 1 },
	{ "Serpent(SSE2) CBC(SSE2) 128 d ablk", "cbc-serpent-sse2", 16, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 192 d ablk", "cbc-serpent-sse2", 24, 0 },
	{ "Serpent(SSE2) CBC(SSE2) 256 d ablk", "cbc-serpent-sse2", 32, 0 },
	{ "Serpent(G) CBC(G) 128 e cd-ablk", "cryptd(cbc(serpent-generic))", 16, 1 },
	{ "Serpent(G) CBC(G) 192 e cd-ablk", "cryptd(cbc(serpent-generic))", 24, 1 },
	{ "Serpent(G) CBC(G) 256 e cd-ablk", "cryptd(cbc(serpent-generic))", 32, 1 },
	{ "Serpent(G) CBC(G) 128 d cd-ablk", "cryptd(cbc(serpent-generic))", 16, 0 },
	{ "Serpent(G) CBC(G) 192 d cd-ablk", "cryptd(cbc(serpent-generic))", 24, 0 },
	{ "Serpent(G) CBC(G) 256 d cd-ablk", "cryptd(cbc(serpent-generic))", 32, 0 },

	{ "Serpent(AVX) ECB(AVX) 128 e cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 16, 1 },
	{ "Serpent(AVX) ECB(AVX) 192 e cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 24, 1 },
	{ "Serpent(AVX) ECB(AVX) 256 e cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 32, 1 },
	{ "Serpent(AVX) ECB(AVX) 128 d cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 16, 0 },
	{ "Serpent(AVX) ECB(AVX) 192 d cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 24, 0 },
	{ "Serpent(AVX) ECB(AVX) 256 d cd-ablk", "cryptd(__driver-ecb-serpent-avx)", 32, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 128 e cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 16, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 192 e cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 24, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 256 e cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 32, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 128 d cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 16, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 192 d cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 24, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 256 d cd-ablk", "cryptd(__driver-ecb-serpent-avx2)", 32, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 128 e cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 16, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 192 e cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 24, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 256 e cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 32, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 128 d cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 16, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 192 d cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 24, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 256 d cd-ablk", "cryptd(__driver-ecb-serpent-sse2)", 32, 0 },
	{ "Serpent(AVX) ECB(AVX) 128 e ablk", "ecb-serpent-avx", 16, 1 },
	{ "Serpent(AVX) ECB(AVX) 192 e ablk", "ecb-serpent-avx", 24, 1 },
	{ "Serpent(AVX) ECB(AVX) 256 e ablk", "ecb-serpent-avx", 32, 1 },
	{ "Serpent(AVX) ECB(AVX) 128 d ablk", "ecb-serpent-avx", 16, 0 },
	{ "Serpent(AVX) ECB(AVX) 192 d ablk", "ecb-serpent-avx", 24, 0 },
	{ "Serpent(AVX) ECB(AVX) 256 d ablk", "ecb-serpent-avx", 32, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 128 e ablk", "ecb-serpent-avx2", 16, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 192 e ablk", "ecb-serpent-avx2", 24, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 256 e ablk", "ecb-serpent-avx2", 32, 1 },
	{ "Serpent(AVX2) ECB(AVX2) 128 d ablk", "ecb-serpent-avx2", 16, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 192 d ablk", "ecb-serpent-avx2", 24, 0 },
	{ "Serpent(AVX2) ECB(AVX2) 256 d ablk", "ecb-serpent-avx2", 32, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 128 e ablk", "ecb-serpent-sse2", 16, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 192 e ablk", "ecb-serpent-sse2", 24, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 256 e ablk", "ecb-serpent-sse2", 32, 1 },
	{ "Serpent(SSE2) ECB(SSE2) 128 d ablk", "ecb-serpent-sse2", 16, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 192 d ablk", "ecb-serpent-sse2", 24, 0 },
	{ "Serpent(SSE2) ECB(SSE2) 256 d ablk", "ecb-serpent-sse2", 32, 0 },
	{ "Serpent(G) ECB(G) 128 e cd-ablk", "cryptd(ecb(serpent-generic))", 16, 1 },
	{ "Serpent(G) ECB(G) 192 e cd-ablk", "cryptd(ecb(serpent-generic))", 24, 1 },
	{ "Serpent(G) ECB(G) 256 e cd-ablk", "cryptd(ecb(serpent-generic))", 32, 1 },
	{ "Serpent(G) ECB(G) 128 d cd-ablk", "cryptd(ecb(serpent-generic))", 16, 0 },
	{ "Serpent(G) ECB(G) 192 d cd-ablk", "cryptd(ecb(serpent-generic))", 24, 0 },
	{ "Serpent(G) ECB(G) 256 d cd-ablk", "cryptd(ecb(serpent-generic))", 32, 0 },

	{ "Blowfish(G) ECB(G) 128 e cd-ablk", "cryptd(ecb(blowfish-generic))", 16, 1 },
	{ "Blowfish(G) ECB(G) 192 e cd-ablk", "cryptd(ecb(blowfish-generic))", 24, 1 },
	{ "Blowfish(G) ECB(G) 256 e cd-ablk", "cryptd(ecb(blowfish-generic))", 32, 1 },
	{ "Blowfish(G) ECB(G) 128 d cd-ablk", "cryptd(ecb(blowfish-generic))", 16, 0 },
	{ "Blowfish(G) ECB(G) 192 d cd-ablk", "cryptd(ecb(blowfish-generic))", 24, 0 },
	{ "Blowfish(G) ECB(G) 256 d cd-ablk", "cryptd(ecb(blowfish-generic))", 32, 0 },
	{ "Blowfish(x86_64) ECB(G) 128 e cd-ablk", "cryptd(ecb(blowfish-asm))", 16, 1 },
	{ "Blowfish(x86_64) ECB(G) 192 e cd-ablk", "cryptd(ecb(blowfish-asm))", 24, 1 },
	{ "Blowfish(x86_64) ECB(G) 256 e cd-ablk", "cryptd(ecb(blowfish-asm))", 32, 1 },
	{ "Blowfish(x86_64) ECB(G) 128 d cd-ablk", "cryptd(ecb(blowfish-asm))", 16, 0 },
	{ "Blowfish(x86_64) ECB(G) 192 d cd-ablk", "cryptd(ecb(blowfish-asm))", 24, 0 },
	{ "Blowfish(x86_64) ECB(G) 256 d cd-ablk", "cryptd(ecb(blowfish-asm))", 32, 0 },
	{ "Blowfish(x86_64) ECB(x86_64) 128 e cd-ablk", "cryptd(ecb-blowfish-asm)", 16, 1 },
	{ "Blowfish(x86_64) ECB(x86_64) 192 e cd-ablk", "cryptd(ecb-blowfish-asm)", 24, 1 },
	{ "Blowfish(x86_64) ECB(x86_64) 256 e cd-ablk", "cryptd(ecb-blowfish-asm)", 32, 1 },
	{ "Blowfish(x86_64) ECB(x86_64) 128 d cd-ablk", "cryptd(ecb-blowfish-asm)", 16, 0 },
	{ "Blowfish(x86_64) ECB(x86_64) 192 d cd-ablk", "cryptd(ecb-blowfish-asm)", 24, 0 },
	{ "Blowfish(x86_64) ECB(x86_64) 256 d cd-ablk", "cryptd(ecb-blowfish-asm)", 32, 0 },

	{ "Blowfish(G) CBC(G) 128 e cd-ablk", "cryptd(cbc(blowfish-generic))", 16, 1 },
	{ "Blowfish(G) CBC(G) 192 e cd-ablk", "cryptd(cbc(blowfish-generic))", 24, 1 },
	{ "Blowfish(G) CBC(G) 256 e cd-ablk", "cryptd(cbc(blowfish-generic))", 32, 1 },
	{ "Blowfish(G) CBC(G) 128 d cd-ablk", "cryptd(cbc(blowfish-generic))", 16, 0 },
	{ "Blowfish(G) CBC(G) 192 d cd-ablk", "cryptd(cbc(blowfish-generic))", 24, 0 },
	{ "Blowfish(G) CBC(G) 256 d cd-ablk", "cryptd(cbc(blowfish-generic))", 32, 0 },
	{ "Blowfish(x86_64) CBC(G) 128 e cd-ablk", "cryptd(cbc(blowfish-asm))", 16, 1 },
	{ "Blowfish(x86_64) CBC(G) 192 e cd-ablk", "cryptd(cbc(blowfish-asm))", 24, 1 },
	{ "Blowfish(x86_64) CBC(G) 256 e cd-ablk", "cryptd(cbc(blowfish-asm))", 32, 1 },
	{ "Blowfish(x86_64) CBC(G) 128 d cd-ablk", "cryptd(cbc(blowfish-asm))", 16, 0 },
	{ "Blowfish(x86_64) CBC(G) 192 d cd-ablk", "cryptd(cbc(blowfish-asm))", 24, 0 },
	{ "Blowfish(x86_64) CBC(G) 256 d cd-ablk", "cryptd(cbc(blowfish-asm))", 32, 0 },
	{ "Blowfish(x86_64) CBC(x86_64) 128 e cd-ablk", "cryptd(cbc-blowfish-asm)", 16, 1 },
	{ "Blowfish(x86_64) CBC(x86_64) 192 e cd-ablk", "cryptd(cbc-blowfish-asm)", 24, 1 },
	{ "Blowfish(x86_64) CBC(x86_64) 256 e cd-ablk", "cryptd(cbc-blowfish-asm)", 32, 1 },
	{ "Blowfish(x86_64) CBC(x86_64) 128 d cd-ablk", "cryptd(cbc-blowfish-asm)", 16, 0 },
	{ "Blowfish(x86_64) CBC(x86_64) 192 d cd-ablk", "cryptd(cbc-blowfish-asm)", 24, 0 },
	{ "Blowfish(x86_64) CBC(x86_64) 256 d cd-ablk", "cryptd(cbc-blowfish-asm)", 32, 0 },

	{ "Blowfish(G) CTR(G) 128 e cd-ablk", "cryptd(ctr(blowfish-generic))", 16, 1 },
	{ "Blowfish(G) CTR(G) 192 e cd-ablk", "cryptd(ctr(blowfish-generic))", 24, 1 },
	{ "Blowfish(G) CTR(G) 256 e cd-ablk", "cryptd(ctr(blowfish-generic))", 32, 1 },
	{ "Blowfish(G) CTR(G) 128 d cd-ablk", "cryptd(ctr(blowfish-generic))", 16, 0 },
	{ "Blowfish(G) CTR(G) 192 d cd-ablk", "cryptd(ctr(blowfish-generic))", 24, 0 },
	{ "Blowfish(G) CTR(G) 256 d cd-ablk", "cryptd(ctr(blowfish-generic))", 32, 0 },
	{ "Blowfish(x86_64) CTR(G) 128 e cd-ablk", "cryptd(ctr(blowfish-asm))", 16, 1 },
	{ "Blowfish(x86_64) CTR(G) 192 e cd-ablk", "cryptd(ctr(blowfish-asm))", 24, 1 },
	{ "Blowfish(x86_64) CTR(G) 256 e cd-ablk", "cryptd(ctr(blowfish-asm))", 32, 1 },
	{ "Blowfish(x86_64) CTR(G) 128 d cd-ablk", "cryptd(ctr(blowfish-asm))", 16, 0 },
	{ "Blowfish(x86_64) CTR(G) 192 d cd-ablk", "cryptd(ctr(blowfish-asm))", 24, 0 },
	{ "Blowfish(x86_64) CTR(G) 256 d cd-ablk", "cryptd(ctr(blowfish-asm))", 32, 0 },
	{ "Blowfish(x86_64) CTR(x86_64) 128 e cd-ablk", "cryptd(ctr-blowfish-asm)", 16, 1 },
	{ "Blowfish(x86_64) CTR(x86_64) 192 e cd-ablk", "cryptd(ctr-blowfish-asm)", 24, 1 },
	{ "Blowfish(x86_64) CTR(x86_64) 256 e cd-ablk", "cryptd(ctr-blowfish-asm)", 32, 1 },
	{ "Blowfish(x86_64) CTR(x86_64) 128 d cd-ablk", "cryptd(ctr-blowfish-asm)", 16, 0 },
	{ "Blowfish(x86_64) CTR(x86_64) 192 d cd-ablk", "cryptd(ctr-blowfish-asm)", 24, 0 },
	{ "Blowfish(x86_64) CTR(x86_64) 256 d cd-ablk", "cryptd(ctr-blowfish-asm)", 32, 0 },

	{ "Blowfish(G) XTS(G) 128 e cd-ablk", "cryptd(xts(blowfish-generic))", 32, 1 },
	{ "Blowfish(G) XTS(G) 192 e cd-ablk", "cryptd(xts(blowfish-generic))", 48, 1 },
	{ "Blowfish(G) XTS(G) 256 e cd-ablk", "cryptd(xts(blowfish-generic))", 64, 1 },
	{ "Blowfish(G) XTS(G) 128 d cd-ablk", "cryptd(xts(blowfish-generic))", 32, 0 },
	{ "Blowfish(G) XTS(G) 192 d cd-ablk", "cryptd(xts(blowfish-generic))", 48, 0 },
	{ "Blowfish(G) XTS(G) 256 d cd-ablk", "cryptd(xts(blowfish-generic))", 64, 0 },
	{ "Blowfish(x86_64) XTS(G) 128 e cd-ablk", "cryptd(xts(blowfish-asm))", 32, 1 },
	{ "Blowfish(x86_64) XTS(G) 192 e cd-ablk", "cryptd(xts(blowfish-asm))", 48, 1 },
	{ "Blowfish(x86_64) XTS(G) 256 e cd-ablk", "cryptd(xts(blowfish-asm))", 64, 1 },
	{ "Blowfish(x86_64) XTS(G) 128 d cd-ablk", "cryptd(xts(blowfish-asm))", 32, 0 },
	{ "Blowfish(x86_64) XTS(G) 192 d cd-ablk", "cryptd(xts(blowfish-asm))", 48, 0 },
	{ "Blowfish(x86_64) XTS(G) 256 d cd-ablk", "cryptd(xts(blowfish-asm))", 64, 0 },

	{ "Blowfish(G) LRW(G) 128 e cd-ablk", "cryptd(lrw(blowfish-generic))", 32, 1 },
	{ "Blowfish(G) LRW(G) 192 e cd-ablk", "cryptd(lrw(blowfish-generic))", 40, 1 },
	{ "Blowfish(G) LRW(G) 256 e cd-ablk", "cryptd(lrw(blowfish-generic))", 48, 1 },
	{ "Blowfish(G) LRW(G) 128 d cd-ablk", "cryptd(lrw(blowfish-generic))", 32, 0 },
	{ "Blowfish(G) LRW(G) 192 d cd-ablk", "cryptd(lrw(blowfish-generic))", 40, 0 },
	{ "Blowfish(G) LRW(G) 256 d cd-ablk", "cryptd(lrw(blowfish-generic))", 48, 0 },
	{ "Blowfish(x86_64) LRW(G) 128 e cd-ablk", "cryptd(lrw(blowfish-asm))", 32, 1 },
	{ "Blowfish(x86_64) LRW(G) 192 e cd-ablk", "cryptd(lrw(blowfish-asm))", 40, 1 },
	{ "Blowfish(x86_64) LRW(G) 256 e cd-ablk", "cryptd(lrw(blowfish-asm))", 48, 1 },
	{ "Blowfish(x86_64) LRW(G) 128 d cd-ablk", "cryptd(lrw(blowfish-asm))", 32, 0 },
	{ "Blowfish(x86_64) LRW(G) 192 d cd-ablk", "cryptd(lrw(blowfish-asm))", 40, 0 },
	{ "Blowfish(x86_64) LRW(G) 256 d cd-ablk", "cryptd(lrw(blowfish-asm))", 48, 0 },

	{ "Twofish(G) ECB(G) 128 e cd-ablk", "cryptd(ecb(twofish-generic))", 16, 1 },
	{ "Twofish(G) ECB(G) 192 e cd-ablk", "cryptd(ecb(twofish-generic))", 24, 1 },
	{ "Twofish(G) ECB(G) 256 e cd-ablk", "cryptd(ecb(twofish-generic))", 32, 1 },
	{ "Twofish(G) ECB(G) 128 d cd-ablk", "cryptd(ecb(twofish-generic))", 16, 0 },
	{ "Twofish(G) ECB(G) 192 d cd-ablk", "cryptd(ecb(twofish-generic))", 24, 0 },
	{ "Twofish(G) ECB(G) 256 d cd-ablk", "cryptd(ecb(twofish-generic))", 32, 0 },
	{ "Twofish(x86_64) ECB(G) 128 e cd-ablk", "cryptd(ecb(twofish-asm))", 16, 1 },
	{ "Twofish(x86_64) ECB(G) 192 e cd-ablk", "cryptd(ecb(twofish-asm))", 24, 1 },
	{ "Twofish(x86_64) ECB(G) 256 e cd-ablk", "cryptd(ecb(twofish-asm))", 32, 1 },
	{ "Twofish(x86_64) ECB(G) 128 d cd-ablk", "cryptd(ecb(twofish-asm))", 16, 0 },
	{ "Twofish(x86_64) ECB(G) 192 d cd-ablk", "cryptd(ecb(twofish-asm))", 24, 0 },
	{ "Twofish(x86_64) ECB(G) 256 d cd-ablk", "cryptd(ecb(twofish-asm))", 32, 0 },
	{ "Twofish(3way) ECB(3way) 128 e cd-ablk", "cryptd(ecb-twofish-3way)", 16, 1 },
	{ "Twofish(3way) ECB(3way) 192 e cd-ablk", "cryptd(ecb-twofish-3way)", 24, 1 },
	{ "Twofish(3way) ECB(3way) 256 e cd-ablk", "cryptd(ecb-twofish-3way)", 32, 1 },
	{ "Twofish(3way) ECB(3way) 128 d cd-ablk", "cryptd(ecb-twofish-3way)", 16, 0 },
	{ "Twofish(3way) ECB(3way) 192 d cd-ablk", "cryptd(ecb-twofish-3way)", 24, 0 },
	{ "Twofish(3way) ECB(3way) 256 d cd-ablk", "cryptd(ecb-twofish-3way)", 32, 0 },
	{ "Twofish(AVX) ECB(AVX) 128 e cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 16, 1 },
	{ "Twofish(AVX) ECB(AVX) 192 e cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 24, 1 },
	{ "Twofish(AVX) ECB(AVX) 256 e cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 32, 1 },
	{ "Twofish(AVX) ECB(AVX) 128 d cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 16, 0 },
	{ "Twofish(AVX) ECB(AVX) 192 d cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 24, 0 },
	{ "Twofish(AVX) ECB(AVX) 256 d cd-ablk", "cryptd(__driver-ecb-twofish-avx)", 32, 0 },
	{ "Twofish(AVX) ECB(AVX) 128 e ablk", "ecb-twofish-avx", 16, 1 },
	{ "Twofish(AVX) ECB(AVX) 192 e ablk", "ecb-twofish-avx", 24, 1 },
	{ "Twofish(AVX) ECB(AVX) 256 e ablk", "ecb-twofish-avx", 32, 1 },
	{ "Twofish(AVX) ECB(AVX) 128 d ablk", "ecb-twofish-avx", 16, 0 },
	{ "Twofish(AVX) ECB(AVX) 192 d ablk", "ecb-twofish-avx", 24, 0 },
	{ "Twofish(AVX) ECB(AVX) 256 d ablk", "ecb-twofish-avx", 32, 0 },

	{ "Twofish(G) CBC(G) 128 e cd-ablk", "cryptd(cbc(twofish-generic))", 16, 1 },
	{ "Twofish(G) CBC(G) 192 e cd-ablk", "cryptd(cbc(twofish-generic))", 24, 1 },
	{ "Twofish(G) CBC(G) 256 e cd-ablk", "cryptd(cbc(twofish-generic))", 32, 1 },
	{ "Twofish(G) CBC(G) 128 d cd-ablk", "cryptd(cbc(twofish-generic))", 16, 0 },
	{ "Twofish(G) CBC(G) 192 d cd-ablk", "cryptd(cbc(twofish-generic))", 24, 0 },
	{ "Twofish(G) CBC(G) 256 d cd-ablk", "cryptd(cbc(twofish-generic))", 32, 0 },
	{ "Twofish(x86_64) CBC(G) 128 e cd-ablk", "cryptd(cbc(twofish-asm))", 16, 1 },
	{ "Twofish(x86_64) CBC(G) 192 e cd-ablk", "cryptd(cbc(twofish-asm))", 24, 1 },
	{ "Twofish(x86_64) CBC(G) 256 e cd-ablk", "cryptd(cbc(twofish-asm))", 32, 1 },
	{ "Twofish(x86_64) CBC(G) 128 d cd-ablk", "cryptd(cbc(twofish-asm))", 16, 0 },
	{ "Twofish(x86_64) CBC(G) 192 d cd-ablk", "cryptd(cbc(twofish-asm))", 24, 0 },
	{ "Twofish(x86_64) CBC(G) 256 d cd-ablk", "cryptd(cbc(twofish-asm))", 32, 0 },
	{ "Twofish(3way) CBC(3way) 128 e cd-ablk", "cryptd(cbc-twofish-3way)", 16, 1 },
	{ "Twofish(3way) CBC(3way) 192 e cd-ablk", "cryptd(cbc-twofish-3way)", 24, 1 },
	{ "Twofish(3way) CBC(3way) 256 e cd-ablk", "cryptd(cbc-twofish-3way)", 32, 1 },
	{ "Twofish(3way) CBC(3way) 128 d cd-ablk", "cryptd(cbc-twofish-3way)", 16, 0 },
	{ "Twofish(3way) CBC(3way) 192 d cd-ablk", "cryptd(cbc-twofish-3way)", 24, 0 },
	{ "Twofish(3way) CBC(3way) 256 d cd-ablk", "cryptd(cbc-twofish-3way)", 32, 0 },
	{ "Twofish(AVX) CBC(AVX) 128 e cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 16, 1 },
	{ "Twofish(AVX) CBC(AVX) 192 e cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 24, 1 },
	{ "Twofish(AVX) CBC(AVX) 256 e cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 32, 1 },
	{ "Twofish(AVX) CBC(AVX) 128 d cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 16, 0 },
	{ "Twofish(AVX) CBC(AVX) 192 d cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 24, 0 },
	{ "Twofish(AVX) CBC(AVX) 256 d cd-ablk", "cryptd(__driver-cbc-twofish-avx)", 32, 0 },
	{ "Twofish(AVX) CBC(AVX) 128 e ablk", "cbc-twofish-avx", 16, 1 },
	{ "Twofish(AVX) CBC(AVX) 192 e ablk", "cbc-twofish-avx", 24, 1 },
	{ "Twofish(AVX) CBC(AVX) 256 e ablk", "cbc-twofish-avx", 32, 1 },
	{ "Twofish(AVX) CBC(AVX) 128 d ablk", "cbc-twofish-avx", 16, 0 },
	{ "Twofish(AVX) CBC(AVX) 192 d ablk", "cbc-twofish-avx", 24, 0 },
	{ "Twofish(AVX) CBC(AVX) 256 d ablk", "cbc-twofish-avx", 32, 0 },

	{ "Twofish(G) CTR(G) 128 e cd-ablk", "cryptd(ctr(twofish-generic))", 16, 1 },
	{ "Twofish(G) CTR(G) 192 e cd-ablk", "cryptd(ctr(twofish-generic))", 24, 1 },
	{ "Twofish(G) CTR(G) 256 e cd-ablk", "cryptd(ctr(twofish-generic))", 32, 1 },
	{ "Twofish(G) CTR(G) 128 d cd-ablk", "cryptd(ctr(twofish-generic))", 16, 0 },
	{ "Twofish(G) CTR(G) 192 d cd-ablk", "cryptd(ctr(twofish-generic))", 24, 0 },
	{ "Twofish(G) CTR(G) 256 d cd-ablk", "cryptd(ctr(twofish-generic))", 32, 0 },
	{ "Twofish(x86_64) CTR(G) 128 e cd-ablk", "cryptd(ctr(twofish-asm))", 16, 1 },
	{ "Twofish(x86_64) CTR(G) 192 e cd-ablk", "cryptd(ctr(twofish-asm))", 24, 1 },
	{ "Twofish(x86_64) CTR(G) 256 e cd-ablk", "cryptd(ctr(twofish-asm))", 32, 1 },
	{ "Twofish(x86_64) CTR(G) 128 d cd-ablk", "cryptd(ctr(twofish-asm))", 16, 0 },
	{ "Twofish(x86_64) CTR(G) 192 d cd-ablk", "cryptd(ctr(twofish-asm))", 24, 0 },
	{ "Twofish(x86_64) CTR(G) 256 d cd-ablk", "cryptd(ctr(twofish-asm))", 32, 0 },
	{ "Twofish(3way) CTR(3way) 128 e cd-ablk", "cryptd(ctr-twofish-3way)", 16, 1 },
	{ "Twofish(3way) CTR(3way) 192 e cd-ablk", "cryptd(ctr-twofish-3way)", 24, 1 },
	{ "Twofish(3way) CTR(3way) 256 e cd-ablk", "cryptd(ctr-twofish-3way)", 32, 1 },
	{ "Twofish(3way) CTR(3way) 128 d cd-ablk", "cryptd(ctr-twofish-3way)", 16, 0 },
	{ "Twofish(3way) CTR(3way) 192 d cd-ablk", "cryptd(ctr-twofish-3way)", 24, 0 },
	{ "Twofish(3way) CTR(3way) 256 d cd-ablk", "cryptd(ctr-twofish-3way)", 32, 0 },
	{ "Twofish(AVX) CTR(AVX) 128 e cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 16, 1 },
	{ "Twofish(AVX) CTR(AVX) 192 e cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 24, 1 },
	{ "Twofish(AVX) CTR(AVX) 256 e cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 32, 1 },
	{ "Twofish(AVX) CTR(AVX) 128 d cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 16, 0 },
	{ "Twofish(AVX) CTR(AVX) 192 d cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 24, 0 },
	{ "Twofish(AVX) CTR(AVX) 256 d cd-ablk", "cryptd(__driver-ctr-twofish-avx)", 32, 0 },
	{ "Twofish(AVX) CTR(AVX) 128 e ablk", "ctr-twofish-avx", 16, 1 },
	{ "Twofish(AVX) CTR(AVX) 192 e ablk", "ctr-twofish-avx", 24, 1 },
	{ "Twofish(AVX) CTR(AVX) 256 e ablk", "ctr-twofish-avx", 32, 1 },
	{ "Twofish(AVX) CTR(AVX) 128 d ablk", "ctr-twofish-avx", 16, 0 },
	{ "Twofish(AVX) CTR(AVX) 192 d ablk", "ctr-twofish-avx", 24, 0 },
	{ "Twofish(AVX) CTR(AVX) 256 d ablk", "ctr-twofish-avx", 32, 0 },

	{ "Twofish(G) XTS(G) 128 e cd-ablk", "cryptd(xts(twofish-generic))", 32, 1 },
	{ "Twofish(G) XTS(G) 192 e cd-ablk", "cryptd(xts(twofish-generic))", 48, 1 },
	{ "Twofish(G) XTS(G) 256 e cd-ablk", "cryptd(xts(twofish-generic))", 64, 1 },
	{ "Twofish(G) XTS(G) 128 d cd-ablk", "cryptd(xts(twofish-generic))", 32, 0 },
	{ "Twofish(G) XTS(G) 192 d cd-ablk", "cryptd(xts(twofish-generic))", 48, 0 },
	{ "Twofish(G) XTS(G) 256 d cd-ablk", "cryptd(xts(twofish-generic))", 64, 0 },
	{ "Twofish(x86_64) XTS(G) 128 e cd-ablk", "cryptd(xts(twofish-asm))", 32, 1 },
	{ "Twofish(x86_64) XTS(G) 192 e cd-ablk", "cryptd(xts(twofish-asm))", 48, 1 },
	{ "Twofish(x86_64) XTS(G) 256 e cd-ablk", "cryptd(xts(twofish-asm))", 64, 1 },
	{ "Twofish(x86_64) XTS(G) 128 d cd-ablk", "cryptd(xts(twofish-asm))", 32, 0 },
	{ "Twofish(x86_64) XTS(G) 192 d cd-ablk", "cryptd(xts(twofish-asm))", 48, 0 },
	{ "Twofish(x86_64) XTS(G) 256 d cd-ablk", "cryptd(xts(twofish-asm))", 64, 0 },
	{ "Twofish(3way) XTS(3way) 128 e cd-ablk", "cryptd(xts-twofish-3way)", 32, 1 },
	{ "Twofish(3way) XTS(3way) 192 e cd-ablk", "cryptd(xts-twofish-3way)", 48, 1 },
	{ "Twofish(3way) XTS(3way) 256 e cd-ablk", "cryptd(xts-twofish-3way)", 64, 1 },
	{ "Twofish(3way) XTS(3way) 128 d cd-ablk", "cryptd(xts-twofish-3way)", 32, 0 },
	{ "Twofish(3way) XTS(3way) 192 d cd-ablk", "cryptd(xts-twofish-3way)", 48, 0 },
	{ "Twofish(3way) XTS(3way) 256 d cd-ablk", "cryptd(xts-twofish-3way)", 64, 0 },
	{ "Twofish(AVX) XTS(AVX) 128 e cd-ablk", "cryptd(__driver-xts-twofish-avx)", 32, 1 },
	{ "Twofish(AVX) XTS(AVX) 192 e cd-ablk", "cryptd(__driver-xts-twofish-avx)", 48, 1 },
	{ "Twofish(AVX) XTS(AVX) 256 e cd-ablk", "cryptd(__driver-xts-twofish-avx)", 64, 1 },
	{ "Twofish(AVX) XTS(AVX) 128 d cd-ablk", "cryptd(__driver-xts-twofish-avx)", 32, 0 },
	{ "Twofish(AVX) XTS(AVX) 192 d cd-ablk", "cryptd(__driver-xts-twofish-avx)", 48, 0 },
	{ "Twofish(AVX) XTS(AVX) 256 d cd-ablk", "cryptd(__driver-xts-twofish-avx)", 64, 0 },
	{ "Twofish(AVX) XTS(AVX) 128 e ablk", "xts-twofish-avx", 32, 1 },
	{ "Twofish(AVX) XTS(AVX) 192 e ablk", "xts-twofish-avx", 48, 1 },
	{ "Twofish(AVX) XTS(AVX) 256 e ablk", "xts-twofish-avx", 64, 1 },
	{ "Twofish(AVX) XTS(AVX) 128 d ablk", "xts-twofish-avx", 32, 0 },
	{ "Twofish(AVX) XTS(AVX) 192 d ablk", "xts-twofish-avx", 48, 0 },
	{ "Twofish(AVX) XTS(AVX) 256 d ablk", "xts-twofish-avx", 64, 0 },

	{ "Twofish(G) LRW(G) 128 e cd-ablk", "cryptd(lrw(twofish-generic))", 32, 1 },
	{ "Twofish(G) LRW(G) 192 e cd-ablk", "cryptd(lrw(twofish-generic))", 40, 1 },
	{ "Twofish(G) LRW(G) 256 e cd-ablk", "cryptd(lrw(twofish-generic))", 48, 1 },
	{ "Twofish(G) LRW(G) 128 d cd-ablk", "cryptd(lrw(twofish-generic))", 32, 0 },
	{ "Twofish(G) LRW(G) 192 d cd-ablk", "cryptd(lrw(twofish-generic))", 40, 0 },
	{ "Twofish(G) LRW(G) 256 d cd-ablk", "cryptd(lrw(twofish-generic))", 48, 0 },
	{ "Twofish(x86_64) LRW(G) 128 e cd-ablk", "cryptd(lrw(twofish-asm))", 32, 1 },
	{ "Twofish(x86_64) LRW(G) 192 e cd-ablk", "cryptd(lrw(twofish-asm))", 40, 1 },
	{ "Twofish(x86_64) LRW(G) 256 e cd-ablk", "cryptd(lrw(twofish-asm))", 48, 1 },
	{ "Twofish(x86_64) LRW(G) 128 d cd-ablk", "cryptd(lrw(twofish-asm))", 32, 0 },
	{ "Twofish(x86_64) LRW(G) 192 d cd-ablk", "cryptd(lrw(twofish-asm))", 40, 0 },
	{ "Twofish(x86_64) LRW(G) 256 d cd-ablk", "cryptd(lrw(twofish-asm))", 48, 0 },
	{ "Twofish(3way) LRW(3way) 128 e cd-ablk", "cryptd(lrw-twofish-3way)", 32, 1 },
	{ "Twofish(3way) LRW(3way) 192 e cd-ablk", "cryptd(lrw-twofish-3way)", 40, 1 },
	{ "Twofish(3way) LRW(3way) 256 e cd-ablk", "cryptd(lrw-twofish-3way)", 48, 1 },
	{ "Twofish(3way) LRW(3way) 128 d cd-ablk", "cryptd(lrw-twofish-3way)", 32, 0 },
	{ "Twofish(3way) LRW(3way) 192 d cd-ablk", "cryptd(lrw-twofish-3way)", 40, 0 },
	{ "Twofish(3way) LRW(3way) 256 d cd-ablk", "cryptd(lrw-twofish-3way)", 48, 0 },
	{ "Twofish(AVX) LRW(AVX) 128 e cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 32, 1 },
	{ "Twofish(AVX) LRW(AVX) 192 e cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 40, 1 },
	{ "Twofish(AVX) LRW(AVX) 256 e cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 48, 1 },
	{ "Twofish(AVX) LRW(AVX) 128 d cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 32, 0 },
	{ "Twofish(AVX) LRW(AVX) 192 d cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 40, 0 },
	{ "Twofish(AVX) LRW(AVX) 256 d cd-ablk", "cryptd(__driver-lrw-twofish-avx)", 48, 0 },
	{ "Twofish(AVX) LRW(AVX) 128 e ablk", "lrw-twofish-avx", 32, 1 },
	{ "Twofish(AVX) LRW(AVX) 192 e ablk", "lrw-twofish-avx", 40, 1 },
	{ "Twofish(AVX) LRW(AVX) 256 e ablk", "lrw-twofish-avx", 48, 1 },
	{ "Twofish(AVX) LRW(AVX) 128 d ablk", "lrw-twofish-avx", 32, 0 },
	{ "Twofish(AVX) LRW(AVX) 192 d ablk", "lrw-twofish-avx", 40, 0 },
	{ "Twofish(AVX) LRW(AVX) 256 d ablk", "lrw-twofish-avx", 48, 0 },

	{ "Salsa20(G) ECB(G) 128 e cd-ablk", "ecb(salsa20-generic))", 16, 1 },
	{ "Salsa20(G) ECB(G) 192 e cd-ablk", "ecb(salsa20-generic))", 24, 1 },
	{ "Salsa20(G) ECB(G) 256 e cd-ablk", "ecb(salsa20-generic))", 32, 1 },
	{ "Salsa20(G) ECB(G) 128 d cd-ablk", "ecb(salsa20-generic))", 16, 0 },
	{ "Salsa20(G) ECB(G) 192 d cd-ablk", "ecb(salsa20-generic))", 24, 0 },
	{ "Salsa20(G) ECB(G) 256 d cd-ablk", "ecb(salsa20-generic))", 32, 0 },
	{ "Salsa20(x86) ECB(G) 128 e cd-ablk", "ecb(salsa20-asm))", 16, 1 },
	{ "Salsa20(x86) ECB(G) 192 e cd-ablk", "ecb(salsa20-asm))", 24, 1 },
	{ "Salsa20(x86) ECB(G) 256 e cd-ablk", "ecb(salsa20-asm))", 32, 1 },
	{ "Salsa20(x86) ECB(G) 128 d cd-ablk", "ecb(salsa20-asm))", 16, 0 },
	{ "Salsa20(x86) ECB(G) 192 d cd-ablk", "ecb(salsa20-asm))", 24, 0 },
	{ "Salsa20(x86) ECB(G) 256 d cd-ablk", "ecb(salsa20-asm))", 32, 0 },

	{ "Salsa20(G) CBC(G) 128 e cd-ablk", "cryptd(cbc(salsa20-generic))", 16, 1 },
	{ "Salsa20(G) CBC(G) 192 e cd-ablk", "cryptd(cbc(salsa20-generic))", 24, 1 },
	{ "Salsa20(G) CBC(G) 256 e cd-ablk", "cryptd(cbc(salsa20-generic))", 32, 1 },
	{ "Salsa20(G) CBC(G) 128 d cd-ablk", "cryptd(cbc(salsa20-generic))", 16, 0 },
	{ "Salsa20(G) CBC(G) 192 d cd-ablk", "cryptd(cbc(salsa20-generic))", 24, 0 },
	{ "Salsa20(G) CBC(G) 256 d cd-ablk", "cryptd(cbc(salsa20-generic))", 32, 0 },
	{ "Salsa20(x86) CBC(G) 128 e cd-ablk", "cryptd(cbc(salsa20-asm))", 16, 1 },
	{ "Salsa20(x86) CBC(G) 192 e cd-ablk", "cryptd(cbc(salsa20-asm))", 24, 1 },
	{ "Salsa20(x86) CBC(G) 256 e cd-ablk", "cryptd(cbc(salsa20-asm))", 32, 1 },
	{ "Salsa20(x86) CBC(G) 128 d cd-ablk", "cryptd(cbc(salsa20-asm))", 16, 0 },
	{ "Salsa20(x86) CBC(G) 192 d cd-ablk", "cryptd(cbc(salsa20-asm))", 24, 0 },
	{ "Salsa20(x86) CBC(G) 256 d cd-ablk", "cryptd(cbc(salsa20-asm))", 32, 0 },

	{ "Salsa20(G) CTR(G) 128 e cd-ablk", "cryptd(ctr(salsa20-generic))", 16, 1 },
	{ "Salsa20(G) CTR(G) 192 e cd-ablk", "cryptd(ctr(salsa20-generic))", 24, 1 },
	{ "Salsa20(G) CTR(G) 256 e cd-ablk", "cryptd(ctr(salsa20-generic))", 32, 1 },
	{ "Salsa20(G) CTR(G) 128 d cd-ablk", "cryptd(ctr(salsa20-generic))", 16, 0 },
	{ "Salsa20(G) CTR(G) 192 d cd-ablk", "cryptd(ctr(salsa20-generic))", 24, 0 },
	{ "Salsa20(G) CTR(G) 256 d cd-ablk", "cryptd(ctr(salsa20-generic))", 32, 0 },
	{ "Salsa20(x86) CTR(G) 128 e cd-ablk", "cryptd(ctr(salsa20-asm))", 16, 1 },
	{ "Salsa20(x86) CTR(G) 192 e cd-ablk", "cryptd(ctr(salsa20-asm))", 24, 1 },
	{ "Salsa20(x86) CTR(G) 256 e cd-ablk", "cryptd(ctr(salsa20-asm))", 32, 1 },
	{ "Salsa20(x86) CTR(G) 128 d cd-ablk", "cryptd(ctr(salsa20-asm))", 16, 0 },
	{ "Salsa20(x86) CTR(G) 192 d cd-ablk", "cryptd(ctr(salsa20-asm))", 24, 0 },
	{ "Salsa20(x86) CTR(G) 256 d cd-ablk", "cryptd(ctr(salsa20-asm))", 32, 0 },

	{ "Salsa20(G) XTS(G) 128 e cd-ablk", "cryptd(xts(salsa20-generic))", 32, 1 },
	{ "Salsa20(G) XTS(G) 192 e cd-ablk", "cryptd(xts(salsa20-generic))", 48, 1 },
	{ "Salsa20(G) XTS(G) 256 e cd-ablk", "cryptd(xts(salsa20-generic))", 64, 1 },
	{ "Salsa20(G) XTS(G) 128 d cd-ablk", "cryptd(xts(salsa20-generic))", 32, 0 },
	{ "Salsa20(G) XTS(G) 192 d cd-ablk", "cryptd(xts(salsa20-generic))", 48, 0 },
	{ "Salsa20(G) XTS(G) 256 d cd-ablk", "cryptd(xts(salsa20-generic))", 64, 0 },
	{ "Salsa20(x86) XTS(G) 128 e cd-ablk", "cryptd(xts(salsa20-asm))", 32, 1 },
	{ "Salsa20(x86) XTS(G) 192 e cd-ablk", "cryptd(xts(salsa20-asm))", 48, 1 },
	{ "Salsa20(x86) XTS(G) 256 e cd-ablk", "cryptd(xts(salsa20-asm))", 64, 1 },
	{ "Salsa20(x86) XTS(G) 128 d cd-ablk", "cryptd(xts(salsa20-asm))", 32, 0 },
	{ "Salsa20(x86) XTS(G) 192 d cd-ablk", "cryptd(xts(salsa20-asm))", 48, 0 },
	{ "Salsa20(x86) XTS(G) 256 d cd-ablk", "cryptd(xts(salsa20-asm))", 64, 0 },

	{ "Salsa20(G) LRW(G) 128 e cd-ablk", "cryptd(lrw(salsa20-generic))", 32, 1 },
	{ "Salsa20(G) LRW(G) 192 e cd-ablk", "cryptd(lrw(salsa20-generic))", 40, 1 },
	{ "Salsa20(G) LRW(G) 256 e cd-ablk", "cryptd(lrw(salsa20-generic))", 48, 1 },
	{ "Salsa20(G) LRW(G) 128 d cd-ablk", "cryptd(lrw(salsa20-generic))", 32, 0 },
	{ "Salsa20(G) LRW(G) 192 d cd-ablk", "cryptd(lrw(salsa20-generic))", 40, 0 },
	{ "Salsa20(G) LRW(G) 256 d cd-ablk", "cryptd(lrw(salsa20-generic))", 48, 0 },
	{ "Salsa20(x86) LRW(G) 128 e cd-ablk", "cryptd(lrw(salsa20-asm))", 32, 1 },
	{ "Salsa20(x86) LRW(G) 192 e cd-ablk", "cryptd(lrw(salsa20-asm))", 40, 1 },
	{ "Salsa20(x86) LRW(G) 256 e cd-ablk", "cryptd(lrw(salsa20-asm))", 48, 1 },
	{ "Salsa20(x86) LRW(G) 128 d cd-ablk", "cryptd(lrw(salsa20-asm))", 32, 0 },
	{ "Salsa20(x86) LRW(G) 192 d cd-ablk", "cryptd(lrw(salsa20-asm))", 40, 0 },
	{ "Salsa20(x86) LRW(G) 256 d cd-ablk", "cryptd(lrw(salsa20-asm))", 48, 0 },
};

static struct cp_test cp_skcipher_testdef[(ARRAY_SIZE(testcases))];

void cp_skcipher_register(struct cp_test **skcipher_test, size_t *entries)
{
	size_t i = 0;

	for (i = i; i < ARRAY_SIZE(testcases); i++) {
		cp_skcipher_testdef[i].testname = testcases[i].testname;
		cp_skcipher_testdef[i].driver_name = testcases[i].driver_name;
		cp_skcipher_testdef[i].type = "skcipher";
		cp_skcipher_testdef[i].exectime = DFLT_EXECTIME;
		cp_skcipher_testdef[i].u.skcipher.keysize = testcases[i].keysize;
		cp_skcipher_testdef[i].init_test = cp_skcipher_init_test;
		cp_skcipher_testdef[i].fini_test = cp_skcipher_fini_test;
		if (testcases[i].enc)
			cp_skcipher_testdef[i].exec_test = cp_ablkcipher_enc_test;
		else
			cp_skcipher_testdef[i].exec_test = cp_ablkcipher_dec_test;
	}
	*skcipher_test = &cp_skcipher_testdef[0];
	*entries = i;
}
