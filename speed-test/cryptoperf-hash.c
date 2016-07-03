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

#include <stdlib.h>

#include "cryptoperf.h"

/****************************************************************************
 * Synchronous symmetric ciphers
 ****************************************************************************/

static int cp_hash_init_test(struct cp_test *test, size_t len)
{
	unsigned char *scratchpad = NULL;
#define MAX_KEYLEN 128
	unsigned char data[MAX_KEYLEN];

	dbg("Initializing hash test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing driver_name for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_md_init(&test->u.hash.handle, test->driver_name, 0)) {
		printf(DRIVER_NAME": could not allocate shash handle for "
		       "%s\n", test->driver_name);
		goto out2;
	}

	/* HMAC */
	if (test->u.hash.hmac) {
		if (kcapi_md_blocksize(test->u.hash.handle) > MAX_KEYLEN) {
			printf(DRIVER_NAME": key length for cipher %s too large %u\n",
			       test->driver_name,
			       kcapi_md_blocksize(test->u.hash.handle));
			goto out;
		}
		cp_read_random(data, kcapi_md_blocksize(test->u.hash.handle));
		if (kcapi_md_setkey(test->u.hash.handle, data,
				    kcapi_md_blocksize(test->u.hash.handle))) {
			printf(DRIVER_NAME": key could not be set\n");
			goto out;
		}
	}

	if (len < 4)
		len = 4;

	if (posix_memalign((void *)&scratchpad,
			   kcapi_md_blocksize(test->u.hash.handle),
			   kcapi_md_blocksize(test->u.hash.handle) * len)) {
		printf(DRIVER_NAME": could not allocate scratchpad for "
		       "%s\n", test->driver_name);
		goto out;
	}

	cp_read_random(scratchpad,
		       kcapi_md_blocksize(test->u.hash.handle) * len);

	test->u.hash.inputlen = len * kcapi_md_blocksize(test->u.hash.handle);
	test->u.hash.scratchpad = scratchpad;
	return 0;

out:
	kcapi_md_destroy(test->u.hash.handle);
out2:
	if (scratchpad)
		free(scratchpad);
	return -ENOMEM;
}

static void cp_hash_fini_test(struct cp_test *test)
{
	dbg("Cleaning up shash test %s\n", test->testname);
	kcapi_md_destroy(test->u.hash.handle);
	free(test->u.hash.scratchpad);
}

static unsigned int cp_hash_test(struct cp_test *test)
{
	kcapi_md_digest(test->u.hash.handle,
			test->u.hash.scratchpad,
			test->u.hash.inputlen,
			test->u.hash.scratchpad,
			kcapi_md_digestsize(test->u.hash.handle));
	return test->u.hash.inputlen;
}

struct cp_hash_tests {
	char *testname;
	char *driver_name;
	unsigned int hmac;
};

static const struct cp_hash_tests testcases[] = {
	{ "SHA-1(G)", "sha1-generic", 0 },
	{ "SHA-224(G)", "sha224-generic", 0 },
	{ "SHA-256(G)", "sha256-generic", 0 },
	{ "SHA-384(G)", "sha384-generic", 0 },
	{ "SHA-512(G)", "sha512-generic", 0 },
	{ "SHA-1(SSSE3)", "sha1-ssse3", 0 },
	{ "SHA-224(SSSE3)", "sha224-ssse3", 0 },
	{ "SHA-256(SSSE3)", "sha256-ssse3", 0 },
	{ "SHA-384(SSSE3)", "sha384-ssse3", 0 },
	{ "SHA-512(SSSE3)", "sha512-ssse3", 0 },
	{ "SHA-1(AVX)", "sha1-avx", 0 },
	{ "SHA-224(AVX)", "sha224-avx", 0 },
	{ "SHA-256(AVX)", "sha256-avx", 0 },
	{ "SHA-384(AVX)", "sha384-avx", 0 },
	{ "SHA-512(AVX)", "sha512-avx", 0 },
	{ "SHA-1(AVX2)", "sha1-avx2", 0 },
	{ "SHA-224(AVX2)", "sha224-avx2", 0 },
	{ "SHA-256(AVX2)", "sha256-avx2", 0 },
	{ "SHA-384(AVX2)", "sha384-avx2", 0 },
	{ "SHA-512(AVX2)", "sha512-avx2", 0 },

	{ "HMAC SHA-1(G)", "hmac(sha1-generic)", 1 },
	{ "HMAC SHA-224(G)", "hmac(sha224-generic)", 1 },
	{ "HMAC SHA-256(G)", "hmac(sha256-generic)", 1 },
	{ "HMAC SHA-384(G)", "hmac(sha384-generic)", 1 },
	{ "HMAC SHA-512(G)", "hmac(sha512-generic)", 1 },
	{ "HMAC SHA-1(SSSE3)", "hmac(sha1-ssse3)", 1 },
	{ "HMAC SHA-224(SSSE3)", "hmac(sha224-ssse3)", 1 },
	{ "HMAC SHA-256(SSSE3)", "hmac(sha256-ssse3)", 1 },
	{ "HMAC SHA-384(SSSE3)", "hmac(sha384-ssse3)", 1 },
	{ "HMAC SHA-512(SSSE3)", "hmac(sha512-ssse3)", 1 },
	{ "HMAC SHA-1(AVX)", "hmac(sha1-avx)", 1 },
	{ "HMAC SHA-224(AVX)", "hmac(sha224-avx)", 1 },
	{ "HMAC SHA-256(AVX)", "hmac(sha256-avx)", 1 },
	{ "HMAC SHA-384(AVX)", "hmac(sha384-avx)", 1 },
	{ "HMAC SHA-512(AVX)", "hmac(sha512-avx)", 1 },
	{ "HMAC SHA-1(AVX2)", "hmac(sha1-avx2)", 1 },
	{ "HMAC SHA-224(AVX2)", "hmac(sha224-avx2)", 1 },
	{ "HMAC SHA-256(AVX2)", "hmac(sha256-avx2)", 1 },
	{ "HMAC SHA-384(AVX2)", "hmac(sha384-avx2)", 1 },
	{ "HMAC SHA-512(AVX2)", "hmac(sha512-avx2)", 1 },

	{ "MD5(G)", "md5-generic", 0 },
	{ "HMAC MD5(G)", "hmac(md5-generic)", 1 },
};

static struct cp_test cp_hash_testdef[(ARRAY_SIZE(testcases))];

void cp_hash_register(struct cp_test **hash_test, size_t *entries)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		cp_hash_testdef[i].enc = 0;
		cp_hash_testdef[i].testname = testcases[i].testname;
		cp_hash_testdef[i].driver_name = testcases[i].driver_name;
		cp_hash_testdef[i].type = "hash";
		cp_hash_testdef[i].exectime = DFLT_EXECTIME;
		cp_hash_testdef[i].u.hash.hmac = testcases[i].hmac;
		cp_hash_testdef[i].init_test = cp_hash_init_test;
		cp_hash_testdef[i].fini_test = cp_hash_fini_test;
		cp_hash_testdef[i].exec_test = cp_hash_test;
	}
	*hash_test = &cp_hash_testdef[0];
	*entries = i;
}
