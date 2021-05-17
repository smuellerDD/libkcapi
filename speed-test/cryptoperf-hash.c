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

#include <stdlib.h>

/****************************************************************************
 * Synchronous symmetric ciphers
 ****************************************************************************/

static int cp_hash_init_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;
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

	if (params->len < 4)
		params->len = 4;

	if (posix_memalign((void *)&scratchpad,
			   kcapi_md_blocksize(test->u.hash.handle),
			   kcapi_md_blocksize(test->u.hash.handle) * params->len)) {
		printf(DRIVER_NAME": could not allocate scratchpad for "
		       "%s\n", test->driver_name);
		goto out;
	}

	cp_read_random(scratchpad,
		       kcapi_md_blocksize(test->u.hash.handle) * params->len);

	test->u.hash.inputlen =
			params->len * kcapi_md_blocksize(test->u.hash.handle);
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

static size_t cp_hash_test(struct cp_test *test)
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
	{ "SHA-1(MV-CESA)", "mv-sha1", 0 },
	{ "SHA-256(MV-CESA)", "mv-sha256", 0 },

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
	{ "HMAC SHA-1(MV-CESA)", "mv-hmac-sha1", 1 },
	{ "HMAC SHA-256(MV-CESA)", "mv-hmac-sha256", 1 },

	{ "MD5(G)", "md5-generic", 0 },
	{ "MD5(MV-CESA)", "mv-md5", 0 },
	{ "HMAC MD5(G)", "hmac(md5-generic)", 1 },
	{ "HMAC MD5(MV-CESA)", "mv-hmac-md5", 1 },
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
