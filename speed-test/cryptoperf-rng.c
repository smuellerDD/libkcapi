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

/****************************************************************************
 * Random Number Generators
 ****************************************************************************/
static int cp_rng_init_test(struct cp_test *test)
{
	unsigned char *scratchpad = NULL;
	struct cp_test_param *params = test->test_params;
#define SEEDSIZE 64
	unsigned char seed[SEEDSIZE];

	dbg("Initializing RNG test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing driver_name for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_rng_init(&test->u.rng.handle, test->driver_name, 0)) {
		printf(DRIVER_NAME": could not allocate rng handle for "
		       "%s\n", test->driver_name);
		goto out;
	}
	dbg("testing RNG %s allocated\n", test->driver_name);

	cp_read_random(seed, SEEDSIZE);
	if (kcapi_rng_seed(test->u.rng.handle, seed, SEEDSIZE)) {
		printf(DRIVER_NAME": seed could not be set\n");
		goto out;
	}

	if (!params->len)
		params->len = 1;
	if (posix_memalign((void *)&scratchpad, 16,
			   test->u.rng.blocksize * params->len)) {
		printf(DRIVER_NAME": could not allocate scratchpad for "
		       "%s\n", test->driver_name);
		goto out;
	}

	test->u.rng.scratchpad = scratchpad;
	test->u.rng.inputlen = params->len * test->u.rng.blocksize;

	return 0;

out:
	kcapi_rng_destroy(test->u.rng.handle);
	if (scratchpad)
		free(scratchpad);
	return -ENOMEM;
}

static void cp_rng_fini_test(struct cp_test *test)
{
	kcapi_rng_destroy(test->u.rng.handle);
	free(test->u.rng.scratchpad);
}

static size_t cp_rng_exec_test(struct cp_test *test)
{
	kcapi_rng_generate(test->u.rng.handle,
			   test->u.rng.scratchpad,
			   test->u.rng.inputlen);
	return test->u.rng.inputlen;
}

struct cp_rng_tests {
	char *testname;
	char *driver_name;
	unsigned int blocksize;
};

static const struct cp_rng_tests testcases[] = {
	{ "HMAC SHA-1 DRBG NOPR", "drbg_nopr_hmac_sha1", 20 },
	{ "HMAC SHA-256 DRBG NOPR", "drbg_nopr_hmac_sha256", 32 },
	{ "HMAC SHA-384 DRBG NOPR", "drbg_nopr_hmac_sha384", 48 },
	{ "HMAC SHA-512 DRBG NOPR", "drbg_nopr_hmac_sha512", 64 },
	{ "HMAC SHA-1 DRBG PR", "drbg_pr_hmac_sha1", 20 },
	{ "HMAC SHA-256 DRBG PR", "drbg_pr_hmac_sha256", 32 },
	{ "HMAC SHA-384 DRBG PR", "drbg_pr_hmac_sha384", 48 },
	{ "HMAC SHA-512 DRBG PR", "drbg_pr_hmac_sha512", 64 },
	{ "Hash SHA-1 DRBG NOPR", "drbg_nopr_sha1", 20 },
	{ "Hash SHA-256 DRBG NOPR", "drbg_nopr_sha256", 32 },
	{ "Hash SHA-384 DRBG NOPR", "drbg_nopr_sha384", 48 },
	{ "Hash SHA-512 DRBG NOPR", "drbg_nopr_sha512", 64 },
	{ "Hash SHA-1 DRBG PR", "drbg_pr_sha1", 20 },
	{ "Hash SHA-256 DRBG PR", "drbg_pr_sha256", 32 },
	{ "Hash SHA-384 DRBG PR", "drbg_pr_sha384", 48 },
	{ "Hash SHA-512 DRBG PR", "drbg_pr_sha512", 64 },
	{ "CTR AES-128 DRBG NOPR", "drbg_nopr_ctr_aes128", 16 },
	{ "CTR AES-192 DRBG NOPR", "drbg_nopr_ctr_aes192", 16 },
	{ "CTR AES-256 DRBG NOPR", "drbg_nopr_ctr_aes256", 16 },
	{ "CTR AES-128 DRBG PR", "drbg_pr_ctr_aes128", 16 },
	{ "CTR AES-192 DRBG PR", "drbg_pr_ctr_aes192", 16 },
	{ "CTR AES-256 DRBG PR", "drbg_pr_ctr_aes256", 16 },
//	{ "ANSI X9.31", "ansi_cprng", 16 },
//	{ "FIPS mode ANSI X9.31", "fips_ansi_cprng", 16 },
};

static struct cp_test cp_rng_testdef[(ARRAY_SIZE(testcases))];

void cp_rng_register(struct cp_test **rng_test, size_t *entries)
{
	size_t i = 0;

	for (i = 0; i < ARRAY_SIZE(testcases); i++) {
		cp_rng_testdef[i].enc = 0;
		cp_rng_testdef[i].testname = testcases[i].testname;
		cp_rng_testdef[i].driver_name = testcases[i].driver_name;
		cp_rng_testdef[i].type = "rng";
		cp_rng_testdef[i].exectime = DFLT_EXECTIME;
		cp_rng_testdef[i].u.rng.blocksize = testcases[i].blocksize;
		cp_rng_testdef[i].init_test = cp_rng_init_test;
		cp_rng_testdef[i].fini_test = cp_rng_fini_test;
		cp_rng_testdef[i].exec_test = cp_rng_exec_test;
	}
	*rng_test = &cp_rng_testdef[0];
	*entries = i;
}
