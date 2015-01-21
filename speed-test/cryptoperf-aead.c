/*
 * Copyright (C) 2015, Stephan Mueller <smueller@chronox.de>
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
#include <sys/user.h>

/****************************************************************************
 * AEAD ciphers
 ****************************************************************************/

static int cp_aead_init_test(struct cp_test *test, size_t len, int enc, int ccm)
{
	unsigned char *input = NULL;
	unsigned char *output = NULL;
#define MAX_KEYLEN 64
#define ASSOCLEN 16
#define TAGLEN 16
#define BLOCKLEN 16
	unsigned char data[MAX_KEYLEN];
	unsigned char ivrand[MAX_KEYLEN];
	unsigned char *ivdata = NULL;
	size_t ivlen = 0;
	unsigned char *assoc = NULL;

	dbg("Initializing AEAD test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing test definition information for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_aead_init(&test->u.aead.handle, test->driver_name)) {
		printf(DRIVER_NAME": could not allocate aead handle for "
		       "%s\n", test->driver_name);
		goto out;
	}

	if (test->u.aead.keysize > MAX_KEYLEN) {
		printf(DRIVER_NAME": key length for cipher %s too large\n",
		       test->driver_name);
		goto out;
	}

	cp_read_random(data, test->u.aead.keysize);
	if (kcapi_aead_setkey(&test->u.aead.handle, data,
			      test->u.aead.keysize)) {
		printf(DRIVER_NAME": key could not be set\n");
		goto out;
	}

	cp_read_random(ivrand, BLOCKLEN);
	if (ccm) {
		if (kcapi_aead_ccm_nonce_to_iv(ivrand, 10, &ivdata, &ivlen))
			goto out;
	} else {
		if (kcapi_pad_iv(&test->u.aead.handle, ivrand,
				 kcapi_aead_blocksize(&test->u.aead.handle),
				 &ivdata, &ivlen))
			goto out;
	}
	test->u.aead.iv = ivdata;

	if (kcapi_aead_settaglen(&test->u.aead.handle, TAGLEN)) {
		printf(DRIVER_NAME ": Setting of authentication tag length failed\n");
		goto out;
	}

	if (posix_memalign((void *)&assoc, 16, ASSOCLEN)) {
		printf(DRIVER_NAME": could not allocate assoc for %s\n",
		       test->driver_name);
		goto out;
	}
	cp_read_random(assoc, ASSOCLEN);
	test->u.aead.assoclen = ASSOCLEN;
	test->u.aead.assoc = assoc;
	kcapi_aead_setassoclen(&test->u.aead.handle, test->u.aead.assoclen);

	if (enc) {
		test->u.aead.inputlen = kcapi_aead_outbuflen(
			&test->u.aead.handle, BLOCKLEN * len,
			TAGLEN, 0);
		test->u.aead.outputlen = kcapi_aead_outbuflen(
			&test->u.aead.handle, BLOCKLEN * len,
			TAGLEN, 1);
	} else {
		test->u.aead.inputlen = kcapi_aead_outbuflen(
			&test->u.aead.handle, BLOCKLEN * len,
			TAGLEN, 1);
		test->u.aead.outputlen = kcapi_aead_outbuflen(
			&test->u.aead.handle, BLOCKLEN * len,
			TAGLEN, 0);
	}
	if (posix_memalign((void *)&input, PAGE_SIZE, test->u.aead.inputlen)) {
		printf(DRIVER_NAME": could not allocate input buffer for "
		       "%s\n", test->driver_name);
		goto out;
	}
	if (posix_memalign((void *)&output, PAGE_SIZE, test->u.aead.outputlen)) {
		printf(DRIVER_NAME": could not allocate output buffer for "
		       "%s\n", test->driver_name);
		goto out;
	}
	test->u.aead.input = input;
	test->u.aead.output = output;

	if (enc) {
		cp_read_random(input, test->u.aead.inputlen);
	} else {
		int ret = 0;
		/* we need good data to avoid testing just the hash */
		cp_read_random(output, test->u.aead.outputlen);
		ret = kcapi_aead_encrypt(&test->u.aead.handle,
					 test->u.aead.output,
					 test->u.aead.outputlen,
					 test->u.aead.iv,
					 test->u.aead.assoc,
					 test->u.aead.input,
					 test->u.aead.inputlen);
		if (ret < 0) {
			printf(DRIVER_NAME": could not create ciphertext for "
		       "%s (%d)\n", test->driver_name, ret);
			goto out;
		}
		test->u.aead.tag = test->u.aead.input + test->u.aead.inputlen -
				   TAGLEN;
		test->u.aead.inputlen -= TAGLEN;
	}

	return 0;

out:
	kcapi_cipher_destroy(&test->u.aead.handle);
	if (ivdata)
		free(ivdata);
	if (assoc)
		free(assoc);
	if (input)
		free(input);
	if (output)
		free(output);
	return -ENOMEM;
}

static int cp_aead_init_enc_dflt(struct cp_test *test, size_t len)
{
	return cp_aead_init_test(test, len, 1, 0);
}

static int cp_aead_init_enc_ccm(struct cp_test *test, size_t len)
{
	return cp_aead_init_test(test, len, 1, 1);
}

static int cp_aead_init_dec_dflt(struct cp_test *test, size_t len)
{
	return cp_aead_init_test(test, len, 0, 0);
}

static int cp_aead_init_dec_ccm(struct cp_test *test, size_t len)
{
	return cp_aead_init_test(test, len, 0, 1);
}

static void cp_aead_fini_test(struct cp_test *test)
{
	dbg("Cleaning up asynchronous symmetric test %s\n", test->testname);
	free(test->u.aead.input);
	free(test->u.aead.output);
	free(test->u.aead.assoc);
	free(test->u.aead.iv);
	kcapi_cipher_destroy(&test->u.aead.handle);
}

static unsigned int cp_ablkcipher_enc_test(struct cp_test *test)
{
	kcapi_aead_encrypt(&test->u.aead.handle,
			   test->u.aead.input,
			   test->u.aead.inputlen,
			   test->u.aead.iv,
			   test->u.aead.assoc,
			   test->u.aead.output,
			   test->u.aead.outputlen);
	return test->u.aead.inputlen;
}

static unsigned int cp_ablkcipher_dec_test(struct cp_test *test)
{
	kcapi_aead_decrypt(&test->u.aead.handle,
			   test->u.aead.input,
			   test->u.aead.inputlen,
			   test->u.aead.iv,
			   test->u.aead.assoc,
			   test->u.aead.tag,
			   test->u.aead.output,
			   test->u.aead.outputlen);
	return test->u.aead.inputlen;
}

struct cp_aead_tests {
	char *testname;
	char *driver_name;
	unsigned int keysize;
	unsigned int ccm;
};

static const struct cp_aead_tests testcases[] = {

	{ "AES(G) GCM(G) 128", "gcm(aes-generic)", 16, 0 },
	{ "AES(G) GCM(G) 192", "gcm(aes-generic)", 24, 0 },
	{ "AES(G) GCM(G) 256", "gcm(aes-generic)", 32, 0 },
#if 0
	/* these tests panic the kernel due to missing setkey callback */
	{ "AES(AESNI) GCM(ASM) 128", "__driver-gcm-aes-aesni", 16, 0 },
	{ "AES(AESNI) GCM(ASM) 192", "__driver-gcm-aes-aesni", 24, 0 },
	{ "AES(AESNI) GCM(ASM) 256", "__driver-gcm-aes-aesni", 32, 0 },
#endif
	{ "AES(AESNI) GCM(ASM-RFC) 128", "rfc4106-gcm-aesni", 16, 0 },
	{ "AES(AESNI) GCM(ASM-RFC) 192", "rfc4106-gcm-aesni", 24, 0 },
	{ "AES(AESNI) GCM(ASM-RFC) 256", "rfc4106-gcm-aesni", 32, 0 },
	{ "AES(AESNI) GCM(G) 128", "gcm(__driver-aes-aesni)", 16, 0 },
	{ "AES(AESNI) GCM(G) 192", "gcm(__driver-aes-aesni)", 24, 0 },
	{ "AES(AESNI) GCM(G) 256", "gcm(__driver-aes-aesni)", 32, 0 },
	{ "AES(G) CCM(G) 128", "ccm(aes-generic)", 16, 1 },
	{ "AES(G) CCM(G) 192", "ccm(aes-generic)", 24, 1 },
	{ "AES(G) CCM(G) 256", "ccm(aes-generic)", 32, 1 },
	{ "AES(AESNI) CCM(G) 128", "ccm(__driver-aes-aesni)", 16, 0 },
	{ "AES(AESNI) CCM(G) 192", "ccm(__driver-aes-aesni)", 24, 0 },
	{ "AES(AESNI) CCM(G) 256", "ccm(__driver-aes-aesni)", 32, 0 },
};

static struct cp_test cp_aead_testdef[(2 * (ARRAY_SIZE(testcases)))];

void cp_aead_register(struct cp_test **aead_test, size_t *entries)
{
	size_t i = 0;
	size_t j = 0;

	for (i = 0, j = 0;
	     i < (ARRAY_SIZE(testcases)) && j < (2 * ARRAY_SIZE(testcases));
	     i++, j++) {
		int enc = 0;
		for (enc = 0; enc < 2; enc++) {
			j += enc;
			cp_aead_testdef[j].enc = enc;
			cp_aead_testdef[j].testname = testcases[i].testname;
			cp_aead_testdef[j].driver_name = testcases[i].driver_name;
			cp_aead_testdef[j].type = "aead";
			cp_aead_testdef[j].exectime = DFLT_EXECTIME;
			cp_aead_testdef[j].u.aead.keysize = testcases[i].keysize;
			if (enc) {
				if (testcases[i].ccm)
					cp_aead_testdef[j].init_test =
						cp_aead_init_enc_ccm;
				else
					cp_aead_testdef[j].init_test =
						cp_aead_init_enc_dflt;
			} else {
				if (testcases[i].ccm)
					cp_aead_testdef[j].init_test =
						cp_aead_init_dec_ccm;
				else
					cp_aead_testdef[j].init_test =
						cp_aead_init_dec_dflt;
			}
			cp_aead_testdef[j].fini_test = cp_aead_fini_test;
			if (enc)
				cp_aead_testdef[j].exec_test = cp_ablkcipher_enc_test;
			else
				cp_aead_testdef[j].exec_test = cp_ablkcipher_dec_test;
		}
	}
	*aead_test = &cp_aead_testdef[0];
	*entries = j;
}
