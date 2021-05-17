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
#include <sys/user.h>

/****************************************************************************
 * AEAD ciphers
 ****************************************************************************/

static int cp_aead_init_test(struct cp_test *test, int enc, int ccm)
{
	struct cp_test_param *params = test->test_params;
	unsigned char *input = NULL;
	unsigned char *output = NULL;
#define MAX_KEYLEN 64
#define TAGLEN 16
#define BLOCKLEN 16
	unsigned char data[MAX_KEYLEN];
	unsigned char ivrand[MAX_KEYLEN];
	unsigned char *ivdata = NULL;
	uint32_t ivlen = 0;
	size_t pagesize = (size_t)sysconf(_SC_PAGESIZE);

	if (pagesize > ULONG_MAX) {
		printf(DRIVER_NAME": unable to determine the page size\n");
		return -errno;
	}

	dbg("Initializing AEAD test %s\n", test->testname);
	if (!test->driver_name) {
		printf(DRIVER_NAME": missing test definition information for %s\n",
		       test->testname);
		return -EFAULT;
	}

	if (kcapi_aead_init(&test->u.aead.handle, test->driver_name,
			    params->aio ? KCAPI_INIT_AIO : 0)) {
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
	if (kcapi_aead_setkey(test->u.aead.handle, data,
			      test->u.aead.keysize)) {
		printf(DRIVER_NAME": key could not be set\n");
		goto out;
	}

	cp_read_random(ivrand, BLOCKLEN);
	if (ccm) {
		if (kcapi_aead_ccm_nonce_to_iv(ivrand, 10, &ivdata, &ivlen))
			goto out;
	} else {
		if (kcapi_pad_iv(test->u.aead.handle, ivrand,
				 kcapi_aead_blocksize(test->u.aead.handle),
				 &ivdata, &ivlen))
			goto out;
	}
	test->u.aead.iv = ivdata;

	if (kcapi_aead_settaglen(test->u.aead.handle, TAGLEN)) {
		printf(DRIVER_NAME ": Setting of authentication tag length failed\n");
		goto out;
	}

	if (enc) {
		test->u.aead.indatalen = kcapi_aead_inbuflen_enc(
			test->u.aead.handle, BLOCKLEN * params->len,
			test->u.aead.assoclen, TAGLEN);
		test->u.aead.outdatalen = kcapi_aead_outbuflen_enc(
			test->u.aead.handle, BLOCKLEN * params->len,
			test->u.aead.assoclen, TAGLEN);
	} else {
		test->u.aead.indatalen = kcapi_aead_inbuflen_dec(
			test->u.aead.handle, BLOCKLEN * params->len,
			test->u.aead.assoclen, TAGLEN);
		test->u.aead.outdatalen = kcapi_aead_outbuflen_dec(
			test->u.aead.handle, BLOCKLEN * params->len,
			test->u.aead.assoclen, TAGLEN);
	}

	if (posix_memalign((void *)&input, pagesize,
			   test->u.aead.indatalen *
					(params->aio ? params->aio : 1))) {
		printf(DRIVER_NAME": could not allocate input buffer for "
		       "%s\n", test->driver_name);
		goto out;
	}
	if (posix_memalign((void *)&output, pagesize,
			   test->u.aead.outdatalen *
					(params->aio ? params->aio : 1))) {
		printf(DRIVER_NAME": could not allocate output buffer for "
		       "%s\n", test->driver_name);
		goto out;
	}
	kcapi_aead_setassoclen(test->u.aead.handle, test->u.aead.assoclen);

	test->u.aead.input = input;
	test->u.aead.output = output;

	if (enc) {
		cp_read_random(input, test->u.aead.indatalen);
	} else {
		ssize_t ret = 0;
		/* we need good data to avoid testing just the hash */
		cp_read_random(output, test->u.aead.outdatalen);
		ret = kcapi_aead_encrypt(test->u.aead.handle,
					 test->u.aead.output,
					 test->u.aead.outdatalen,
					 test->u.aead.iv,
					 test->u.aead.input,
					 test->u.aead.indatalen, 0);
		if (ret < 0) {
			printf(DRIVER_NAME": could not create ciphertext for "
		       "%s (%zd)\n", test->driver_name, ret);
			goto out;
		}
		/* copy the AAD as this is not copied by the kernel */
		memcpy(test->u.aead.input, test->u.aead.output,
		       test->u.aead.assoclen);
		/* just a verification to avoid being fooled */
		ret = kcapi_aead_decrypt(test->u.aead.handle,
					 test->u.aead.input,
					 test->u.aead.indatalen,
					 test->u.aead.iv,
					 test->u.aead.output,
					 test->u.aead.outdatalen,
					 params->accesstype);
		if (ret < 0) {
			printf(DRIVER_NAME": could not decrypt ciphertext for "
		       "%s (%zd)\n", test->driver_name, ret);
			goto out;
		}
	}

	if (params->aio) {
		unsigned int i;

		if (posix_memalign((void *)&test->u.aead.iniov, BLOCKLEN,
				     params->aio * sizeof(struct iovec))) {
			printf(DRIVER_NAME": could not allocate iniov buffer\n");
			goto out;
		}
		if (posix_memalign((void *)&test->u.aead.outiov, BLOCKLEN,
				     params->aio * sizeof(struct iovec))) {
			free(test->u.aead.iniov);
			printf(DRIVER_NAME": could not allocate outiov buffer\n");
			goto out;
		}

		for (i = 0; i < params->aio; i++) {
			ssize_t ret = 0;

			test->u.aead.iniov[i].iov_base = input;
			test->u.aead.iniov[i].iov_len = test->u.aead.indatalen;
			test->u.aead.outiov[i].iov_base = output;
			test->u.aead.outiov[i].iov_len = test->u.aead.outdatalen;

			if (!i) {
				input += test->u.aead.indatalen;
				output += test->u.aead.outdatalen;
				continue;
			}

			if (enc) {
				cp_read_random(input, test->u.aead.indatalen);
			} else {
				/* we need good data to avoid testing just the hash */
				cp_read_random(output, test->u.aead.outdatalen);
				ret = kcapi_aead_encrypt(test->u.aead.handle,
							output,
							test->u.aead.outdatalen,
							test->u.aead.iv,
							input,
							test->u.aead.indatalen, 0);
				if (ret < 0) {
					printf(DRIVER_NAME": could not create ciphertext for "
				"%s (%zd)\n", test->driver_name, ret);
					goto out;
				}
				/* copy the AAD as this is not copied by the kernel */
				memcpy(input, output, test->u.aead.assoclen);
				/* just a verification to avoid being fooled */
				ret = kcapi_aead_decrypt(test->u.aead.handle,
							input,
							test->u.aead.indatalen,
							test->u.aead.iv,
							output,
							test->u.aead.outdatalen,
							params->accesstype);
				if (ret < 0) {
					printf(DRIVER_NAME": could not decrypt ciphertext for "
				"%s (%zd)\n", test->driver_name, ret);
					goto out;
				}
			}

			input += test->u.aead.indatalen;
			output += test->u.aead.outdatalen;
		}
	}

	return 0;

out:
	kcapi_cipher_destroy(test->u.aead.handle);
	if (ivdata)
		free(ivdata);
	if (input)
		free(input);
	if (output)
		free(output);
	return -ENOMEM;
}

static int cp_aead_init_enc_dflt(struct cp_test *test)
{
	return cp_aead_init_test(test, 1, 0);
}

static int cp_aead_init_enc_ccm(struct cp_test *test)
{
	return cp_aead_init_test(test, 1, 1);
}

static int cp_aead_init_dec_dflt(struct cp_test *test)
{
	return cp_aead_init_test(test, 0, 0);
}

static int cp_aead_init_dec_ccm(struct cp_test *test)
{
	return cp_aead_init_test(test, 0, 1);
}

static void cp_aead_fini_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	dbg("Cleaning up asynchronous symmetric test %s\n", test->testname);
	free(test->u.aead.input);
	free(test->u.aead.output);
	free(test->u.aead.iv);
	if (params->aio) {
		free(test->u.aead.iniov);
		free(test->u.aead.outiov);
	}
	kcapi_cipher_destroy(test->u.aead.handle);
}

static size_t cp_ablkcipher_enc_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	if (params->aio)
		kcapi_aead_encrypt_aio(test->u.aead.handle,
				       test->u.aead.iniov,
				       test->u.aead.outiov,
				       params->aio,
				       test->u.aead.iv,
				       params->accesstype);
	else
		kcapi_aead_encrypt(test->u.aead.handle,
				   test->u.aead.input,
				   test->u.aead.indatalen,
				   test->u.aead.iv,
				   test->u.aead.output,
				   test->u.aead.outdatalen,
				   params->accesstype);
	return test->u.aead.outdatalen;
}

static size_t cp_ablkcipher_dec_test(struct cp_test *test)
{
	struct cp_test_param *params = test->test_params;

	if (params->aio)
		kcapi_aead_decrypt_aio(test->u.aead.handle,
				       test->u.aead.iniov,
				       test->u.aead.outiov,
				       params->aio,
				       test->u.aead.iv,
				       params->accesstype);
	else
		kcapi_aead_decrypt(test->u.aead.handle,
				   test->u.aead.input,
				   test->u.aead.indatalen,
				   test->u.aead.iv,
				   test->u.aead.output,
				   test->u.aead.outdatalen,
				   params->accesstype);
	return test->u.aead.outdatalen;
}

struct cp_aead_tests {
	char *testname;
	char *driver_name;
	unsigned int keysize;
	unsigned int assoclen;
	unsigned int ccm;
};

static const struct cp_aead_tests testcases[] = {

	{ "AES(G) GCM(G) 128", "gcm(aes-generic)", 16, 16, 0 },
	{ "AES(G) GCM(G) 192", "gcm(aes-generic)", 24, 16, 0 },
	{ "AES(G) GCM(G) 256", "gcm(aes-generic)", 32, 16, 0 },
	{ "AES(AESNI) GCM(ASM-RFC) 128", "rfc4106-gcm-aesni", 20, 16, 0 },
	{ "AES(AESNI) GCM(ASM-RFC) 192", "rfc4106-gcm-aesni", 28, 16, 0 },
	{ "AES(AESNI) GCM(ASM-RFC) 256", "rfc4106-gcm-aesni", 36, 16, 0 },
	{ "AES(AESNI) GCM(G) 128", "gcm(aes-aesni)", 16, 16, 0 },
	{ "AES(AESNI) GCM(G) 192", "gcm(aes-aesni)", 24, 16, 0 },
	{ "AES(AESNI) GCM(G) 256", "gcm(aes-aesni)", 32, 16, 0 },
	{ "AES(G) CCM(G) 128", "ccm(aes-generic)", 16, 16, 1 },
	{ "AES(G) CCM(G) 192", "ccm(aes-generic)", 24, 16, 1 },
	{ "AES(G) CCM(G) 256", "ccm(aes-generic)", 32, 16, 1 },
	{ "AES(AESNI) CCM(G) 128", "ccm(aes-aesni)", 16, 16, 1 },
	{ "AES(AESNI) CCM(G) 192", "ccm(aes-aesni)", 24, 16, 1 },
	{ "AES(AESNI) CCM(G) 256", "ccm(aes-aesni)", 32, 16, 1 },
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
			j += (size_t)enc;
			cp_aead_testdef[j].enc = enc;
			cp_aead_testdef[j].testname = testcases[i].testname;
			cp_aead_testdef[j].driver_name = testcases[i].driver_name;
			cp_aead_testdef[j].type = "aead";
			cp_aead_testdef[j].exectime = DFLT_EXECTIME;
			cp_aead_testdef[j].u.aead.keysize = testcases[i].keysize;
			cp_aead_testdef[j].u.aead.assoclen = testcases[i].assoclen;
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
