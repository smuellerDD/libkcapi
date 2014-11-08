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
 * the GNU General Public License, in which case the provisions of the GPL2 are
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>

#include "kcapi.h"

static char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(unsigned int bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/*
 * Convert binary string into hex representation
 * @bin input buffer with binary data
 * @binlen length of bin
 * @hex output buffer to store hex data
 * @hexlen length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u case of hex characters (0=>lower case, 1=>upper case)
 */
static void bin2hex(const unsigned char *bin, size_t binlen,
		    char *hex, size_t hexlen, int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

static int bin_char(unsigned char hex)
{
	if (48 <= hex && 57 >= hex)
		return (hex - 48);
	if (65 <= hex && 70 >= hex)
		return (hex - 55);
	if (97 <= hex && 102 >= hex)
		return (hex - 87);
	return 0;
}

/*
 * Convert hex representation into binary string
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin output buffer with binary data
 * @binlen length of already allocated bin buffer (should be at least
 *	   half of hexlen -- if not, only a fraction of hexlen is converted)
 */
static void hex2bin(const char *hex, size_t hexlen,
		    unsigned char *bin, size_t binlen)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		bin[i] = bin_char(hex[(i*2)]) << 4;
		bin[i] |= bin_char(hex[((i*2)+1)]);
	}
}

static int hex2bin_m(const char *hex, size_t hexlen,
		     unsigned char **bin, size_t binlen)
{
	unsigned char *buf = NULL;

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

void aux_test_rng(char *name)
{
	struct kcapi_handle handle;
#define RNGOUTBUF 150
	unsigned char outbuf[RNGOUTBUF];
	char hex[RNGOUTBUF * 2 + 1];
	ssize_t ret = 0;

	if (kcapi_rng_init(&handle, name)) {
                printf("Allocation of cipher %s failed\n", name);
                return;
        }

	ret = kcapi_rng_generate(&handle, outbuf, RNGOUTBUF);
	if (0 > ret) {
		printf("Failure to generate random numbers %d\n",
		       (int)ret);
		kcapi_rng_destroy(&handle);
		return;
	}
	if (ret != RNGOUTBUF) {
		printf("RNG only returned %d bytes (requested %d)\n",
		       (int)ret, RNGOUTBUF);
	}
	memset(hex, 0, RNGOUTBUF * 2 + 1);
	bin2hex(outbuf, ret, hex, RNGOUTBUF * 2 + 1, 0);
	printf("RNG %s returned: %s\n", name, hex);
	kcapi_rng_destroy(&handle);
}

void auxiliary_tests(void)
{
	struct kcapi_handle handle;

        if (kcapi_aead_init(&handle, "ccm(aes)")) {
                printf("Allocation of cipher failed\n");
                return;
        }
        {
		int iv = kcapi_aead_ivsize(&handle);
		int bs = kcapi_aead_blocksize(&handle);
		int au = kcapi_aead_authsize(&handle);
		printf("AEAD sizes: IV %d BS %d AUTH %d\n", iv, bs, au);
	}
	kcapi_aead_destroy(&handle);


        if (kcapi_cipher_init(&handle, "cbc(aes)")) {
                printf("Allocation of cipher failed\n");
                return;
        }
        {
		int iv = kcapi_cipher_ivsize(&handle);
		int bs = kcapi_cipher_blocksize(&handle);
		printf("Symmetric cipher sizes: IV %d BS %d\n", iv, bs);
	}
	kcapi_cipher_destroy(&handle);

	aux_test_rng("drbg_nopr_hmac_sha256");
	aux_test_rng("drbg_nopr_sha1");
	aux_test_rng("drbg_nopr_ctr_aes256");
	aux_test_rng("ansi_cprng");
}

/************************************************************************
 * CAVS TESTING
 ************************************************************************/

static void usage(void)
{
	char version[20];

	memset(version, 0, 20);
	kcapi_versionstring(version, 20);

	fprintf(stderr, "\nKernel Crypto API CAVS Test\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n\n", version);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-e\tIf set, encrypt otherwise decrypt\n");
	fprintf(stderr, "\t-c\tKernel Crypto API cipher name to be used for operation\n");
	fprintf(stderr, "\t-p\tPlaintext used during encryption / message digest\n");
	fprintf(stderr, "\t-q\tCiphertext used durign decryption\n");
	fprintf(stderr, "\t-i\tIV used for operation\n");
	fprintf(stderr, "\t-n\tNonce used for CCM operation\n");
	fprintf(stderr, "\t-k\tSymmetric cipher key / HMAC key\n");
	fprintf(stderr, "\t-a\tAssociated data used for AEAD cipher\n");
	fprintf(stderr, "\t-l\tTag length to be produced during encryption for AEAD cipher\n");
	fprintf(stderr, "\t-t\tTag to be used for decryption\n");
	fprintf(stderr, "\t-x\tCipher type with one out of the following\n");
	fprintf(stderr, "\t\t\t1 for symmetric cipher algorithm\n");
	fprintf(stderr, "\t\t\t2 for AEAD cipher algorithm\n");
	fprintf(stderr, "\t\t\t3 for message digest and keyed message digest\n");
	fprintf(stderr, "\t-z\tAuxiliary tests of the API\n");
}

enum type {
	SYM = 1,
	AEAD,
	HASH
};

struct kcapi_cavs {
#define CIPHERMAXNAME 30
	char cipher[CIPHERMAXNAME];
	int enc;
	int type;
	unsigned char *pt;
	size_t ptlen;
	unsigned char *ct;
	size_t ctlen;
	unsigned char *iv;
	size_t ivlen;
	unsigned char *key;
	size_t keylen;
	unsigned char *assoc;
	size_t assoclen;
	unsigned char *tag;
	size_t taglen;
	size_t outlen;
};

/*
 * Encryption command line:
 * $ ./kcapi -x 1 -e -c "cbc(aes)" -k 8d7dd9b0170ce0b5f2f8e1aa768e01e91da8bfc67fd486d081b28254c99eb423 -i 7fbc02ebf5b93322329df9bfccb635af -p 48981da18e4bb9ef7e2e3162d16b1910
 * 8b19050f66582cb7f7e4b6c873819b71
 *
 * Decryption command line:
 * $ ./kcapi -x 1 -c "cbc(aes)" -k 3023b2418ea59a841757dcf07881b3a8def1c97b659a4dad  -i 95aa5b68130be6fcf5cabe7d9f898a41 -q c313c6b50145b69a77b33404cb422598
 * 836de0065f9d6f6a3dd2c53cd17e33a5
 */
static int cavs_sym(struct kcapi_cavs *cavs_test)
{
	struct kcapi_handle handle;
	char *outhex = NULL;
	int ret;

	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
	} else {
		if (!cavs_test->ctlen)
			return -EINVAL;
	}

	if (kcapi_cipher_init(&handle, cavs_test->cipher)) {
		printf("Allocation of cipher failed\n");
		return -EINVAL;
	}

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_cipher_setkey(&handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		kcapi_cipher_destroy(&handle);
		return -EINVAL;
	}

	/* Setting the IV for the cipher operations */
	if (cavs_test->ivlen && cavs_test->iv)
		kcapi_cipher_setiv(&handle, cavs_test->iv, cavs_test->ivlen);

	if (cavs_test->enc) {
		ret = kcapi_cipher_encrypt(&handle,
					   cavs_test->pt, cavs_test->ptlen,
					   cavs_test->pt, cavs_test->ptlen);
	} else {
		ret = kcapi_cipher_decrypt(&handle,
					   cavs_test->ct, cavs_test->ctlen,
					   cavs_test->ct, cavs_test->ctlen);
	}
	kcapi_cipher_destroy(&handle);
	if (0 > ret)  {
		printf("Encryption buffer failed\n");
		return 1;
	}

	if (cavs_test->enc)
		outhex = calloc(1, (cavs_test->ptlen) * 2 + 1);
	else
		outhex = calloc(1, (cavs_test->ctlen) * 2 + 1);
	if (!outhex)
		return -ENOMEM;
	if (cavs_test->enc)
		bin2hex(cavs_test->pt, cavs_test->ptlen,
			outhex, (cavs_test->ptlen) * 2 + 1, 0);
	else
		bin2hex(cavs_test->ct, cavs_test->ctlen,
			outhex, (cavs_test->ctlen) * 2 + 1, 0);
	printf("%s\n", outhex);
	free(outhex);

	return 0;
}

static unsigned char *concatenate(const unsigned char *buf1, size_t buf1len,
				  const unsigned char *buf2, size_t buf2len)
{
	unsigned char *outbuf = NULL;

	outbuf = calloc(1, buf1len + buf2len);
	if (!outbuf)
		return NULL;

	memcpy(outbuf, buf1, buf1len);
	memcpy(outbuf + buf1len, buf2, buf2len);

	return outbuf;
}

/* FIXME remove the check in skcipher sendmsg handler for ivlen == blocklen */
static unsigned char *pad_iv(const unsigned char *iv, size_t ivlen,
			     size_t newlen)
{
	unsigned char *newiv = NULL;

	newiv = calloc(1, newlen);
	if (!newiv)
		return NULL;
	memcpy(newiv, iv, ivlen);

	return newiv;
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
 * The kernel interface does not support zero length plaintext -- in this case
 * the AEAD cipher will simply not be called.
 *
 * The kernel interface does not support zero length AAD -- in this case
 * the kernel waits for more input data and a read will be blocked until the
 * AAD is supplied.
 */
static int cavs_aead(struct kcapi_cavs *cavs_test)
{
	struct kcapi_handle handle;
	unsigned char *outbuf = NULL;
	size_t outbuflen = 0;
	char *outhex = NULL;
	unsigned char *cttag = NULL;
	int ret = -ENOMEM;
	unsigned char *newiv;
	int errsv = 0;

	if (!cavs_test->taglen)
		return -EINVAL;
	if (!cavs_test->ivlen || !cavs_test->iv)
		return -EINVAL;
	if (cavs_test->enc) {
		if (!cavs_test->ptlen)
			return -EINVAL;
		outbuflen = cavs_test->ptlen + cavs_test->taglen;
	} else {
		if (!cavs_test->taglen || !cavs_test->tag)
			return -EINVAL;
		outbuflen = cavs_test->ctlen;
		cttag = concatenate(cavs_test->ct, cavs_test->ctlen,
				    cavs_test->tag, cavs_test->taglen);
		if (!cttag)
			return -ENOMEM;
	}
	outbuf = calloc(1, outbuflen);
	if (!outbuf)
		goto out;

	ret = -EINVAL;
	if (kcapi_aead_init(&handle, cavs_test->cipher)) {
		printf("Allocation of cipher failed\n");
		goto out;
	}

	/* FIXME -- should be removed */
	newiv = pad_iv(cavs_test->iv, cavs_test->ivlen,
		       kcapi_aead_ivsize(&handle));
	if (!newiv)
		goto out;

	/* Set key */
	if (!cavs_test->keylen || !cavs_test->key ||
	    kcapi_aead_setkey(&handle, cavs_test->key, cavs_test->keylen)) {
		printf("Symmetric cipher setkey failed\n");
		goto out;
	}

	/* Setting the IV for the cipher operations */
	kcapi_aead_setiv(&handle, newiv, 16);

	/* Setting the associated data */
	if (cavs_test->assoclen && cavs_test->assoc)
		kcapi_aead_setassoc(&handle, cavs_test->assoc,
				    cavs_test->assoclen);

	/* Setting the tag length */
	kcapi_aead_settaglen(&handle, cavs_test->taglen);

	ret = -EIO;
	if (cavs_test->enc)
		ret = kcapi_aead_encrypt(&handle,
					 cavs_test->pt, cavs_test->ptlen,
					 outbuf, outbuflen);
	else
		ret = kcapi_aead_decrypt(&handle, cttag,
					 cavs_test->ctlen + cavs_test->taglen,
					 outbuf, outbuflen);
	errsv = errno;
	if (0 > ret && EBADMSG != errsv){
		printf("Cipher operation of buffer failed: %d %d\n", errno, ret);
		goto out;
	}

	if (EBADMSG == errsv) {
		printf("EBADMSG\n");
		ret = 0;
		goto out;
	}

	ret = -ENOMEM;
	outhex = calloc(1, (outbuflen * 2 + 1));
	if (!outhex)
		goto out;
	bin2hex(outbuf, outbuflen, outhex, outbuflen * 2 + 1, 0);
	printf("%s\n", outhex);

	ret = 0;

out:
	kcapi_aead_destroy(&handle);
	if (newiv)
		free(newiv);
	if (outbuf)
		free(outbuf);
	if (cttag)
		free(cttag);
	if (outhex)
		free(outhex);
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
static int cavs_hash(struct kcapi_cavs *cavs_test)
{
	struct kcapi_handle handle;
	int rc = 0;
#define MAXMD 64
	unsigned char md[MAXMD];
#define MAXMDHEX (MAXMD * 2 + 1)
	char mdhex[MAXMDHEX];

	if (cavs_test->outlen > MAXMD)
		return -EINVAL;

	memset(md, 0, MAXMD);
	memset(mdhex, 0, MAXMDHEX);

	if (kcapi_md_init(&handle, cavs_test->cipher)) {
		printf("Allocation of hash failed\n");
		return 1;
	}
	/* HMAC */
	if (cavs_test->keylen) {
		if (kcapi_md_setkey(&handle, cavs_test->key,
					cavs_test->keylen)) {
			printf("HMAC setkey failed\n");
			kcapi_md_destroy(&handle);
			return 1;
		}
	}
	if (kcapi_md_update(&handle, cavs_test->pt, cavs_test->ptlen)) {
		printf("Hash update of buffer failed\n");
		kcapi_md_destroy(&handle);
		return 1;
	}
	rc = kcapi_md_final(&handle, md,
			    cavs_test->outlen ? cavs_test->outlen : MAXMD);
	if (0 > rc) {
		printf("Hash final failed\n");
		kcapi_md_destroy(&handle);
		return 1;
	}
	kcapi_md_destroy(&handle);

	bin2hex(md, rc, mdhex, MAXMDHEX, 0);
	printf("%s\n", mdhex);
	return 0;
}

int main(int argc, char *argv[])
{
	int c = 0;
	int ret = 1;
	int rc = 1;
	struct kcapi_cavs cavs_test;

	memset(&cavs_test, 0, sizeof(struct kcapi_cavs));

	while(1)
	{
		int opt_index = 0;
		size_t len = 0;
		static struct option opts[] =
		{
			{"enc", 0, 0, 0},
			{"cipher", 1, 0, 0},
			{"pt", 1, 0, 0},
			{"ct", 1, 0, 0},
			{"iv", 1, 0, 0},
			{"nonce", 1, 0, 0},
			{"key", 1, 0, 0},
			{"assoc", 1, 0, 0},
			{"taglen", 1, 0, 0},
			{"tag", 1, 0, 0},
			{"ciphertype", 1, 0, 0},
			{"aux", 0, 0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "ec:p:q:i:n:k:a:l:t:x:z", opts, &opt_index);
		if(-1 == c)
			break;
		switch(c)
		{
			case 'e':
				cavs_test.enc = 1;
				break;
			case 'c':
				strncpy(cavs_test.cipher, optarg,
					CIPHERMAXNAME);
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
				cavs_test.ivlen = len / 2;
				break;
			case 'n':
			{
				unsigned char *nonce;
				len = strlen(optarg);
				ret = hex2bin_m(optarg, len, &nonce, len / 2);
				if (ret)
					goto out;
				ret = kcapi_aead_ccm_nonce_to_iv(nonce, len / 2,
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
				cavs_test.keylen = len / 2;
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
				len = atoi(optarg);
				if (cavs_test.taglen &&
				    len != cavs_test.taglen) {
					printf("Set taglen != tag size\n");
					goto out;
				}
				cavs_test.taglen = len;
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
				cavs_test.taglen = len / 2;
				break;
			case 'x':
				cavs_test.type = atoi(optarg);
				break;
			case 'z':
				auxiliary_tests();
				rc = 0;
				goto out;
				break;
			default:
				usage();
				goto out;
		}
	}

	if (SYM == cavs_test.type)
		rc = cavs_sym(&cavs_test);
	else if (AEAD == cavs_test.type)
		rc = cavs_aead(&cavs_test);
	else if (HASH == cavs_test.type)
		rc = cavs_hash(&cavs_test);
	else
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
	if (cavs_test.assoc)
		free(cavs_test.assoc);
	if (cavs_test.tag)
		free(cavs_test.tag);
	return rc;
}
