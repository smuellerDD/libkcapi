/*
 * Copyright (C) 2017 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <kcapi.h>

static int hashtest(void)
{
	char *in = "teststring";
	uint8_t out[64];
	ssize_t ret;

	ret = kcapi_md_sha1((uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 20) {
		printf("SHA-1 error");
		return 1;
	}

	ret = kcapi_md_sha224((uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 28) {
		printf("SHA-224 error");
		return 1;
	}

	ret = kcapi_md_sha256((uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 32) {
		printf("SHA-256 error");
		return 1;
	}

	ret = kcapi_md_sha384((uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 48) {
		printf("SHA-384 error");
		return 1;
	}

	ret = kcapi_md_sha512((uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 64) {
		printf("SHA-512 error");
		return 1;
	}

	return 0;
}

static int hmactest(void)
{
	char *in = "teststring";
	uint8_t out[64];
	ssize_t ret;

	ret = kcapi_md_hmac_sha1((uint8_t*)in, (uint32_t)strlen(in),
				 (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 20) {
		printf("HMAC SHA-1 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha224((uint8_t*)in, (uint32_t)strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 28) {
		printf("HMAC SHA-224 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha256((uint8_t*)in, (uint32_t)strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 32) {
		printf("HMAC SHA-256 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha384((uint8_t*)in, (uint32_t)strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 48) {
		printf("HMAC SHA-384 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha512((uint8_t*)in, (uint32_t)strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 64) {
		printf("HMAC SHA-512 error");
		return 1;
	}

	return 0;
}

static int ciphertest(void)
{
	uint8_t *origpt = (uint8_t *)"01234567890123450123456789012345";
	uint8_t ct[32];
	uint8_t newpt[32];
	ssize_t ret;

	ret = kcapi_cipher_enc_aes_cbc(origpt, 32, origpt, 32, origpt,
				       ct, sizeof(ct));
	if (ret != sizeof(ct)) {
		printf("AES CBC encrytion error");
		return 1;
	}

	ret = kcapi_cipher_dec_aes_cbc(origpt, 32, ct, sizeof(ct), origpt,
				       newpt, sizeof(newpt));
	if (ret != sizeof(newpt) || memcmp(origpt, newpt, sizeof(newpt))) {
		printf("AES CBC decrytion error");
		return 1;
	}

	ret = kcapi_cipher_enc_aes_ctr(origpt, 32, origpt, 32, origpt, ct,
				       sizeof(ct));
	if (ret != sizeof(ct)) {
		printf("AES CTR encrytion error");
		return 1;
	}

	ret = kcapi_cipher_dec_aes_ctr(origpt, 32, ct, sizeof(ct), origpt,
				       newpt, sizeof(newpt));
	if (ret != sizeof(newpt) || memcmp(origpt, newpt, sizeof(newpt))) {
		printf("AES CTR decrytion error");
		return 1;
	}

	return 0;
}

static int rngtest(void)
{
	uint8_t out[67];
	ssize_t ret;

	ret = kcapi_rng_get_bytes(out, sizeof(out));
	if (ret != sizeof(out)) {
		printf("Random number generation error");
		return 1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	(void)argc;
	(void)argv;

	ret = hashtest();
	if (ret)
		return ret;

	ret = hmactest();
	if (ret)
		return ret;

	ret = ciphertest();
	if (ret)
		return ret;

	ret = rngtest();
	if (ret)
		return ret;

        return 0;
}
