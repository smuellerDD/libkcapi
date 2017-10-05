/*
 * Copyright (C) 2017, Stephan Mueller <smueller@chronox.de>
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

int main(int argc, char *argv[])
{
        char *in = "teststring";
	uint8_t out[64];
	int32_t ret;

	(void)argc;
	(void)argv;

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

	ret = kcapi_md_hmac_sha1((uint8_t*)in, strlen(in),
				 (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 20) {
		printf("HMAC SHA-1 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha224((uint8_t*)in, strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 28) {
		printf("HMAC SHA-224 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha256((uint8_t*)in, strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 32) {
		printf("HMAC SHA-256 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha384((uint8_t*)in, strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 48) {
		printf("HMAC SHA-384 error");
		return 1;
	}

	ret = kcapi_md_hmac_sha512((uint8_t*)in, strlen(in),
				   (uint8_t*)in, strlen(in), out, sizeof(out));
	if (ret != 64) {
		printf("HMAC SHA-512 error");
		return 1;
	}

        return 0;
}
