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
#include <kcapi.h>

int main(int argc, char *argv[])
{
        char buf[8192];
        struct kcapi_handle *handle;
        struct iovec iov;
        ssize_t ret;
	int i;

        (void)argc;
        (void)argv;

        iov.iov_base = buf;

        ret = kcapi_cipher_init(&handle, "cbc(aes)", 0);
        if (ret)
                return (int)ret;

        ret = kcapi_cipher_setkey(handle, (unsigned char *)"0123456789abcdef", 16);
        if (ret)
                return (int)ret;

        ret = kcapi_cipher_stream_init_enc(handle, (unsigned char *)"0123456789abcdef", NULL, 0);
        if (ret < 0)
                return (int)ret;

	for (i = 0; i < 100; i++) {
		//printf("round %d\n", i);

		iov.iov_len = 6182;
		ret = kcapi_cipher_stream_update(handle, &iov, 1);
		if (ret < 0)
			return (int)ret;

		iov.iov_len = 6182;
		ret = kcapi_cipher_stream_op(handle, &iov, 1);
		if (ret < 0)
			return (int)ret;
	}

        kcapi_cipher_destroy(handle);

        return 0;
}
