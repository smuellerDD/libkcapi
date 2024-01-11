/* libkcapi Utilities API
 *
 * Copyright (C) 2016 - 2024, Stephan Mueller <smueller@chronox.de>
 *
 * License: see COPYING file in root directory
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

#include "internal.h"
#include "kcapi.h"

void kcapi_set_verbosity(enum kcapi_verbosity level)
{
	kcapi_verbosity_level = level;
}

void kcapi_versionstring(char *buf, uint32_t buflen)
{
	snprintf(buf, buflen, "libkcapi%s%d.%d.%.f",
		 (((uint32_t)KCAPI_PATCHLEVEL != KCAPI_PATCHLEVEL) ?
							 " pre-release " : " "),
		 KCAPI_MAJVERSION, KCAPI_MINVERSION, (double)KCAPI_PATCHLEVEL);
}

uint32_t kcapi_version(void)
{
	uint32_t version = 0;

	version =  KCAPI_MAJVERSION * 1000000;
	version += KCAPI_MINVERSION * 10000;
	version += KCAPI_PATCHLEVEL * 100;

	return version;
}

int kcapi_pad_iv(struct kcapi_handle *handle,
		 const uint8_t *iv, uint32_t ivlen,
		 uint8_t **newiv, uint32_t *newivlen)
{
	uint8_t *niv = NULL;
	struct kcapi_handle_tfm *tfm = handle->tfm;
	uint32_t nivlen = tfm->info.ivsize;
	uint32_t copylen = (ivlen > nivlen) ? nivlen : ivlen;
	int ret = 0;

	ret = posix_memalign((void *)&niv, 16, nivlen);
	if (ret)
		return -ret;
	memcpy(niv, iv, copylen);
	if (nivlen > copylen)
		memset(niv + copylen, 0, nivlen - copylen);

	*newiv = niv;
	*newivlen = nivlen;

	return 0;
}

int kcapi_set_maxsplicesize(struct kcapi_handle *handle, unsigned int size)
{
	int ret;

	if (!handle)
		return -EINVAL;

	ret = fcntl(handle->pipes[0], F_SETPIPE_SZ, size);
	if (ret < 0)
		goto err;

	ret = fcntl(handle->pipes[1], F_SETPIPE_SZ, size);
	if (ret < 0)
		goto err;

	handle->pipesize = (unsigned int)ret;

	return 0;

err:
	ret = -errno;
	if (ret == -EBUSY) {
		kcapi_dolog(KCAPI_LOG_WARN,
			    "AF_ALG: setting maximum splice pipe size to %u failed - it would exceed maximum quota",
			    size);
	} else {
		kcapi_dolog(KCAPI_LOG_WARN,
			    "AF_ALG: setting maximum splice pipe size to %u failed: %s",
			    size, strerror(ret));
	}
	return ret;
}

int kcapi_get_maxsplicesize(struct kcapi_handle *handle)
{
	unsigned int pagesize = (unsigned int)sysconf(_SC_PAGESIZE);

	if (!handle)
		return -EINVAL;

	/* Both pipe endpoints should have the same pipe size */
	handle->pipesize = (unsigned int)fcntl(handle->pipes[0], F_GETPIPE_SZ);

	/*
	 * For vmsplice to allow the maximum number of 16 pages, we need to
	 * increase the pipe buffer by one more page - it seems the kernel
	 * uses some parts of the pipe for some house-keeping?!
	 */
	if (handle->pipesize > pagesize)
		handle->pipesize -= pagesize;

	/* TODO: what do we do for pipesize < pagesize? Can that even happen? */

	return ((int)handle->pipesize);
}
