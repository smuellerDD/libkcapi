/* libkcapi Utilities API
 *
 * Copyright (C) 2016 - 2018, Stephan Mueller <smueller@chronox.de>
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

DSO_PUBLIC
void kcapi_set_verbosity(enum kcapi_verbosity level)
{
	kcapi_verbosity_level = level;
}

DSO_PUBLIC
void kcapi_versionstring(char *buf, uint32_t buflen)
{
	snprintf(buf, buflen, "libkcapi%s%d.%d.%.f",
		 (((uint32_t)KCAPI_PATCHLEVEL != KCAPI_PATCHLEVEL) ?
							 " pre-release " : " "),
		 KCAPI_MAJVERSION, KCAPI_MINVERSION, (double)KCAPI_PATCHLEVEL);
}

DSO_PUBLIC
uint32_t kcapi_version(void)
{
	uint32_t version = 0;

	version =  KCAPI_MAJVERSION * 1000000;
	version += KCAPI_MINVERSION * 10000;
	version += KCAPI_PATCHLEVEL * 100;

	return version;
}

DSO_PUBLIC
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
