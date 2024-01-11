/*
 * Copyright (C) 2017 - 2024, Stephan Mueller <smueller@chronox.de>
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

#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "app-internal.h"

static unsigned int verbosity = KCAPI_LOG_NONE;
static char appname[16];

static char hex_char(unsigned int bin, int u)
{
	char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
	char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				     '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

/**
 * Convert binary string into hex representation
 * @bin [in] input buffer with binary data
 * @binlen [in] length of bin
 * @hex [out] output buffer to store hex data
 * @hexlen [in] length of already allocated hex buffer (should be at least
 *	   twice binlen -- if not, only a fraction of binlen is converted)
 * @u [in] case of hex characters (0=>lower case, 1=>upper case)
 */
void bin2hex(const uint8_t *bin, size_t binlen,
	     char *hex, size_t hexlen, int u)
{
	uint32_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

void bin2print(const uint8_t *bin, size_t binlen,
	       const char *filename, FILE *outfile, uint32_t lfcr)
{
	char *hex;
	size_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	/* fipshmac does not want the file name :-( */
	if (outfile != stdout)
		fprintf(outfile, "%s", hex);
	else
		if (filename)
			fprintf(outfile, "%s  %s", hex, filename);
		else
			fprintf(outfile, "%s", hex);

	if (lfcr == 1)
		fputc(0x0a, outfile);
	if (lfcr == 2)
		fputc(0x00, outfile);

	free(hex);
}

void dolog(enum kcapi_verbosity severity, const char *fmt, ...)
{
	va_list args;
	char msg[1024];
	char sev[16];

	if (severity > verbosity)
		return;

	memset(sev, 0, sizeof(sev));
	memset(msg, 0, sizeof(msg));

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg) - 1, fmt, args);
	va_end(args);

	switch (severity) {
	case KCAPI_LOG_DEBUG:
		snprintf(sev, sizeof(sev), "Debug");
		break;
	case KCAPI_LOG_VERBOSE:
		snprintf(sev, sizeof(sev), "Verbose");
		break;
	case KCAPI_LOG_WARN:
		snprintf(sev, sizeof(sev), "Warning");
		break;
	case KCAPI_LOG_ERR:
		snprintf(sev, sizeof(sev), "Error");
		break;
	default:
		snprintf(sev, sizeof(sev), "Unknown");
	}
	fprintf(stderr, "%s - %s: %s\n", appname, sev, msg);
}

void dolog_bin(enum kcapi_verbosity severity,
	       const uint8_t *bin, uint32_t binlen, const char *explanation)
{
	char *hex;
	uint32_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	dolog(severity, "%s: %s", explanation, hex);
	free(hex);
}

void set_verbosity(const char *name, enum kcapi_verbosity level)
{
	strncpy(appname, name, sizeof(appname) - 1);
	appname[sizeof(appname) - 1] = '\0';
	kcapi_set_verbosity(level);
	verbosity = level;
}

static uint8_t bin_char(char hex)
{
	if (48 <= hex && 57 >= hex)
		return (uint8_t)(hex - 48);
	if (65 <= hex && 70 >= hex)
		return (uint8_t)(hex - 55);
	if (97 <= hex && 102 >= hex)
		return (uint8_t)(hex - 87);
	return 0;
}

/**
 * Convert hex representation into binary string
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin output buffer with binary data
 * @binlen length of already allocated bin buffer (should be at least
 *	   half of hexlen -- if not, only a fraction of hexlen is converted)
 */
void hex2bin(const char *hex, uint32_t hexlen, uint8_t *bin, uint32_t binlen)
{
	uint32_t i;
	uint32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	/*
	 * handle odd-length of strings where the first digit is the least
	 * significant nibble
	 */
	if (hexlen & 1) {
		bin[0] = bin_char(hex[0]);
		bin++;
		hex++;
	}

	for (i = 0; i < chars; i++) {
		bin[i] = (uint8_t)(bin_char(hex[(i*2)]) << 4);
		bin[i] |= bin_char(hex[((i*2)+1)]);
	}
}

/**
 * Allocate sufficient space for binary representation of hex
 * and convert hex into bin
 *
 * Caller must free bin
 * @hex input buffer with hex representation
 * @hexlen length of hex
 * @bin return value holding the pointer to the newly allocated buffer
 * @binlen return value holding the allocated size of bin
 *
 * return: 0 on success, !0 otherwise
 */
int hex2bin_alloc(const char *hex, uint32_t hexlen,
		  uint8_t **bin, uint32_t *binlen)
{
	uint8_t *out = NULL;
	uint32_t outlen = 0;
	int ret;

	if (!hexlen)
		return -EINVAL;

	outlen = (hexlen + 1) / 2;

	ret = posix_memalign((void *)&out, 16, outlen);
	if (ret)
		return -ret;

	hex2bin(hex, hexlen, out, outlen);
	*bin = out;
	*binlen = outlen;
	return 0;
}

ssize_t read_complete(int fd, uint8_t *buf, size_t buflen)
{
	ssize_t ret;
	ssize_t rc = 0;

	if (buflen > INT_MAX)
		return -EINVAL;

	do {
		ret = read(fd, buf, buflen);
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += ret;
		}
		rc += ret;
		if (ret)
			break;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

	return rc;
}

int check_filetype(int fd, struct stat *sb, const char *filename)
{
	int ret = fstat(fd, sb);
	if (ret) {
		dolog(KCAPI_LOG_ERR,
		      "fstat() failed: %s", strerror(errno));
		return -errno;
	}

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK) {
		dolog(KCAPI_LOG_ERR,
		      "%s is no regular file or symlink", filename);
		return -EINVAL;
	}

	return 0;
}
