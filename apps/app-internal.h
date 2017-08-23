/*
 * Copyright (C) 2017, Stephan Mueller <smueller@chronox.de>
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

#ifndef _APP_INTERNAL_H
#define _APP_INTERNAL_H

#include <stdint.h>

#include <kcapi.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define STDIN_FD 0
#define STDOUT_FD 1
#define MAX_ALG_PAGES 16
#define TMPBUFLEN (4096 * (MAX_ALG_PAGES - 1))

#define KCAPI_APP_ALIGN 8
#define __aligned(x)	__attribute__((aligned(x)))

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))

typedef enum { false, true } bool;

void dolog(enum kcapi_verbosity severity, const char *fmt, ...);
void dolog_bin(enum kcapi_verbosity severity,
	       const uint8_t *bin, uint32_t binlen, const char *explanation);
void set_verbosity(const char *name, enum kcapi_verbosity level);
void hex2bin(const char *hex, uint32_t hexlen, uint8_t *bin, uint32_t binlen);
int hex2bin_alloc(const char *hex, uint32_t hexlen,
		  uint8_t **bin, uint32_t *binlen);
void bin2hex(const uint8_t *bin, uint32_t binlen,
	     char *hex, uint32_t hexlen, int u);
void bin2print(const uint8_t *bin, uint32_t binlen,
	       const char *filename, FILE *outfile, uint32_t lfcr);
int read_complete(int fd, uint8_t *buf, uint32_t buflen);
int check_filetype(int fd, struct stat *sb, const char *filename);

#ifdef __cplusplus
}
#endif

#endif /* _KCAPI_H */
