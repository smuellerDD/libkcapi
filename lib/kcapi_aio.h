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
 * the GNU General Public License, in which case the provisions of the GPL2
 * are required INSTEAD OF the above restrictions.  (This clause is
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

#ifndef _KCAPI_AIO_H
#define _KCAPI_AIO_H

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/aio_abi.h>

#define KCAPI_AIO_CONCURRENT	64

/**
 * AIO related data structure to hold all information for AIO
 * @skcipher_aio_disable: AIO support for symmetric ciphers not present
 * @efd: event file descriptor
 * @aio_ctx: AIO context to use for AIO syscalls
 * @cio: Active concurrent IOCBs
 */
struct kcapi_aio {
	unsigned int skcipher_aio_disable:1;
	int efd;
	aio_context_t aio_ctx;
	unsigned int curr_cio;
	struct iocb cio[KCAPI_AIO_CONCURRENT];
};

static inline int io_setup(unsigned n, aio_context_t *ctx)
{
    return syscall(__NR_io_setup, n, ctx);
}

static inline int io_destroy(aio_context_t ctx)
{
    return syscall(__NR_io_destroy, ctx);
}

static inline int io_read(aio_context_t ctx, long n,  struct iocb **iocb)
{
    return syscall(__NR_io_submit, ctx, n, iocb);
}

static inline int io_getevents(aio_context_t ctx, long min, long max,
            struct io_event *events, struct timespec *timeout)
{
    return syscall(__NR_io_getevents, ctx, min, max, events, timeout);
}
	
#endif /* _KCAPI_AIO_H */
