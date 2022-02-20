/*
 * Copyright (C) 2017 - 2022, Stephan Mueller <smueller@chronox.de>
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

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <linux/random.h>
#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif

#include <kcapi.h>

#include "app-internal.h"

/* For efficiency reasons, this should be identical to algif_rng.c:MAXSIZE. */
#define KCAPI_RNG_BUFSIZE  128
/* Minimum seed is 256 bits. */
#define KCAPI_RNG_MINSEEDSIZE 32

static struct kcapi_handle *rng = NULL;
static unsigned int Verbosity = KCAPI_LOG_WARN;
static char *rng_name = NULL;
static bool hexout = false;

#if !defined(HAVE_GETRANDOM) && !defined(__NR_getrandom)
static int random_fd = -1;
static int open_random(void)
{
	random_fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
	if (0 > random_fd)
		return random_fd;

	return 0;
}

static void close_random(void)
{
	close(random_fd);
}
#endif

static ssize_t get_random(uint8_t *buf, size_t buflen)
{
	ssize_t ret;

	if (buflen > INT_MAX)
		return 1;

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	ret = open_random();
	if (ret)
		return ret;
#endif

	do {
#ifdef HAVE_GETRANDOM
		ret = getrandom(buf, buflen, 0);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed getrandom system call for %lu bytes", buflen);
#elif defined __NR_getrandom
		ret = syscall(__NR_getrandom, buf, buflen, 0);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed getrandom system call for %lu bytes", buflen);
#else
		ret = read(random_fd, buf, buflen);
		dolog(KCAPI_LOG_DEBUG,
		      "Accessed /dev/urandom for %lu bytes", buflen);
#endif
		if (0 < ret) {
			buflen -= (size_t)ret;
			buf += (size_t)ret;
		}
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

#if (!defined(HAVE_GETRANDOM) && !defined(__NR_getrandom))
	close_random();
#endif

	if (buflen == 0)
		return 0;
	return 1;
}

static void usage(void)
{
	char version[30];
	uint32_t ver = kcapi_version();

	memset(version, 0, sizeof(version));
	kcapi_versionstring(version, sizeof(version));

	fprintf(stderr, "\nKernel Crypto API Random Number Gatherer\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-b --bytes <BYTES>\tNumber of bytes to generate (required option)\n");
	fprintf(stderr, "\t-n --name <RNGNAME>\tDRNG name as advertised in /proc/crypto\n");
	fprintf(stderr, "\t\t\t\t(stdrng is default)\n");
	fprintf(stderr, "\t   --hex\t\tThe random number is returned in hexadecimal\n");
	fprintf(stderr, "\t\t\t\tnotation\n");
	fprintf(stderr, "\t-h --help\t\tThis help information\n");
	fprintf(stderr, "\t   --version\t\tPrint version\n");
	fprintf(stderr, "\t-v --verbose\t\tVerbose logging, multiple options increase\n");
	fprintf(stderr, "\t\t\t\tverbosity\n");
	fprintf(stderr, "\nData provided at stdin is used to seed the DRNG\n");

	exit(1);
}

static int parse_opts(int argc, char *argv[], size_t *outlen)
{
	int c = 0;
	char version[30];
	size_t bytes = 0;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = {
			{"verbose",	no_argument,		0, 'v'},
			{"quiet",	no_argument,		0, 'q'},
			{"help",	no_argument,		0, 'h'},
			{"version",	no_argument,		0, 0},
			{"bytes",	required_argument,	0, 'b'},
			{"name",	required_argument,	0, 'n'},
			{"hex",		no_argument,		0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "vqhb:n:", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				Verbosity++;
				break;
			case 1:
				Verbosity = KCAPI_LOG_NONE;
				break;
			case 2:
				usage();
				break;
			case 3:
				memset(version, 0, sizeof(version));
				kcapi_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				exit(0);
				break;
			case 4:
				bytes = strtoul(optarg, NULL, 10);
				if (bytes == ULONG_MAX) {
					usage();
					return -EINVAL;
				}
				break;
			case 5:
				rng_name = optarg;
				break;
			case 6:
				hexout = true;
				break;
			default:
				usage();
			}
			break;
		case 'v':
			Verbosity++;
			break;
		case 'q':
			Verbosity = KCAPI_LOG_NONE;
			break;
		case 'h':
			usage();
			break;
		case 'b':
			bytes = strtoul(optarg, NULL, 10);
			if (bytes == ULONG_MAX) {
				usage();
				return -EINVAL;
			}
			break;
		case 'n':
			rng_name = optarg;
			break;
		default:
			usage();
		}
	}

	if (!bytes)
		usage();

	*outlen = (size_t)bytes;
	return 0;
}

int main(int argc, char *argv[])
{
	ssize_t ret;
	uint8_t buf[KCAPI_RNG_BUFSIZE] __aligned(KCAPI_APP_ALIGN);
	uint8_t *seedbuf = buf;
	uint32_t seedsize = 0;
	size_t outlen;

	ret = parse_opts(argc, argv, &outlen);
	if (ret)
		return (int)ret;

	set_verbosity("kcapi-rng", Verbosity);

	if (rng_name)
		ret = kcapi_rng_init(&rng, rng_name, 0);
	else
		ret = kcapi_rng_init(&rng, "stdrng", 0);
	if (ret)
		return (int)ret;

	seedsize = kcapi_rng_seedsize(rng);
	if (seedsize) {
		/*
		 * Only reseed, if there is a seedsize defined. For example,
		 * the DRBG has a seedsize of 0 because it seeds itself from
		 * known good noise sources.
		 */
		if (seedsize < KCAPI_RNG_MINSEEDSIZE)
			seedsize = KCAPI_RNG_MINSEEDSIZE;

		/*
		 * Only allocate a new buffer if our buffer is
		 * insufficiently large.
		 */
		if (seedsize > KCAPI_RNG_BUFSIZE) {
			seedbuf = calloc(1, seedsize);
			if (!seedbuf) {
				ret = -ENOMEM;
				goto out;
			}
		}

		ret = get_random(seedbuf, seedsize);
		if (ret)
			goto out;
	}

	/*
	 * Invoke seeding even if seedsize is 0 -- this also triggers any
	 * internal seeding operation like in the DRBG.
	 */
	ret = kcapi_rng_seed(rng, seedbuf, seedsize);
	if (ret)
		goto out;
	dolog(KCAPI_LOG_DEBUG, "Seeding the DRNG with %u bytes of data",
	      seedsize);

	if (!isatty(0) && (errno == EINVAL || errno == ENOTTY)) {
		while (fgets((char *)seedbuf, (int)seedsize, stdin)) {
			ret = kcapi_rng_seed(rng, seedbuf, seedsize);
			if (ret)
				dolog(KCAPI_LOG_WARN,
				      "User-provided seed of %lu bytes not accepted by DRNG (error: %ld)",
				      (unsigned long)sizeof(buf), ret);
			else
				dolog(KCAPI_LOG_DEBUG,
				      "User-provided seed of %u bytes",
				      seedsize);
		}
	}

	while (outlen) {
		size_t todo = (outlen < KCAPI_RNG_BUFSIZE) ?
					outlen : KCAPI_RNG_BUFSIZE;

		ret = kcapi_rng_generate(rng, buf, todo);
		if (ret < 0)
			goto out;

		if ((uint32_t)ret == 0) {
			ret = -EFAULT;
			goto out;
		}

		if (hexout) {
			char hexbuf[2 * KCAPI_RNG_BUFSIZE];

			bin2hex(buf, (size_t)ret, hexbuf, sizeof(hexbuf), 0);
			fwrite(hexbuf, 2 * (size_t)ret, 1, stdout);
		} else {
			fwrite(buf, (size_t)ret, 1, stdout);
		}

		outlen -= (size_t)ret;
	}

	ret = 0;

out:
	if (rng)
		kcapi_rng_destroy(rng);
	kcapi_memset_secure(buf, 0, sizeof(buf));

	/* Free seedbuf if it was allocated. */
	if (seedbuf && (seedbuf != buf)) {
		kcapi_memset_secure(seedbuf, 0, seedsize);
		free(seedbuf);
	}

	return (int)ret;
}
