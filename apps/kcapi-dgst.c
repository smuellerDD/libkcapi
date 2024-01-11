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

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>

#include "app-internal.h"

struct opt_data {
	const char *infile;
	const char *outfile;
	const char *ciphername;
	const char *passwd;
	const char *salt;
	const char *pbkdf_hash;
	int password_fd;
	int key_fd;
	uint32_t pbkdf_iterations;
	bool keyed_md;
	bool hexout;
};

static int cipher_op(struct kcapi_handle *handle, struct opt_data *opts)
{
	int infd = -1, outfd = -1;
	ssize_t ret = 0;
	struct stat insb, outsb;
	uint8_t *inmem = NULL;
	uint8_t *outmem = NULL;
	uint8_t tmpbuf[TMPBUFLEN] __aligned(KCAPI_APP_ALIGN);
	uint32_t outlen = 0;

	/*
	 * To avoid spurious padding, the buffer must be multiples of the
	 * block size.
	 */
	BUILD_BUG_ON(TMPBUFLEN % 32);

	/* Access input data */
	if (opts->infile) {
		infd = open(opts->infile, O_RDONLY | O_CLOEXEC);
		if (infd < 0) {
			dolog(KCAPI_LOG_ERR, "Cannot open file %s: %s",
			      opts->infile, strerror(errno));
			return -EIO;
		}
		ret = check_filetype(infd, &insb, opts->infile);
		if (ret)
			goto out;
	} else
		infd = STDIN_FD;

	/* Access output data */
	if (opts->outfile) {
		outfd = open(opts->outfile, O_RDWR | O_CLOEXEC | O_CREAT,
			     S_IRWXU | S_IRWXG | S_IRWXO);
		if (outfd < 0) {
			dolog(KCAPI_LOG_ERR, "Cannot open file %s: %s",
			      opts->outfile, strerror(errno));
			ret = -EIO;
			goto out;
		}

		ret = check_filetype(outfd, &outsb, opts->outfile);
		if (ret)
			goto out;
	} else
		outfd = STDOUT_FD;

	if (infd == STDIN_FD) {
		size_t tmpbuflen;

		while ((tmpbuflen =
		        fread(tmpbuf, sizeof(uint8_t), TMPBUFLEN, stdin))) {

			ret = kcapi_md_update(handle, tmpbuf, tmpbuflen);
			if (ret < 0)
				goto out;
		}
	} else if (insb.st_size) {
		uint8_t *inmem_p;

		inmem = mmap(NULL, (size_t)insb.st_size, PROT_READ, MAP_SHARED,
			     infd, 0);
		if (inmem == MAP_FAILED) {
			dolog(KCAPI_LOG_ERR, "Use of mmap for infd failed");
			ret = -ENOMEM;
			goto out;
		}

		inmem_p = inmem;
		while (insb.st_size) {
			size_t todo = (insb.st_size > INT_MAX) ? INT_MAX :
							(size_t)insb.st_size;
			ret = kcapi_md_update(handle, inmem_p, todo);
			if (ret < 0)
				goto out;
			inmem_p += todo;
			insb.st_size -= (off_t)todo;
		}
	}

	outlen = kcapi_md_digestsize(handle);

	if (opts->hexout)
		outlen *= 2;

	if (outfd == STDOUT_FD) {
		ret = kcapi_md_final(handle, tmpbuf, TMPBUFLEN);
		if (ret < 0)
			goto out;

		if ((uint32_t)ret != kcapi_md_digestsize(handle)) {
			dolog(KCAPI_LOG_ERR,
			      "Unexpected digest output size: %ld (expected %u)\n",
			      ret, kcapi_md_digestsize(handle));
			ret = -EFAULT;
			goto out;
		}

		if (opts->hexout) {
			bin2print(tmpbuf, kcapi_md_digestsize(handle), NULL,
				  stdout, 0);
		} else {
			if (fwrite(tmpbuf, sizeof(char), outlen,
				   stdout) != outlen) {
				dolog(KCAPI_LOG_ERR, "Write failed %d", -errno);
				ret = -errno;
				goto out;
			}
		}

		dolog(KCAPI_LOG_VERBOSE, "Digest of %ld bytes generated\n", ret);
	} else {
		if ((uint64_t)outsb.st_size != outlen) {
			ret = ftruncate(outfd, outlen);
			if (ret)
				goto out;
		}

		outmem = mmap(NULL, outlen, PROT_WRITE, MAP_SHARED, outfd, 0);
		if (outmem == MAP_FAILED) {
			dolog(KCAPI_LOG_ERR, "Use of mmap for outfd failed");
			ret = -ENOMEM;
			goto out;
		}

		if (opts->hexout)
			ret = kcapi_md_final(handle, tmpbuf,
					     kcapi_md_digestsize(handle));
		else
			ret = kcapi_md_final(handle, outmem,
					     kcapi_md_digestsize(handle));
		if (ret < 0)
			goto out;

		if ((uint32_t)ret != kcapi_md_digestsize(handle)) {
			dolog(KCAPI_LOG_ERR,
			      "Unexpected digest output size: %ld (expected %u)\n",
			      ret, kcapi_md_digestsize(handle));
			ret = -EFAULT;
			goto out;
		}

		if (opts->hexout)
			bin2hex(tmpbuf, kcapi_md_digestsize(handle),
				(char *)outmem, outlen, 0);

		dolog(KCAPI_LOG_VERBOSE, "Digest of %ld bytes generated\n", ret);
	}

out:
	if (outmem && outmem != MAP_FAILED)
		munmap(outmem, outlen);

	if (inmem && inmem != MAP_FAILED)
		munmap(inmem, (size_t)insb.st_size);

	if (infd >= 0 && infd != STDIN_FD)
		close(infd);
	if (outfd >= 0 && outfd != STDOUT_FD)
		close(outfd);

	return (ret < 0) ? (int)ret : (int)kcapi_md_digestsize(handle);
}

static int set_key(struct kcapi_handle *handle, struct opt_data *opts)
{
	uint8_t passwdbuf[128] __aligned(KCAPI_APP_ALIGN);
	uint32_t passwdlen = 0;
	uint8_t keybuf[32];
	uint32_t keybuflen = 0;
	int have_key = 0;
	const uint8_t *passwdptr = NULL;
	ssize_t ret;

	/* Only set keys when needed */
	if (!opts->keyed_md)
		return 0;

	/* Get password from command line */
	if (opts->passwd) {
		passwdptr = (uint8_t *)opts->passwd;
		passwdlen = (uint32_t)strlen(opts->passwd);
	}

	/* Get password from password FD */
	if (opts->password_fd != -1) {
		ret = read_complete(opts->password_fd, passwdbuf,
				    sizeof(passwdbuf));
		if (ret < 0)
			goto out;

		passwdbuf[sizeof(passwdbuf) - 1] = '\0';
		passwdptr = passwdbuf;
		passwdlen = (uint32_t)ret;
	}

	if (passwdptr && passwdlen) {
		uint8_t *saltbuf = NULL;
		uint32_t saltbuflen = 0;

		dolog(KCAPI_LOG_DEBUG, "password %s", passwdptr);

		if (!opts->pbkdf_iterations) {
			opts->pbkdf_iterations =
			     kcapi_pbkdf_iteration_count(opts->pbkdf_hash, 0);

			dolog(KCAPI_LOG_WARN, "PBKDF2 iterations used: %u",
			      opts->pbkdf_iterations);
		}

		if (opts->salt) {
			ret = hex2bin_alloc(opts->salt,
					    (uint32_t)strlen(opts->salt),
					    &saltbuf, &saltbuflen);
			if (ret)
				goto out;
		} else {
			struct kcapi_handle *rng;
			uint32_t j = 0;

			ret = kcapi_rng_init(&rng, "stdrng", 0);
			if (ret)
				goto out;
			ret = kcapi_rng_seed(rng, NULL, 0);
			if (ret) {
				kcapi_rng_destroy(rng);
				goto out;
			}

			saltbuflen = 32;
			saltbuf = malloc(saltbuflen);
			if (!saltbuf) {
				ret = -ENOMEM;
				kcapi_rng_destroy(rng);
				goto out;
			}

			while (j < saltbuflen) {
				ret = kcapi_rng_generate(rng, saltbuf,
							 (size_t)saltbuflen);
				if (ret < 0) {
					kcapi_rng_destroy(rng);
					free(saltbuf);
					goto out;
				}
				j += (uint32_t)ret;
			}
			kcapi_rng_destroy(rng);

			dolog_bin(KCAPI_LOG_WARN, saltbuf, saltbuflen,
				  "PBKDF2 salt used");
		}

		/* reading of sizeof(keybuf) implies 256 bit key */
		ret = kcapi_pbkdf(opts->pbkdf_hash, passwdptr, passwdlen,
				  saltbuf, saltbuflen, opts->pbkdf_iterations,
				  keybuf, sizeof(keybuf));
		free(saltbuf);
		if (ret)
			goto out;

		have_key = 1;
		keybuflen = sizeof(keybuf);

		dolog(KCAPI_LOG_VERBOSE,
		      "Data Encryption Key derived from Password using PBKDF2 using %s with %u iterations",
		      opts->pbkdf_hash, opts->pbkdf_iterations);
	}

	/* Get key from key FD */
	if (opts->key_fd != -1) {
		ret = read_complete(opts->key_fd, keybuf, sizeof(keybuf));
		if (ret < 0)
			return (int)ret;

		have_key = 1;
		keybuflen = (uint32_t)ret;
	}

	if (!have_key) {
		dolog(KCAPI_LOG_ERR, "No key found in input data");
		ret = -EINVAL;
		goto out;
	}

	dolog_bin(KCAPI_LOG_DEBUG, keybuf, keybuflen,
		  "keyed message digest key");

	ret = kcapi_md_setkey(handle, keybuf, keybuflen);

out:
	kcapi_memset_secure(passwdbuf, 0, sizeof(passwdbuf));
	kcapi_memset_secure(keybuf, 0, sizeof(keybuf));

	return (int)ret;
}

static void usage(void)
{
	char version[30];
	uint32_t ver = kcapi_version();

	memset(version, 0, sizeof(version));
	kcapi_versionstring(version, sizeof(version));

	fprintf(stderr, "\nKernel Crypto API Message Digest Crypto Helper\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-c --cipher <NAME>\tCipher name to use for crypto operation\n");
	fprintf(stderr, "\t-i --infile <FILE>\tFile with input data\n");
	fprintf(stderr, "\t-o --outfile <FILE>\tFile with output data\n");
	fprintf(stderr, "\t-s --salt <SALT>\tSalt for PBKDF2\n");
	fprintf(stderr, "\t-p --passwd <PWD>\tPassword the session key is derived from using\n");
	fprintf(stderr, "\t\t\t\tPBKDF2\n");
	fprintf(stderr, "\t   --passwdfd <FD>\tPassword file descriptor providing password\n");
	fprintf(stderr, "\t   --pbkdfiter <NUM>\tNumber of PBKDF2 iterations\n");
	fprintf(stderr, "\t   --pbkdfmac <MAC>\tMac for PBKDF2 (default: hmac(sha256))\n");
	fprintf(stderr, "\t   --keyfd <FD>\t\tKey file descriptor providing password\n");
	fprintf(stderr, "\t   --hex\t\tDigest is returned in hexadecimal notation\n");
	fprintf(stderr, "\t-h --help\t\tThis help information\n");
	fprintf(stderr, "\t   --version\t\tPrint version\n");
	fprintf(stderr, "\t-v --verbose\t\tVerbose logging, multiple options increase\n");
	fprintf(stderr, "\t\t\t\tverbosity\n");
	fprintf(stderr, "\t-q --quiet\t\tNo informational output - quiet operation\n");
	fprintf(stderr, "\nData provided at stdin is hashed\n");
	fprintf(stderr, "Data output at stdout\n");

	exit(1);
}

static void parse_opts(int argc, char *argv[], struct opt_data *opts)
{
	int c = 0;
	char version[30];
	unsigned long val = 0;
	uint32_t verbosity = KCAPI_LOG_WARN;

	memset(opts, 0, sizeof(*opts));
	opts->password_fd = -1;
	opts->key_fd = -1;

	while (1) {
		int opt_index = 0;
		static struct option options[] = {
			{"cipher",	required_argument,	0, 'c'},
			{"infile",	required_argument,	0, 'i'},
			{"outfile",	required_argument,	0, 'o'},
			{"salt",	required_argument,	0, 's'},
			{"passwd",	required_argument,	0, 'p'},
			{"passwdfd",	required_argument,	0, 0},
			{"pbkdfiter",	required_argument,	0, 0},
			{"pbkdfmac",	required_argument,	0, 0},
			{"keyfd",	required_argument,	0, 0},
			{"hex",		no_argument,		0, 0},

			{"verbose",	no_argument,		0, 'v'},
			{"quiet",	no_argument,		0, 'q'},
			{"help",	no_argument,		0, 'h'},
			{"version",	no_argument,		0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "c:i:o:s:p:vqh",
				options, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				opts->ciphername = optarg;
				break;
			case 1:
				opts->infile = optarg;
				break;
			case 2:
				opts->outfile = optarg;
				break;
			case 3:
				opts->salt = optarg;
				break;
			case 4:
				opts->passwd = optarg;
				break;
			case 5:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->password_fd = (int)val;
				break;
			case 6:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "PBKDF2 iteration value too big");
					usage();
				}
				opts->pbkdf_iterations = (uint32_t)val;
				break;
			case 7:
				opts->pbkdf_hash = optarg;
				break;
			case 8:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->key_fd = (int)val;
				break;
			case 9:
				opts->hexout = true;
				break;

			case 10:
				verbosity++;
				break;
			case 11:
				verbosity = KCAPI_LOG_NONE;
				break;
			case 12:
				usage();
				break;
			case 13:
				memset(version, 0, sizeof(version));
				kcapi_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				exit(0);
				break;
			default:
				usage();
			}
			break;

		case 'c':
			opts->ciphername = optarg;
			break;
		case 'i':
			opts->infile = optarg;
			break;
		case 'o':
			opts->outfile = optarg;
			break;
		case 's':
			opts->salt = optarg;
			break;
		case 'p':
			opts->passwd = optarg;
			break;


		case 'v':
			verbosity++;
			break;
		case 'q':
			verbosity = KCAPI_LOG_NONE;
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
		}
	}

	set_verbosity("kcapi-dgst", verbosity);

	if (!opts->ciphername) {
		dolog(KCAPI_LOG_ERR, "Provide cipher name");
		usage();
	}

	if (opts->passwd || opts->password_fd != -1 || opts->key_fd != -1)
		opts->keyed_md = true;

	if (opts->passwd)
		dolog(KCAPI_LOG_WARN,
		      "Password on command line is visible in process listing and /proc! Use --passwd_fd command line option!");

	if (!opts->pbkdf_hash)
		opts->pbkdf_hash = "hmac(sha256)";
	dolog(KCAPI_LOG_DEBUG, "Using PBKDF2 mac of %s", opts->pbkdf_hash);
}

int main(int argc, char *argv[])
{
	struct kcapi_handle *handle = NULL;
	struct opt_data opts;
	int ret;

	parse_opts(argc, argv, &opts);

	ret = kcapi_md_init(&handle, opts.ciphername, 0);
	if (ret)
		return ret;

	ret = set_key(handle, &opts);
	if (ret)
		goto out;

	ret = cipher_op(handle, &opts);

	if (ret > 0) {
		dolog(KCAPI_LOG_VERBOSE, "%d bytes of %smessage digest created",
		      ret, opts.keyed_md ? "keyed " : "");
		ret = 0;
	} else {
		dolog(KCAPI_LOG_ERR,
		      "message digest creation failed with error %d",
		      ret);
	}

out:
	kcapi_md_destroy(handle);

	return ret;
}
