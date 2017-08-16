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

#define MAX_ALG_PAGES 16

struct opt_data {
	const char *infile;
	const char *outfile;
	const char *ciphername;
	const char *iv;
	const char *aad;
	uint32_t aadlen;
	const char *tag;
	uint32_t taglen;
	const char *passwd;
	const char *salt;
	pid_t password_fd;
	pid_t key_fd;
	uint32_t pbkdf_iterations;
	uint32_t decrypt;
	uint32_t nounpad;
	const char *pbkdf_hash;
	int (*func_init)(struct kcapi_handle **handle, const char *ciphername,
			 uint32_t flags);
	void (*func_destroy)(struct kcapi_handle *handle);
	int (*func_setkey)(struct kcapi_handle *handle,
			   const uint8_t *key, uint32_t keylen);
	int32_t (*func_stream_init_enc)(struct kcapi_handle *handle,
					const uint8_t *iv,
					struct iovec *iov, uint32_t iovlen);
	int32_t (*func_stream_init_dec)(struct kcapi_handle *handle,
					const uint8_t *iv,
					struct iovec *iov, uint32_t iovlen);
	int32_t (*func_stream_update)(struct kcapi_handle *handle,
				      struct iovec *iov, uint32_t iovlen);
	int32_t (*func_stream_op)(struct kcapi_handle *handle,
				  struct iovec *iov, uint32_t iovlen);
	uint32_t (*func_blocksize)(struct kcapi_handle *handle);
};

static int check_filetype(int fd, struct stat *sb, const char *filename)
{
	fstat(fd, sb);

	/* Do not return an error in case we cannot validate the data. */
	if ((sb->st_mode & S_IFMT) != S_IFREG &&
	    (sb->st_mode & S_IFMT) != S_IFLNK) {
		dolog(KCAPI_LOG_ERR,
		      "%s is no regular file or symlink", filename);
		return -EINVAL;
	}

	return 0;
}

static int return_data(struct kcapi_handle *handle, struct opt_data *opts,
		       int outfd, uint32_t outsize, uint32_t offset,
		       uint32_t unpad)
{
	uint8_t tmpbuf[TMPBUFLEN];
	uint8_t *outmem = NULL;
	struct iovec outiov;
	int ret = 0;
	int generated_bytes = 0;

	if (outfd == STDOUT_FD) {
		while (outsize > 0) {
			uint32_t len = outsize < TMPBUFLEN ?
					outsize : TMPBUFLEN;
			uint8_t *tmpbufptr = tmpbuf;

			outiov.iov_base = tmpbuf;
			outiov.iov_len = len;
			ret = opts->func_stream_op(handle, &outiov, 1);
			if (ret < 0)
				goto out;
			generated_bytes += ret;

			if ((len = fwrite(tmpbufptr, sizeof(char), len,
					  stdout)) != 0) {
				outsize -= len;
				tmpbufptr += len;
			} else {
				dolog(KCAPI_LOG_ERR, "Write failed %d", -errno);
				ret = -errno;
				goto out;
			}
		}

		dolog(KCAPI_LOG_VERBOSE, "Removal of padding disabled");
	} else {
		uint8_t *off_ptr;
		uint32_t off_outsize = outsize + offset;

		outmem = mmap(NULL, off_outsize, PROT_WRITE, MAP_SHARED,
			      outfd, 0);
		if (outmem == MAP_FAILED) {
			dolog(KCAPI_LOG_ERR, "Use of mmap for outfd failed");
			ret = -ENOMEM;
			goto out;
		}
		off_ptr = outmem + offset;
		outiov.iov_base = off_ptr;
		outiov.iov_len = outsize;

		ret = opts->func_stream_op(handle, &outiov, 1);
		if (ret < 0)
			goto out;
		generated_bytes += ret;

		/* Padding is only removed for decryption */
		if (!opts->decrypt)
			goto out;

		/* undo padding */
		if (unpad && !opts->nounpad) {
			uint8_t padbyte;

			padbyte = *(off_ptr + generated_bytes - 1);

			if ((uint32_t)padbyte < opts->func_blocksize(handle)) {
				uint32_t i;
				uint32_t padded = 1;

				for (i = generated_bytes - 2;
				     i >= generated_bytes - (uint32_t)padbyte;
				     i--) {
					if (*(off_ptr + i) != padbyte) {
						padded = 0;
						break;
					}
				}

				if (padded) {
					dolog(KCAPI_LOG_DEBUG, "Unpad %d bytes",
					      (uint32_t)padbyte);

					ret = ftruncate(outfd,
							off_outsize -
							 (uint32_t)padbyte);
					if (ret)
						goto out;

					generated_bytes -= (uint32_t)padbyte;
				}
			}
		} else
			dolog(KCAPI_LOG_VERBOSE, "Removal of padding disabled");
	}

out:
	if (outmem && outmem != MAP_FAILED)
		munmap(outmem, outsize);
	return (ret < 0) ? ret : generated_bytes;
}

static uint32_t outbufsize(struct kcapi_handle *handle, struct opt_data *opts,
			   uint32_t datalen)
{
	uint32_t outsize;

	if (opts->aad) {
		if (opts->decrypt)
			outsize = kcapi_aead_outbuflen_dec(handle, datalen,
							   opts->aadlen,
							   opts->taglen);
		else
			outsize = kcapi_aead_outbuflen_enc(handle, datalen,
							   opts->aadlen,
							   opts->taglen);
	} else {
		outsize = ((datalen + opts->func_blocksize(handle) - 1) /
			   opts->func_blocksize(handle)) *
			   opts->func_blocksize(handle);
	}

	dolog(KCAPI_LOG_DEBUG, "Data size expected to be generated: %u",
	      outsize);

	return outsize;
}

static int add_padding(struct kcapi_handle *handle, struct opt_data *opts,
		       uint8_t *padbuf, uint32_t outsize, uint32_t currblock)
{
	uint32_t padsize = 0;

	if (opts->aad)
		return 0;

	if (opts->decrypt)
		return 0;

	if (outsize > currblock) {
		struct iovec iniov;
		int ret = 0;

		padsize = outsize - currblock;
		memset(padbuf, (uint8_t)padsize, padsize);

		/*
		 * WARNING: we cannot use a local buffer here, because when
		 * splicing the data, the data is first accessed from user space
		 * upon recvmsg. Thus, the buffer with the pad data must be
		 * alive until the recvmsg is invoked.
		 */
		iniov.iov_base = padbuf;
		iniov.iov_len = padsize;
		ret = opts->func_stream_update(handle, &iniov, 1);
		if (ret < 0)
			return ret;

		dolog_bin(KCAPI_LOG_DEBUG, iniov.iov_base, iniov.iov_len,
			  "Padding contents");
		dolog(KCAPI_LOG_VERBOSE, "Padding of %u bytes applied",
		      iniov.iov_len);
	}

	return padsize;
}

static int cipher_op(struct kcapi_handle *handle, struct opt_data *opts)
{
	int infd = -1, outfd = -1;
	int ret = 0;
	int generated_bytes = 0;
	struct stat insb, outsb;
	uint8_t *inmem = NULL;
	uint32_t outsize = 0;
	struct iovec iniov;
	uint8_t *ivbuf = NULL;
	uint32_t ivbuflen = 0;
	char tmpbuf[TMPBUFLEN];

	uint8_t *aadbuf = NULL;
	uint8_t *tagbuf = NULL;
	uint8_t padbuf[32];

	/*
	 * To avoid spurious padding, the buffer must be multiples of the
	 * block size.
	 */
	BUILD_BUG_ON(TMPBUFLEN % 32);

	if (opts->iv) {
		ret = hex2bin_alloc(opts->iv, strlen(opts->iv),
					&ivbuf, &ivbuflen);
		if (ret)
			goto out;
	}

	/* AEAD specific code */
	if (opts->aad) {
		uint8_t *newiv = NULL;
		uint32_t newivlen;

		ret = hex2bin_alloc(opts->aad, strlen(opts->aad),
				    &aadbuf, &opts->aadlen);
		if (ret)
			return ret;

		kcapi_aead_setassoclen(handle, opts->aadlen);

		if (opts->tag) {
			ret = hex2bin_alloc(opts->tag, strlen(opts->tag),
					&tagbuf, &opts->taglen);
			if (ret)
				goto out;
		}

		if (opts->taglen) {
			ret = kcapi_aead_settaglen(handle, opts->taglen);
			if (ret)
				goto out;
		}


		/* generate the right IV */
		if (ivbuf && ivbuflen) {
			ret = kcapi_pad_iv(handle, ivbuf, ivbuflen,
					   &newiv, &newivlen);
			if (ret)
				goto out;

			free(ivbuf);
			ivbuf = newiv;
			ivbuflen = newivlen;
		}
	}

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

	if (opts->decrypt)
		ret = opts->func_stream_init_dec(handle, ivbuf, NULL, 0);
	else
		ret = opts->func_stream_init_enc(handle, ivbuf, NULL, 0);
	if (ret)
		goto out;

	if (aadbuf) {
		iniov.iov_base = aadbuf;
		iniov.iov_len = opts->aadlen;

		ret = opts->func_stream_update(handle, &iniov, 1);
		if (ret < 0)
			goto out;
	}

	if (infd == STDIN_FD) {
		iniov.iov_base = tmpbuf;
		while ((iniov.iov_len =
		        fread(tmpbuf, sizeof(uint8_t), TMPBUFLEN, stdin))) {

			ret = opts->func_stream_update(handle, &iniov, 1);
			if (ret < 0)
				goto out;

			/* WARNING: with AEAD, only one loop is possible */
			if (tagbuf) {
				iniov.iov_base = tagbuf;
				iniov.iov_len = opts->taglen;

				ret = opts->func_stream_update(handle, &iniov,
							       1);
				if (ret < 0)
					goto out;
			}

			outsize = outbufsize(handle, opts, iniov.iov_len);

			if (outfd != STDOUT_FD) {
				ret = ftruncate(outfd,
						generated_bytes + outsize);
				if (ret)
					goto out;
			}

			/* padding */
			ret = add_padding(handle, opts, padbuf,
					  outsize, iniov.iov_len);
			if (ret)
				goto out;

			ret = return_data(handle, opts, outfd, outsize,
					  generated_bytes, 0);
			if (ret < 0)
				goto out;
			generated_bytes += ret;
		}
	} else {
		uint32_t maxdata = sysconf(_SC_PAGESIZE) * MAX_ALG_PAGES;
		uint32_t sent_data = 0;

		inmem = mmap(NULL, insb.st_size, PROT_READ, MAP_SHARED,
			     infd, 0);
		if (inmem == MAP_FAILED) {
			dolog(KCAPI_LOG_ERR, "Use of mmap for infd failed");
			ret = -ENOMEM;
			goto out;
		}

		if (outfd != STDOUT_FD) {
			uint8_t padbyte;

			outsize = outbufsize(handle, opts, insb.st_size);
			ret = ftruncate(outfd, outsize);
			if (ret)
				goto out;

			padbyte = *(inmem + insb.st_size - 1);

			if ((uint32_t)padbyte < opts->func_blocksize(handle)) {
				uint32_t i;
				uint32_t padded = 1;

				for (i = insb.st_size - 2;
				     i >=  insb.st_size - (uint32_t)padbyte;
				     i--) {
					if (*(inmem + i) != padbyte) {
						padded = 0;
						break;
					}
				}

				if (padded &&
				    (insb.st_size == (i + (uint32_t)padbyte))) {
					dolog(KCAPI_LOG_WARN,
					      "Input file's trailing bytes will be treated as padding during decryption unless you turn off padding handling with --nounpad\n");
				}
			}


		}

		while (sent_data < insb.st_size) {
			uint32_t avail = insb.st_size - sent_data;
			uint32_t todo = avail > maxdata ? maxdata : avail;

			iniov.iov_base = inmem + sent_data;
			iniov.iov_len = todo;
			ret = opts->func_stream_update(handle, &iniov, 1);
			if (ret < 0)
				goto out;

			/* WARNING: with AEAD, only one loop is possible */
			if (tagbuf) {
				iniov.iov_base = tagbuf;
				iniov.iov_len = opts->taglen;

				ret = opts->func_stream_update(handle, &iniov,
								1);
				if (ret < 0)
					goto out;
			}

			outsize = outbufsize(handle, opts, iniov.iov_len);

			/* padding */
			ret = add_padding(handle, opts, padbuf,
					  outsize, iniov.iov_len);
			if (ret < 0)
				goto out;

			ret = return_data(handle, opts, outfd, outsize,
					  generated_bytes, 1);
			if (ret < 0)
				goto out;

			generated_bytes += ret;
			sent_data += todo;
		}
	}

out:
	if (inmem && inmem != MAP_FAILED)
		munmap(inmem, insb.st_size);

	if (ivbuf)
		free(ivbuf);
	if (tagbuf)
		free(tagbuf);
	if (aadbuf)
		free(aadbuf);

	if (infd >= 0 && infd != STDIN_FD)
		close(infd);
	if (outfd >= 0 && outfd != STDOUT_FD)
		close(outfd);

	return (ret < 0) ? ret : generated_bytes;
}

static int read_complete(int fd, uint8_t *buf, uint32_t buflen)
{
	ssize_t ret;
	int rc = 0;

	if (buflen > INT_MAX)
		return -EINVAL;

	do {
		ret = read(fd, buf, buflen);
		if (0 < ret) {
			buflen -= ret;
			buf += ret;
		}
		rc += ret;
		if (ret)
			break;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > 0);

	return rc;
}

static int set_key(struct kcapi_handle *handle, struct opt_data *opts)
{
	uint8_t passwdbuf[128];
	uint32_t passwdlen = 0;
	uint8_t keybuf[32];
	uint32_t keybuflen = 0;
	int have_key = 0;
	const uint8_t *passwdptr = NULL;
	int ret;

	/* Get password from command line */
	if (opts->passwd) {
		passwdptr = (uint8_t *)opts->passwd;
		passwdlen = strlen(opts->passwd);
	}

	/* Get password from password FD */
	if (opts->password_fd != -1) {
		ret = read_complete(opts->password_fd, passwdbuf,
				    sizeof(passwdbuf));
		if (ret < 0)
			goto out;

		passwdbuf[sizeof(passwdbuf) - 1] = '\0';
		passwdptr = passwdbuf;
		passwdlen = ret;
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
			ret = hex2bin_alloc(opts->salt, strlen(opts->salt),
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
							 saltbuflen);
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
				  saltbuf, saltbuflen, opts->pbkdf_iterations, keybuf, sizeof(keybuf));
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
			return ret;

		have_key = 1;
		keybuflen = ret;
	}

	if (!have_key) {
		dolog(KCAPI_LOG_ERR, "No key found in input data");
		ret = -EINVAL;
		goto out;
	}

	dolog_bin(KCAPI_LOG_DEBUG, keybuf, keybuflen, "data-encryption-key");

	ret = opts->func_setkey(handle, keybuf, keybuflen);

out:
	kcapi_memset_secure(passwdbuf, 0, sizeof(passwdbuf));
	kcapi_memset_secure(keybuf, 0, sizeof(keybuf));

	return ret;
}

static void usage(void)
{
	char version[30];
	uint32_t ver = kcapi_version();

	memset(version, 0, sizeof(version));
	kcapi_versionstring(version, sizeof(version));

	fprintf(stderr, "\nKernel Crypto API Symmetric Crypto Helper\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-c --cipher <NAME>\tCipher name to use for crypto operation\n");
	fprintf(stderr, "\t-e --encrypt\t\tEncryption operation (default)\n");
	fprintf(stderr, "\t-d --decrypt\t\tDecryption operation\n");
	fprintf(stderr, "\t-i --infile <FILE>\tFile with input data\n");
	fprintf(stderr, "\t-o --outfile <FILE>\tFile with output data\n");
	fprintf(stderr, "\t--iv <IV>\t\tIV for cipher operation\n");
	fprintf(stderr, "\t--aad <AAD>\t\tAAD for AEAD cipher operation\n");
	fprintf(stderr, "\t--tag <TAG>\t\tTag for AEAD decryption operation\n");
	fprintf(stderr, "\t--taglen <BYTES>\tTag length to be generated AEAD encryption\n");
	fprintf(stderr, "\t\t\t\toperation\n");
	fprintf(stderr, "\t-s --salt <SALT>\tSalt for PBKDF2\n");
	fprintf(stderr, "\t-p --passwd <PWD>\tPassword the session key is derived from using\n");
	fprintf(stderr, "\t\t\t\tPBKDF2\n");
	fprintf(stderr, "\t --passwdfd <FD>\tPassword file descriptor providing password\n");
	fprintf(stderr, "\t --pbkdfiter <NUM>\tNumber of PBKDF2 iterations\n");
	fprintf(stderr, "\t --keyfd <FD>\t\tKey file descriptor providing password\n");
	fprintf(stderr, "\t --nounpad\t\tDo not unpad output file\n");
	fprintf(stderr, "\t-h --help\t\tThis help information\n");
	fprintf(stderr, "\t   --version\t\tPrint version\n");
	fprintf(stderr, "\t-v --verbose\t\tVerbose logging, multiple options increase\n");
	fprintf(stderr, "\t\t\t\tverbosity\n");
	fprintf(stderr, "\t-q --quiet\t\tNo informational output - quiet operation\n");
	fprintf(stderr, "\nData provided at stdin is encrypted or decrypted\n");
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
			{"encrypt",	no_argument,		0, 'e'},
			{"decrypt",	no_argument,		0, 'd'},
			{"infile",	required_argument,	0, 'i'},
			{"outfile",	required_argument,	0, 'o'},
			{"iv",		required_argument,	0, 0},
			{"aad",		required_argument,	0, 0},
			{"tag",		required_argument,	0, 0},
			{"taglen",	required_argument,	0, 0},
			{"salt",	required_argument,	0, 's'},
			{"passwd",	required_argument,	0, 'p'},
			{"passwdfd",	required_argument,	0, 0},
			{"pbkdfiter",	required_argument,	0, 0},
			{"keyfd",	required_argument,	0, 0},
			{"nounpad",	no_argument,		0, 0},

			{"verbose",	no_argument,		0, 'v'},
			{"quiet",	no_argument,		0, 'q'},
			{"help",	no_argument,		0, 'h'},
			{"version",	no_argument,		0, 0},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "c:edi:o:s:p:vqh",
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
				opts->decrypt = 0;
				break;
			case 2:
				opts->decrypt = 1;
				break;
			case 3:
				opts->infile = optarg;
				break;
			case 4:
				opts->outfile = optarg;
				break;
			case 5:
				opts->iv = optarg;
				break;
			case 6:
				opts->aad = optarg;
				break;
			case 7:
				opts->tag = optarg;
				break;
			case 8:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Tag length value too big");
					usage();
				}
				opts->taglen = val;
				break;
			case 9:
				opts->salt = optarg;
				break;
			case 10:
				opts->passwd = optarg;
				break;
			case 11:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->password_fd = (pid_t)val;
				break;
			case 12:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "PBKDF2 iteration value too big");
					usage();
				}
				opts->pbkdf_iterations = val;
				break;
			case 13:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->key_fd = (pid_t)val;
				break;
			case 14:
				opts->nounpad = 1;
				break;

			case 15:
				verbosity++;
				break;
			case 16:
				verbosity = KCAPI_LOG_NONE;
				break;
			case 17:
				usage();
				break;
			case 18:
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
		case 'e':
			opts->decrypt = 0;
			break;
		case 'd':
			opts->decrypt = 1;
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

	set_verbosity(verbosity);

	if (!opts->ciphername) {
		dolog(KCAPI_LOG_ERR, "Provide cipher name");
		usage();
	}

	if (!opts->passwd && opts->password_fd == -1 &&
	    opts->key_fd == -1) {
		dolog(KCAPI_LOG_ERR, "Provide at least a password, a password FD or key FD");
		usage();
	}

	if (opts->aad) {
		if (opts->decrypt && !opts->tag) {
			dolog(KCAPI_LOG_ERR, "No tag provided for AEAD decryption operation");
			usage();
		}
		if (!opts->decrypt && !opts->taglen) {
			dolog(KCAPI_LOG_ERR, "No tag length provided for AEAD encryption operation");
			usage();
		}
	}

	if (opts->passwd)
		dolog(KCAPI_LOG_WARN, "Password on command line is visible in process listing and /proc! Use --passwd_fd command line option!");
}

int main(int argc, char *argv[])
{
	struct kcapi_handle *handle = NULL;
	struct opt_data opts;
	int ret;

	parse_opts(argc, argv, &opts);
	opts.pbkdf_hash = "hmac(sha256)";

	if (opts.aad) {
		opts.func_init = kcapi_aead_init;
		opts.func_destroy = kcapi_aead_destroy;
		opts.func_setkey = kcapi_aead_setkey;
		opts.func_stream_init_enc = kcapi_aead_stream_init_enc;
		opts.func_stream_init_dec = kcapi_aead_stream_init_dec;
		opts.func_stream_update = kcapi_aead_stream_update;
		opts.func_stream_op = kcapi_aead_stream_op;
		opts.func_blocksize = kcapi_aead_blocksize;
	} else {
		opts.func_init = kcapi_cipher_init;
		opts.func_destroy = kcapi_cipher_destroy;
		opts.func_setkey = kcapi_cipher_setkey;
		opts.func_stream_init_enc = kcapi_cipher_stream_init_enc;
		opts.func_stream_init_dec = kcapi_cipher_stream_init_dec;
		opts.func_stream_update = kcapi_cipher_stream_update;
		opts.func_stream_op = kcapi_cipher_stream_op;
		opts.func_blocksize = kcapi_cipher_blocksize;
	}

	ret = opts.func_init(&handle, opts.ciphername, 0);
	if (ret)
		return ret;

	ret = set_key(handle, &opts);
	if (ret)
		goto out;

	ret = cipher_op(handle, &opts);

	if (ret > 0) {
		dolog(KCAPI_LOG_VERBOSE, "%d bytes of %stext created",
		      ret, opts.decrypt ? "plain" : "cipher");
		ret = 0;
	} else {
		dolog(KCAPI_LOG_ERR, "encryption failed with error %d", ret);
	}

out:
	opts.func_destroy(handle);

	return ret;
}
