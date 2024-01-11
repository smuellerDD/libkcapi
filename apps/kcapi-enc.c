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

#define TAGBUFLEN 16

struct opt_data {
	const char *infile;
	const char *outfile;
	const char *ciphername;
	const char *iv;
	const char *ccmnonce;
	const char *aad;
	const char *tag;
	const char *passwd;
	const char *salt;
	const char *pbkdf_hash;
	int password_fd;
	int key_fd;
	uint32_t key_len;
	uint32_t pbkdf_iterations;
	uint32_t taglen;
	uint32_t aadlen;
	bool decrypt;
	bool nounpad;
	bool removetag;
	int (*func_init)(struct kcapi_handle **handle, const char *ciphername,
			 uint32_t flags);
	void (*func_destroy)(struct kcapi_handle *handle);
	int (*func_setkey)(struct kcapi_handle *handle,
			   const uint8_t *key, uint32_t keylen);
	ssize_t (*func_stream_init_enc)(struct kcapi_handle *handle,
					const uint8_t *iv,
					struct iovec *iov, size_t iovlen);
	ssize_t (*func_stream_init_dec)(struct kcapi_handle *handle,
					const uint8_t *iv,
					struct iovec *iov, size_t iovlen);
	ssize_t (*func_stream_update)(struct kcapi_handle *handle,
				      struct iovec *iov, size_t iovlen);
	ssize_t (*func_stream_update_last)(struct kcapi_handle *handle,
					   struct iovec *iov, size_t iovlen);
	ssize_t (*func_stream_op)(struct kcapi_handle *handle,
				  struct iovec *iov, size_t iovlen);
	uint32_t (*func_blocksize)(struct kcapi_handle *handle);
};

static ssize_t return_data_stdout(struct kcapi_handle *handle,
				  struct opt_data *opts, size_t outsize)
{
	struct iovec outiov;
	uint8_t tmpbuf[TMPBUFLEN] __aligned(KCAPI_APP_ALIGN);
	ssize_t ret = 0;
	ssize_t generated_bytes = 0;

	/*
	 * Generate output data in a tmp buffer and then dump it.
	 */
	while (outsize > 0) {
		/* length of the input data */
		size_t inlen = outsize < TMPBUFLEN ? outsize : TMPBUFLEN;
		/* length of the output data */
		size_t outlen = inlen;
		uint8_t *tmpbufptr = tmpbuf;

		outiov.iov_base = tmpbuf;
		outiov.iov_len = inlen;
		ret = opts->func_stream_op(handle, &outiov, 1);
		if (ret < 0)
			goto out;
		generated_bytes += ret;

		/*
			* If we have to remove the tag, simply reduce
			* number of bytes to be written to stdout as the tag
			* is the trailing part of the memory.
			*/
		if (opts->removetag) {
			outlen -= opts->taglen;
			generated_bytes -= (ssize_t)opts->taglen;

			dolog(KCAPI_LOG_DEBUG,
				"remove %u bytes of unused but generated tag",
				opts->taglen);
		}

		/* write the data */
		if (fwrite(tmpbufptr, sizeof(char), outlen, stdout) != outlen) {
			dolog(KCAPI_LOG_ERR, "Write failed %d", -errno);
			ret = -errno;
			goto out;
		}
		outsize -= inlen;
	}

	/*
	 * We cannot remove padding as we do not know when the last
	 * block is processed.
	 */
	dolog(KCAPI_LOG_VERBOSE, "Removal of padding disabled");

out:
	return (ret < 0) ? ret : generated_bytes;
}

static ssize_t return_data_fd(struct kcapi_handle *handle,
			      struct opt_data *opts,
			      int outfd, size_t outsize, size_t offset,
			      uint32_t unpad)
{
	struct iovec outiov;
	size_t off_outsize = outsize + offset;
	uint8_t *outmem;
	ssize_t ret = 0;
	ssize_t generated_bytes = 0;
	uint8_t *off_ptr;

	/* Map the file into memory. */
	outmem = mmap(NULL, off_outsize, PROT_WRITE, MAP_SHARED,
			outfd, 0);
	if (outmem == MAP_FAILED) {
		dolog(KCAPI_LOG_ERR, "Use of mmap for outfd failed");
		return -ENOMEM;
	}

	off_ptr = outmem + offset;
	outiov.iov_base = off_ptr;
	outiov.iov_len = outsize;

	/* Write the data. */
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
			ssize_t i;
			uint32_t padded = 1;

			for (i = generated_bytes - 2;
			     i >= generated_bytes - (ssize_t)padbyte; i--) {
				if (*(off_ptr + i) != padbyte) {
					padded = 0;
					break;
				}
			}

			if (padded) {
				dolog(KCAPI_LOG_DEBUG, "Unpad %d bytes",
					(uint32_t)padbyte);

				off_outsize -= (uint32_t)padbyte;

				ret = ftruncate(outfd, (off_t)off_outsize);
				if (ret)
					goto out;

				generated_bytes -= (ssize_t)padbyte;
			}
		}
	} else
		dolog(KCAPI_LOG_VERBOSE, "Removal of padding disabled");

	/*
	 * Remove the trailing tag for older kernels by simply
	 * truncating the output file to the generated data size minus
	 * the tag value. As the tag is the trailing part of the data,
	 * it will be cleared.
	 */
	if (opts->removetag) {
		ret = ftruncate(outfd, (off_t)(off_outsize - opts->taglen));
		if (ret)
			goto out;
		generated_bytes -= (ssize_t)opts->taglen;
		dolog(KCAPI_LOG_DEBUG,
			"remove %u bytes of unused but generated tag",
			opts->taglen);
	}

out:
	munmap(outmem, outsize);
	return (ret < 0) ? ret : generated_bytes;
}

static ssize_t return_data(struct kcapi_handle *handle, struct opt_data *opts,
			   int outfd, size_t outsize, size_t offset,
			   uint32_t unpad)
{
	/* Tell kernel that we have sent all data */
	ssize_t ret = opts->func_stream_update_last(handle, NULL, 0);
	if (ret < 0)
		return (int)ret;

	/* send generated data to stdout */
	if (outfd == STDOUT_FD)
		return return_data_stdout(handle, opts, outsize);
	/* Write to a file. */
	else
		return return_data_fd(handle, opts, outfd, outsize, offset,
				      unpad);
}

/**
 * Get the output data size to be expected for the cipher operation given
 * the input data size.
 */
static size_t outbufsize(struct kcapi_handle *handle, struct opt_data *opts,
			 size_t datalen)
{
	size_t outsize;

	if (opts->aad) {
		if (opts->decrypt) {
			outsize = kcapi_aead_outbuflen_dec(handle, datalen,
							   opts->aadlen,
							   opts->taglen);

			/*
			 * This is needed for kernels < 4.9: see the libkcapi
			 * documentation where the tag value is generated
			 * during decryption. As we do not want a zero tag,
			 * simply discard the tag during print out.
			 */
			if (outsize == (datalen + opts->aadlen + opts->taglen))
				opts->removetag = true;
		} else
			outsize = kcapi_aead_outbuflen_enc(handle, datalen,
							   opts->aadlen,
							   opts->taglen);
	} else {
		outsize = ((datalen + opts->func_blocksize(handle) - 1) /
			   opts->func_blocksize(handle)) *
			   opts->func_blocksize(handle);
	}

	dolog(KCAPI_LOG_DEBUG, "Data size expected to be generated: %lu",
	      outsize);

	return outsize;
}

/*
 * Send the tag value to the kernel for AEAD operations.
 * This function also handles the interface change between kernels 4.8 and 4.9.
 */
static int sendtag(struct kcapi_handle *handle, struct opt_data *opts,
		   uint8_t *tagbuf, uint8_t *tmptagbuf)
{
	size_t outsize;
	struct iovec iniov;
	ssize_t ret;

	/* If no AEAD operation, return immediately. */
	if (!opts->aad)
		return 0;

	/* If we have a tag value, simply send it. */
	if (tagbuf) {
		iniov.iov_base = tagbuf;
		iniov.iov_len = opts->taglen;

		ret = opts->func_stream_update(handle, &iniov,
						1);
		if (ret < 0)
			return (int)ret;

		dolog(KCAPI_LOG_DEBUG, "Sent %u bytes of tag", opts->taglen);

		return 0;
	}

	/*
	 * On kernels < 4.9, the outsize is always aadlen + data + taglen.
	 *
	 * For newer kernels, the outsize is aadlen + data + tag (encryption) or
	 * aadlen + data (decryption).
	 */
	if (opts->decrypt)
		outsize = kcapi_aead_inbuflen_dec(handle, 0, opts->aadlen,
						  opts->taglen);
	else
		outsize = kcapi_aead_inbuflen_enc(handle, 0, opts->aadlen,
						  opts->taglen);

	if (outsize != (opts->aadlen + opts->taglen)) {
		/* We have a newer kernel, do not do anything. */
		return 0;
	}

	/*
	 * Send an empty buffer for a tag as required on kernels < 4.9 as
	 * documented for libkcapi.
	 */
	if (TAGBUFLEN < opts->taglen) {
		dolog(KCAPI_LOG_ERR, "Tag size %u too large\n", opts->taglen);
		return -EINVAL;
	}

	memset(tmptagbuf, 0, opts->taglen);

	iniov.iov_base = tmptagbuf;
	iniov.iov_len = opts->taglen;
	ret = opts->func_stream_update(handle, &iniov, 1);
	if (ret < 0)
		return (int)ret;

	dolog(KCAPI_LOG_DEBUG, "Sent %u bytes of null tag", opts->taglen);

	return 0;
}

/**
 * Add the padding data to ensure that for a cipher operation, the input
 * data is multiples of the cipher's block size.
 */
static int add_padding(struct kcapi_handle *handle, struct opt_data *opts,
		       uint8_t *padbuf, size_t outsize, size_t currblock)
{
	size_t padsize = 0;

	if (opts->aad)
		return 0;

	if (opts->decrypt)
		return 0;

	if (outsize > currblock) {
		struct iovec iniov;
		ssize_t ret = 0;

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
			return (int)ret;

		dolog_bin(KCAPI_LOG_DEBUG, iniov.iov_base,
			  (uint32_t)iniov.iov_len, "Padding contents");
		dolog(KCAPI_LOG_VERBOSE, "Padding of %u bytes applied",
		      iniov.iov_len);
	}

	return (int)padsize;
}

/**
 * Perform the requested cipher operation.
 *
 * The cipher handle must already have the key set.
 */
static int cipher_op(struct kcapi_handle *handle, struct opt_data *opts)
{
	int infd = -1, outfd = -1;
	ssize_t ret = 0;
	unsigned int generated_bytes = 0;
	struct stat insb, outsb;
	uint8_t *inmem = NULL;
	size_t outsize = 0;
	struct iovec iniov;
	uint8_t *ivbuf = NULL;
	uint32_t ivbuflen = 0;
	char tmpbuf[TMPBUFLEN] __aligned(KCAPI_APP_ALIGN);

	uint8_t *aadbuf = NULL;
	uint8_t *tagbuf = NULL;
	uint8_t padbuf[32] __aligned(KCAPI_APP_ALIGN);
	uint8_t tagtmpbuf[TAGBUFLEN] __aligned(KCAPI_APP_ALIGN);

	unsigned int maxdata;

	/*
	 * To avoid spurious padding, the buffer must be multiples of the
	 * block size.
	 */
	BUILD_BUG_ON(TMPBUFLEN % 32);

	if (opts->iv) {
		uint8_t *newiv = NULL;
		uint32_t newivlen;

		ret = hex2bin_alloc(opts->iv, (uint32_t)strlen(opts->iv),
					&ivbuf, &ivbuflen);
		if (ret)
			goto out;

		/* generate the padded IV */
		if (ivbuflen != opts->func_blocksize(handle)) {
			ret = kcapi_pad_iv(handle, ivbuf, ivbuflen,
					   &newiv, &newivlen);
			if (ret)
				goto out;

			free(ivbuf);
			ivbuf = newiv;
			ivbuflen = newivlen;

			dolog_bin(KCAPI_LOG_DEBUG, ivbuf, ivbuflen,
				  "Padded IV");
		}

	} else if (opts->ccmnonce) {
		uint8_t *nonce;
		uint32_t noncelen;

		/* Convert a CCM nonce into an IV. */
		ret = hex2bin_alloc(opts->ccmnonce,
				    (uint32_t)strlen(opts->ccmnonce),
				    &nonce, &noncelen);
		if (ret)
			goto out;

		ret = kcapi_aead_ccm_nonce_to_iv(nonce, noncelen,
						 &ivbuf, &ivbuflen);
		free(nonce);
		if (ret)
			goto out;

		dolog(KCAPI_LOG_DEBUG,
		      "CCM nonce (%u bytes) convereted to IV (%u bytes)",
		      noncelen, ivbuflen);
		dolog_bin(KCAPI_LOG_DEBUG, ivbuf, ivbuflen,
			  "CCM nonce converted to IV");
	}

	/* AEAD specific code */
	if (opts->aad) {
		ret = hex2bin_alloc(opts->aad, (uint32_t)strlen(opts->aad),
				    &aadbuf, &opts->aadlen);
		if (ret)
			goto out;

		/* Set AAD length. */
		kcapi_aead_setassoclen(handle, opts->aadlen);
		dolog(KCAPI_LOG_DEBUG, "Set AAD length to %u bytes",
		      opts->aadlen);

		if (opts->tag) {
			ret = hex2bin_alloc(opts->tag,
					    (uint32_t)strlen(opts->tag),
					    &tagbuf, &opts->taglen);
			if (ret)
				goto out;
		}

		/* Set tag length. */
		if (opts->taglen) {
			ret = kcapi_aead_settaglen(handle, opts->taglen);
			if (ret)
				goto out;

			dolog(KCAPI_LOG_DEBUG, "Set tag length to %u bytes",
			      opts->taglen);
		}
	}

	/* Access input data. */
	if (opts->infile) {
		infd = open(opts->infile, O_RDONLY | O_CLOEXEC);
		if (infd < 0) {
			dolog(KCAPI_LOG_ERR, "Cannot open file %s: %s",
			      opts->infile, strerror(errno));
			ret = -EIO;
			goto out;
		}
		ret = check_filetype(infd, &insb, opts->infile);
		if (ret)
			goto out;
	} else
		infd = STDIN_FD;

	/* Access output location */
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

	/* Initialize cipher operation */
	if (opts->decrypt)
		ret = opts->func_stream_init_dec(handle, ivbuf, NULL, 0);
	else
		ret = opts->func_stream_init_enc(handle, ivbuf, NULL, 0);
	if (ret)
		goto out;

	/* Send AAD in case we have it */
	if (aadbuf) {
		iniov.iov_base = aadbuf;
		iniov.iov_len = opts->aadlen;

		ret = opts->func_stream_update(handle, &iniov, 1);
		if (ret < 0)
			goto out;

		dolog(KCAPI_LOG_DEBUG, "Sent %u bytes of AAD",
		      opts->aadlen);
	}

	ret = kcapi_get_maxsplicesize(handle);
	if (ret < 0)
		goto out;
	maxdata = (unsigned int)ret;

	/* Get data from stdin. */
	if (infd == STDIN_FD) {
		bool data_sent = false;

		iniov.iov_base = tmpbuf;
		while ((iniov.iov_len =
		        fread(tmpbuf, sizeof(uint8_t), TMPBUFLEN, stdin))) {

			/* WARNING: with AEAD, only one loop is possible */
			if (opts->aad && data_sent) {
				dolog(KCAPI_LOG_ERR,
				      "Kernel is unable to receive AEAD data in chunks, send all AEAD data in one operation using a file (max numbers of bytes for STDIN is %u)\n",
				      TMPBUFLEN);
				ret = -EOVERFLOW;
				goto out;
			}

			ret = opts->func_stream_update(handle, &iniov, 1);
			if (ret < 0)
				goto out;

			outsize = outbufsize(handle, opts,
					     (uint32_t)iniov.iov_len);
			ret = sendtag(handle, opts, tagbuf, tagtmpbuf);
			if (ret)
				goto out;

			if (outfd != STDOUT_FD) {
				ret = ftruncate(outfd,
					(off_t)(generated_bytes + outsize));
				if (ret)
					goto out;
			}

			/* padding */
			ret = add_padding(handle, opts, padbuf,
					  outsize, (uint32_t)iniov.iov_len);
			if (ret < 0)
				goto out;

			ret = return_data(handle, opts, outfd, outsize,
					  generated_bytes, 0);
			if (ret < 0)
				goto out;

			generated_bytes += (unsigned int)ret;
		}

	/* Get data from file. */
	} else {
		uint32_t sent_data = 0;

		inmem = mmap(NULL, (size_t)insb.st_size, PROT_READ, MAP_SHARED,
			     infd, 0);
		if (inmem == MAP_FAILED) {
			dolog(KCAPI_LOG_ERR, "Use of mmap for infd failed");
			ret = -ENOMEM;
			goto out;
		}

		if (outfd != STDOUT_FD && insb.st_size) {
			uint8_t padbyte;

			outsize = outbufsize(handle, opts,
					     (uint32_t)insb.st_size);
			ret = ftruncate(outfd, (off_t)outsize);
			if (ret)
				goto out;

			padbyte = *(inmem + insb.st_size - 1);

			/*
			 * Warn if trailing bytes look like padding although
			 * we will not apply padding.
			 */
			if (!opts->decrypt &&
			    !(insb.st_size % opts->func_blocksize(handle)) &&
			    (uint32_t)padbyte < opts->func_blocksize(handle)) {
				uint32_t i;
				uint32_t padded = 1;

				for (i = (uint32_t)insb.st_size - 2;
				     i >=  insb.st_size - (uint32_t)padbyte;
				     i--) {
					if (*(inmem + i) != padbyte) {
						padded = 0;
						break;
					}
				}

				if (padded &&
				    ((uint64_t)insb.st_size ==
				     (i + (uint32_t)padbyte) + 1)) {
					dolog(KCAPI_LOG_WARN,
					      "Input file's trailing bytes will be treated as padding during decryption unless you turn off padding handling with --nounpad\n");
				}
			}
		}

		while (sent_data < (uint64_t)insb.st_size) {
			uint32_t avail = (uint32_t)insb.st_size - sent_data;
			uint32_t todo = avail > maxdata ? maxdata : avail;

			if (opts->aad && avail > todo) {
				dolog(KCAPI_LOG_VERBOSE,
				      "Increase pipeseize for AEAD operation to %u\n",
				      avail);

				ret = kcapi_set_maxsplicesize(handle, avail);
				if (ret < 0)
					goto out;
				todo = avail;
			}

			iniov.iov_base = inmem + sent_data;
			iniov.iov_len = todo;
			ret = opts->func_stream_update(handle, &iniov, 1);
			if (ret < 0)
				goto out;

			outsize = outbufsize(handle, opts,
					     (uint32_t)iniov.iov_len);

			ret = sendtag(handle, opts, tagbuf, tagtmpbuf);
			if (ret)
				goto out;

			/* padding */
			ret = add_padding(handle, opts, padbuf,
					  outsize, (uint32_t)iniov.iov_len);
			if (ret < 0)
				goto out;

			ret = return_data(handle, opts, outfd, outsize,
					  generated_bytes, outsize == avail);
			if (ret < 0)
				goto out;

			generated_bytes += (unsigned int)ret;
			sent_data += todo;
		}
	}

out:
	if (inmem && inmem != MAP_FAILED)
		munmap(inmem, (size_t)insb.st_size);

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

	return (ret < 0) ? (int)ret : (int)generated_bytes;
}

/**
 * Set the key for a cipher operation. This function potentially derives
 * the key from a given passphrase.
 */
static int set_key(struct kcapi_handle *handle, struct opt_data *opts)
{
	uint8_t passwdbuf[128] __aligned(KCAPI_APP_ALIGN);
	uint32_t passwdlen = 0;
	uint8_t keybuf[64] __aligned(KCAPI_APP_ALIGN);
	uint32_t keybuflen = 0;
	int have_key = 0;
	const uint8_t *passwdptr = NULL;
	ssize_t ret;

	if (opts->key_len > sizeof(keybuf))
		return -EINVAL;

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

	/* Transform password into a key using PBKDF2. */
	if (passwdptr && passwdlen) {
		uint8_t *saltbuf = NULL;
		uint32_t saltbuflen = 0;

		dolog(KCAPI_LOG_DEBUG, "password %s", passwdptr);

		/* Determine the number of PBKDF2 iterations. */
		if (!opts->pbkdf_iterations) {
			opts->pbkdf_iterations =
			     kcapi_pbkdf_iteration_count(opts->pbkdf_hash, 0);

			dolog(KCAPI_LOG_WARN, "PBKDF2 iterations used: %u",
			      opts->pbkdf_iterations);
		}

		/* Convert the salt hex representation into binary. */
		if (opts->salt) {
			ret = hex2bin_alloc(opts->salt,
					    (uint32_t)strlen(opts->salt),
					    &saltbuf, &saltbuflen);
			if (ret)
				goto out;
		} else {
			/* No salt provided, generate a random number. */
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

		/*
		 * PBKDF2 operation: generate a key from password --
		 * reading of sizeof(keybuf) implies 256 bit key.
		*/
		ret = kcapi_pbkdf(opts->pbkdf_hash, passwdptr, passwdlen,
				  saltbuf, saltbuflen, opts->pbkdf_iterations,
				  keybuf, opts->key_len);
		free(saltbuf);
		if (ret)
			goto out;

		have_key = 1;
		keybuflen = opts->key_len;

		dolog(KCAPI_LOG_VERBOSE,
		      "Data Encryption Key derived from Password using PBKDF2 using %s with %u iterations",
		      opts->pbkdf_hash, opts->pbkdf_iterations);
	}

	/* Get key from key FD */
	if (opts->key_fd != -1) {
		ret = read_complete(opts->key_fd, keybuf, opts->key_len);
		if (ret < 0)
			goto out;

		have_key = 1;
		keybuflen = (uint32_t)ret;
	}

	if (!have_key) {
		dolog(KCAPI_LOG_ERR, "No key found in input data");
		ret = -EINVAL;
		goto out;
	}

	dolog_bin(KCAPI_LOG_DEBUG, keybuf, keybuflen, "data-encryption-key");

	/* Set the key for the key handle. */
	ret = opts->func_setkey(handle, keybuf, keybuflen);

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

	fprintf(stderr, "\nKernel Crypto API Symmetric Crypto Helper\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-c --cipher <NAME>\tCipher name to use for crypto operation\n");
	fprintf(stderr, "\t-e --encrypt\t\tEncryption operation (default)\n");
	fprintf(stderr, "\t-d --decrypt\t\tDecryption operation\n");
	fprintf(stderr, "\t-i --infile <FILE>\tFile with input data\n");
	fprintf(stderr, "\t-o --outfile <FILE>\tFile with output data\n");
	fprintf(stderr, "\t   --iv <IV>\t\tIV for cipher operation\n");
	fprintf(stderr, "\t   --aad <AAD>\t\tAAD for AEAD cipher operation\n");
	fprintf(stderr, "\t   --tag <TAG>\t\tTag for AEAD decryption operation\n");
	fprintf(stderr, "\t   --taglen <BYTES>\tTag length to be generated AEAD encryption\n");
	fprintf(stderr, "\t   --ccm-nonce <NONCE>\tCCM nonce (instead of IV)\n");
	fprintf(stderr, "\t\t\t\toperation\n");
	fprintf(stderr, "\t   --key-len <LENGTH>\tLength of key passed to cipher");
	fprintf(stderr, " (default: 32)\n");
	fprintf(stderr, "\t-s --salt <SALT>\tSalt for PBKDF2\n");
	fprintf(stderr, "\t-p --passwd <PWD>\tPassword the session key is derived from using\n");
	fprintf(stderr, "\t\t\t\tPBKDF2\n");
	fprintf(stderr, "\t   --passwdfd <FD>\tPassword file descriptor providing password\n");
	fprintf(stderr, "\t   --pbkdfiter <NUM>\tNumber of PBKDF2 iterations\n");
	fprintf(stderr, "\t   --pbkdfmac <MAC>\tMac for PBKDF2 (default: hmac(sha256))\n");
	fprintf(stderr, "\t   --keyfd <FD>\t\tKey file descriptor providing password\n");
	fprintf(stderr, "\t   --nounpad\t\tDo not unpad output file\n");
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
	opts->key_len = 32;

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
			{"ccm-nonce",	required_argument,	0, 0},
			{"salt",	required_argument,	0, 's'},
			{"passwd",	required_argument,	0, 'p'},
			{"passwdfd",	required_argument,	0, 0},
			{"pbkdfiter",	required_argument,	0, 0},
			{"pbkdfmac",	required_argument,	0, 0},
			{"keyfd",	required_argument,	0, 0},
			{"nounpad",	no_argument,		0, 0},

			{"verbose",	no_argument,		0, 'v'},
			{"quiet",	no_argument,		0, 'q'},
			{"help",	no_argument,		0, 'h'},
			{"version",	no_argument,		0, 0},
			{"key-len",	required_argument,	0, 0},
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
				opts->decrypt = false;
				break;
			case 2:
				opts->decrypt = true;
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
				opts->taglen = (uint32_t)val;
				break;
			case 9:
				opts->ccmnonce = optarg;
				break;
			case 10:
				opts->salt = optarg;
				break;
			case 11:
				opts->passwd = optarg;
				break;
			case 12:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->password_fd = (int)val;
				break;
			case 13:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "PBKDF2 iteration value too big");
					usage();
				}
				opts->pbkdf_iterations = (uint32_t)val;
				break;
			case 14:
				opts->pbkdf_hash = optarg;
				break;
			case 15:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Passwd FD value too big");
					usage();
				}
				opts->key_fd = (int)val;
				break;
			case 16:
				opts->nounpad = true;
				break;

			case 17:
				verbosity++;
				break;
			case 18:
				verbosity = KCAPI_LOG_NONE;
				break;
			case 19:
				usage();
				break;
			case 20:
				memset(version, 0, sizeof(version));
				kcapi_versionstring(version, sizeof(version));
				fprintf(stderr, "Version %s\n", version);
				exit(0);
				break;
			case 21:
				val = strtoul(optarg, NULL, 10);
				if (val == UINT_MAX) {
					dolog(KCAPI_LOG_ERR,
					      "Key length value too big");
					usage();
				}
				opts->key_len = (uint32_t)val;
				break;
			default:
				usage();
			}
			break;

		case 'c':
			opts->ciphername = optarg;
			break;
		case 'e':
			opts->decrypt = false;
			break;
		case 'd':
			opts->decrypt = true;
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

	set_verbosity("kcapi-enc", verbosity);

	if (!opts->ciphername) {
		dolog(KCAPI_LOG_ERR, "Provide cipher name");
		usage();
	}

	if (!opts->passwd && opts->password_fd == -1 &&
	    opts->key_fd == -1) {
		dolog(KCAPI_LOG_ERR,
		      "Provide at least a password, a password FD or key FD");
		usage();
	}

	if (opts->aad) {
		if (opts->decrypt && !opts->tag) {
			dolog(KCAPI_LOG_ERR,
			      "No tag provided for AEAD decryption operation");
			usage();
		}
		if (!opts->decrypt && !opts->taglen) {
			dolog(KCAPI_LOG_ERR,
			      "No tag length provided for AEAD encryption operation");
			usage();
		}
	}

	if (opts->iv && opts->ccmnonce) {
		dolog(KCAPI_LOG_ERR, "IV and CCM nonce set\n");
		usage();
	}

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

	if (opts.aad) {
		opts.func_init = kcapi_aead_init;
		opts.func_destroy = kcapi_aead_destroy;
		opts.func_setkey = kcapi_aead_setkey;
		opts.func_stream_init_enc = kcapi_aead_stream_init_enc;
		opts.func_stream_init_dec = kcapi_aead_stream_init_dec;
		opts.func_stream_update = kcapi_aead_stream_update;
		opts.func_stream_update_last = kcapi_aead_stream_update_last;
		opts.func_stream_op = kcapi_aead_stream_op;
		opts.func_blocksize = kcapi_aead_blocksize;
	} else {
		opts.func_init = kcapi_cipher_init;
		opts.func_destroy = kcapi_cipher_destroy;
		opts.func_setkey = kcapi_cipher_setkey;
		opts.func_stream_init_enc = kcapi_cipher_stream_init_enc;
		opts.func_stream_init_dec = kcapi_cipher_stream_init_dec;
		opts.func_stream_update = kcapi_cipher_stream_update;
		opts.func_stream_update_last = kcapi_cipher_stream_update_last;
		opts.func_stream_op = kcapi_cipher_stream_op;
		opts.func_blocksize = kcapi_cipher_blocksize;
	}

	/* Initialize link to the kernel's AF_ALG interface. */
	ret = opts.func_init(&handle, opts.ciphername, 0);
	if (ret)
		return ret;

	/* Set the key from password or key-FD. */
	ret = set_key(handle, &opts);
	if (ret)
		goto out;

	/* Perform cipher operation. */
	ret = cipher_op(handle, &opts);

	if (ret >= 0) {
		dolog(KCAPI_LOG_VERBOSE, "%d bytes of %stext created",
		      ret, opts.decrypt ? "plain" : "cipher");
		ret = 0;
	} else {
		if (ret == -EBADMSG && opts.aad) {
			dolog(KCAPI_LOG_ERR,
			      "AEAD decryption failed due to integrity violation");
		} else {
			dolog(KCAPI_LOG_ERR, "%s failed with error %d",
			      opts.decrypt ? "decryption" : "encryption", ret);
		}
	}

out:
	opts.func_destroy(handle);

	return ret;
}
