/*
 * Copyright (C) 2015 - 2018, Stephan Mueller <smueller@chronox.de>
 * Copyright (C) 2018, Red Hat, Inc. All rights reserved.
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

/*
 * Program implements a drop-in replacement (i.e. same output, behavior and
 * command line switches) for:
 *	* sha1sum
 *	* sha224sum
 *	* sha256sum
 *	* sha384sum
 *	* sha512sum
 *	* md5sum
 *	* fipscheck with hard coded key from libfipscheck
 *	* fipshmac with hard coded key from libfipscheck
 *	* sha1hmac
 *	* sha224hmac
 *	* sha256hmac
 *	* sha384hmac
 *	* sha512hmac
 *
 * Once the application is compiled, a symlink or hardlink to the
 * aforementioned application would turn the binary into behaving like the
 * respective application.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <ctype.h>
#include <dlfcn.h>
#include <libgen.h>
#include <limits.h>

#include <kcapi.h>

#include "app-internal.h"

struct hash_name {
	const char *kcapiname;
	const char *bsdname;
};

const struct hash_name NAMES_MD5[2] = {
	{ "md5", "MD5" }, { "hmac(md5)", "HMAC(MD5)" }
};
const struct hash_name NAMES_SHA1[2] = {
	{ "sha1", "SHA1" }, { "hmac(sha1)", "HMAC(SHA1)" }
};
const struct hash_name NAMES_SHA224[2] = {
	{ "sha224", "SHA224" }, { "hmac(sha224)", "HMAC(SHA224)" }
};
const struct hash_name NAMES_SHA256[2] = {
	{ "sha256", "SHA256" }, { "hmac(sha256)", "HMAC(SHA256)" }
};
const struct hash_name NAMES_SHA384[2] = {
	{ "sha384", "SHA384" }, { "hmac(sha384)", "HMAC(SHA384)" }
};
const struct hash_name NAMES_SHA512[2] = {
	{ "sha512", "SHA512" }, { "hmac(sha512)", "HMAC(SHA512)" }
};

static uint8_t fipscheck_hmackey[] = "orboDeJITITejsirpADONivirpUkvarP";
static uint8_t hmaccalc_hmackey[] = "FIPS-FTW-RHT2009";

static void usage(char *name)
{
	fprintf(stderr, "\n%s - calculation of hash sum (Using Linux Kernel Crypto API)\n", basename(name));
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t%s [OPTION] ... [FILE] ...\n", basename(name));
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-c --check [FILE]\tVerify hash sums from file\n");
	fprintf(stderr, "\t-q --quiet\t\tDo not print out verification result for\n");
	fprintf(stderr, "\t\t\t\tevery file\n");
	fprintf(stderr, "\t-s --status\t\tResult of verification given with return code\n");
	fprintf(stderr, "\t-k --hkey [HEX KEY]\tPerform HMAC verification with given key\n");
	fprintf(stderr, "\t-b --bkey [KEY]\t\tPerform HMAC verification with given key\n");
	fprintf(stderr, "\t--tag\t\t\tCreate a BSD-style checksum\n");
	fprintf(stderr, "\t-h --help\t\tPrint this help text\n");
	fprintf(stderr, "\t-v --version\t\tShow version\n");
}

static void version(char *name)
{
	char version[20];

	memset(version, 0, 20);
	kcapi_versionstring(version, 20);
	
	fprintf(stderr, "%s: %s\n", basename(name), version);
}

static int hasher(struct kcapi_handle *handle, char *filename,
		  const char *comphash, uint32_t comphashlen,
		  const char *bsdhashname, FILE *outfile)
{	
	int fd = -1;
	int ret = 0;
	struct stat sb;
	char *memblock = NULL;
	uint8_t *memblock_p;
	uint8_t md[64];

	if (filename) {
		fd = open(filename, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			fprintf(stderr, "Cannot open file %s: %s\n", filename,
				strerror(errno));
			return -EIO;
		}

		/*
		 * Do not return an error in case we cannot validate the data.
		 */
		ret = check_filetype(fd, &sb, filename);
		if (ret)
			goto out;

		if (sb.st_size) {
			memblock = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
			if (memblock == MAP_FAILED)
			{
				fprintf(stderr, "Use of mmap failed\n");
				ret = -ENOMEM;
				goto out;
			}
		}

		/* Compute hash */
		memblock_p = (uint8_t *)memblock;
		while (sb.st_size) {
			uint32_t todo = (sb.st_size > INT_MAX) ? INT_MAX : sb.st_size;

			ret = kcapi_md_update(handle, memblock_p, todo);
			if (ret < 0)
				goto out;
			sb.st_size -= todo;
			memblock_p += todo;
		}
	} else {
		uint8_t tmpbuf[TMPBUFLEN] __aligned(KCAPI_APP_ALIGN);
		size_t bufsize;

		while ((bufsize =
		        fread(tmpbuf, sizeof(uint8_t), TMPBUFLEN, stdin))) {

			ret = kcapi_md_update(handle, tmpbuf, bufsize);
			if (ret < 0)
				goto out;
		}
		kcapi_memset_secure(tmpbuf, 0, sizeof(tmpbuf));
	}

	ret = kcapi_md_final(handle, md, sizeof(md));

	if (ret > 0) {
		if (comphash && comphashlen) {
			uint8_t compmd[64];

			memset(compmd, 0, sizeof(compmd));
			hex2bin(comphash, comphashlen, compmd, sizeof(compmd));
			if ((comphashlen != (uint32_t)(ret * 2)) ||
			    memcmp(compmd, md, ret))
				ret = 1;
			else
				ret = 0;
		} else {
			if (bsdhashname) {
				fprintf(outfile, "%s (%s) = ", bsdhashname,
					filename ? filename : "-");
				bin2print(md, ret, NULL, outfile, 1);
			} else {
				bin2print(md, ret, filename ? filename : "-",
					  outfile, 1);
			}
			ret = 0;
		}
	} else {
		fprintf(stderr, "Generation of hash for file %s failed (%d)\n",
			filename ? filename : "stdin", ret);
	}

out:
	if (memblock && memblock != MAP_FAILED)
		munmap(memblock, sb.st_size);
	if (fd >= 0)
		close(fd);

	return ret;
}

/*
 * Convert a given file name into its respective HMAC file name
 *
 * return: NULL when malloc failed, a pointer that the caller must free
 * otherwise.
 */
static char *get_hmac_file(char *filename)
{
	uint32_t basenamestart = 0;
	uint32_t i;
	uint32_t filelen;
	char *checkfile = NULL;

	filelen = strlen(filename);
	if (filelen > 4096) {
		fprintf(stderr, "File too long\n");
		return NULL;
	}
	checkfile = malloc(filelen + 7);
	if (!checkfile)
		return NULL;

	for (i = 0; i < filelen; i++) {
		if (!strncmp(filename + i, "/", 1))
			basenamestart = i + 1;
	}
	if (basenamestart > 0)
		strncpy(checkfile, filename, basenamestart);
	strncpy(checkfile + basenamestart, ".", 1);
	strncpy(checkfile + basenamestart + 1,
		filename + basenamestart,
		filelen - basenamestart);
	strncpy(checkfile + filelen + 1, ".hmac", 5);
	strncpy(checkfile + filelen + 6, "\0", 1);
	return checkfile;
}

static int hash_files(const char *hashname, const char *bsdhashname,
		      char *filename[], uint32_t files,
		      const uint8_t *hmackey, uint32_t hmackeylen,
		      int fipshmac)
{
	struct kcapi_handle *handle;
	uint32_t i = 0;
	int ret = 0;
	
	ret = kcapi_md_init(&handle, hashname, 0);
	if (ret) {
		fprintf(stderr, "Allocation of %s cipher failed (ret=%d)\n",
			hashname, ret);
		return -EFAULT;
	}
	if (hmackey) {
		ret = kcapi_md_setkey(handle, hmackey, hmackeylen);
		if (ret) {
			fprintf(stderr, "Setting HMAC key for %s failed (%d)\n",
				hashname, ret);
			return -EINVAL;
		}
	}
	
	if (files) {
		for (i = 0; i < files; i++) {
			FILE *out = stdout;

			if (fipshmac) {
				char *outfile = get_hmac_file(filename[i]);

				if (!outfile) {
					fprintf(stderr,
						"Cannot create HMAC file name\n");
					continue;
				}
				out = fopen(outfile, "w");
				if (!out) {
					fprintf(stderr,
						"Cannot open HMAC file %s\n",
						outfile);
					free(outfile);
					continue;
				}
				free(outfile);
			}
			ret = hasher(handle, filename[i], NULL, 0, bsdhashname, out);
			if (fipshmac)
				fclose(out);
			if (ret)
				break;
		}
	} else {
		ret = hasher(handle, NULL, NULL, 0, bsdhashname, stdout);
	}

	kcapi_md_destroy(handle);
	return ret;
}

#define CHK_QUIET (1)
#define CHK_STATUS (2)

static int process_checkfile(const char *hashname,  const char *bsdhashname,
			     char *checkfile, char *targetfile, int log,
			     const uint8_t *hmackey, uint32_t hmackeylen)
{
	FILE *file = NULL;
	int ret = 0;
	struct kcapi_handle *handle;

	/*
	 * A file can have up to 4096 characters, so a complete line has at most
	 * 4096 bytes (file name) + 128 bytes (SHA512 hex value) + 2 spaces +
	 * one byte for the CR.
	 */
	char buf[(4096 + 128 + 2 + 1)];

	ret = kcapi_md_init(&handle, hashname, 0);
	if (ret) {
		fprintf(stderr, "Allocation of %s cipher failed (%d)\n",
			hashname, ret);
		return -EFAULT;
	}
	if (hmackey) {
		ret = kcapi_md_setkey(handle, hmackey, hmackeylen);
		if (ret) {
			fprintf(stderr, "Setting HMAC key for %s failed (%d)\n",
				hashname, ret);
			return -EINVAL;
		}
	}

	file = fopen(checkfile, "r");
	if (!file) {
		fprintf(stderr, "Cannot open file %s\n", checkfile);
		ret = 253;
		goto out;
	}

	while (fgets(buf, sizeof(buf), file)) {
		char *filename = NULL; // parsed file name
		char *hexhash = NULL;  // parsed hex value of hash
		uint32_t hashlen = 0;  // length of hash hex value
		uint32_t linelen = strlen(buf);
		uint32_t i;
		uint32_t bsd_style = 0; // >0 if --tag formatted style

		/* remove trailing CR and reduce buffer length */
		for (i = linelen; i > 0; i--) {
			if (!isprint(buf[i])) {
				buf[i] = '\0';
				linelen--;
			} else
				break;
		}

		for (i = 0; i < linelen; i++) {

			/*
			 * Check for BSD-style separator between file name and
			 * hash value.
			 */
			if (((linelen - i) >= 3) &&
			    isblank(buf[i]) &&
			    buf[i+1] == '=' &&
			    isblank(buf[i+2])) {
				/* Start of hash value */
				bsd_style = i + 3;
				hexhash = buf + bsd_style;
				break;
			}
		}

		for (i = 0; i < linelen; i++) {
			/* file name / hash separator for regular case */
			if (!bsd_style && isblank(buf[i])) {
				filename = buf + i;
				break;
			}

			/* Count hash bytes */
			if (!bsd_style && !filename)
				hashlen++;

			/* Find file name start value of BSD-style. */
			if (bsd_style &&
			    (linelen - i) >= 2 &&
			     isblank(buf[i]) &&
			     buf[i + 1] == '(') {
				filename = buf + i + 2;
				break;
			}
		}

		/* In regular case, hash starts at the beginning of buffer. */
		if (!bsd_style)
			hexhash = buf;

		if (bsd_style) {
			/* Hash starts after separator */
			hashlen = linelen - bsd_style + 1;

			/* remove closing parenthesis behind filename */
			if (buf[(bsd_style - 4)] == ')')
				buf[(bsd_style - 4)] = '\0';
		}

		if (!hexhash || !hashlen) {
			printf("Hash not found\n");
			ret = 1;
			goto out;
		}

		if (filename) {
			int r;

			/* Consume leading blank characters */
			while (isblank(*filename) && isprint(*filename))
				filename++;

			r = hasher(handle, filename, hexhash, hashlen,
				   bsdhashname, stdout);

			if (r == 0) {
				if (log < CHK_QUIET)
					printf("%s: OK\n", filename);
			} else {
				if (log < CHK_STATUS)
					printf("%s: Not OK\n",
						filename);
				if (ret >= 0)
					ret++;
			}
		} else {
			/*
			 * fipscheck does not have the filename in the check
			 * file
			 */
			if (targetfile) {
				ret = hasher(handle, targetfile,
					     hexhash, hashlen + 1,
					     bsdhashname, stdout);
				goto out;
			}
		}
	}

out:
	if (file)
		fclose(file);
	kcapi_md_destroy(handle);
	return ret;

}

static int fipscheck_self(const char *hash,
			  const uint8_t *hmackey, uint32_t hmackeylen)
{
	char *checkfile = NULL;
	uint32_t n = 0;
	int ret = -EINVAL;
	char fipsflag[1];
#define BUFSIZE 4096
	char selfname[BUFSIZE];
	int32_t selfnamesize = 0;
	Dl_info info;
	void *dl, *sym;

#ifdef HAVE_SECURE_GETENV
	if (secure_getenv("KCAPI_HASHER_FORCE_FIPS")) {
#else
	if (getenv("KCAPI_HASHER_FORCE_FIPS")) {
#endif
		fipsflag[0] = 1;
	} else {
		FILE *fipsfile = NULL;

		fipsfile = fopen("/proc/sys/crypto/fips_enabled", "r");
		if (!fipsfile) {
			if (errno == ENOENT) {
				/* FIPS support not enabled in kernel */
				return 0;
			} else {
				fprintf(stderr, "Cannot open fips_enabled file: %s\n",
					strerror(errno));
				return -EIO;
			}
		}

		n = fread((void *)fipsflag, 1, 1, fipsfile);
		fclose(fipsfile);
		if (n != 1) {
			fprintf(stderr, "Cannot read FIPS flag\n");
			goto out;
		}
	}

	if (fipsflag[0] == '0') {
		ret = 0;
		goto out;
	}

	/* Integrity check of our application. */
	memset(selfname, 0, sizeof(selfname));
	selfnamesize = readlink("/proc/self/exe", selfname, BUFSIZE);
	if (selfnamesize >= BUFSIZE || selfnamesize < 0) {
		fprintf(stderr, "Cannot obtain my filename\n");
		ret = -EFAULT;
		goto out;
	}

	checkfile = get_hmac_file(selfname);
	if (!checkfile) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_checkfile(hash, NULL, checkfile, selfname,
				CHK_STATUS, hmackey, hmackeylen);
	if (ret)
		goto out;

	/* Integrity check of shared libkcapi.so file. */
	memset(selfname, 0, sizeof(selfname));
	snprintf(selfname, (sizeof(selfname) - 1), "libkcapi.so.%u",
		 KCAPI_MAJVERSION);
	dl = dlopen(selfname, RTLD_NODELETE|RTLD_NOLOAD|RTLD_LAZY);
	if (dl == NULL) {
		fprintf(stderr, "dlopen of file %s failed\n", selfname);
		ret = -EFAULT;
		goto out;
	}

	memset(selfname, 0, sizeof(selfname));
	sym = dlsym(dl, "kcapi_md_init");
	if (sym == NULL || !dladdr(sym, &info)) {
		fprintf(stderr, "finding symbol kcapi_md_init failed\n");
		ret = -EFAULT;
		goto out;
	}

	strncpy(selfname, info.dli_fname, (sizeof(selfname) - 1));

	dlclose(dl);

	free(checkfile);
	checkfile = get_hmac_file(selfname);
	if (!checkfile) {
		ret = -ENOMEM;
		goto out;
	}

	ret = process_checkfile(hash, NULL, checkfile, selfname, CHK_STATUS,
				hmackey, hmackeylen);

out:
	if (checkfile)
		free(checkfile);
	return ret;
}

int main(int argc, char *argv[])
{
	const struct hash_name *names;
	const char *hash;
	const char *bsdhash;
	char *basec = NULL;
	char *basen = NULL;
	int ret = -EFAULT;

	char *checkfile = NULL;
	char *targetfile = NULL;
	uint8_t *hmackey = NULL;
	uint32_t hmackeylen = 0;
	int loglevel = 0;
	int hmac = 0;
	int fipscheck = 0;
	int fipshmac = 0;
	int bsd_style = 0;

	/*
	 * Self-integrity check:
	 *	* fipscheck/fipshmac and sha*sum equivalents are using the
	 *	  fipscheck key and hmac(sha256)
	 *	* hmaccalc applications are using the hmaccalc key and
	 *	  hmac(sha512)
	 */
	uint8_t *check_hmackey = fipscheck_hmackey;
	uint32_t check_hmackeylen = strlen((char *)fipscheck_hmackey);
	const char *check_hash;

	static struct option opts[] =
	{
		{"check", 1, 0, 'c'},
		{"quiet", 0, 0, 'q'},
		{"status", 0, 0, 's'},
		{"version", 0, 0, 'v'},
		{"hkey", 1, 0, 'k'},
		{"bkey", 1, 0, 'b'},
		{"help", 0, 0, 'h'},
		{"tag", 0, 0, 0},
		{0, 0, 0, 0}
	};

	basec = strdup(argv[0]);
	if (!basec) {
		fprintf(stderr, "Error copying file name: %s\n",
			strerror(errno));
		return 255;
	}
	basen = basename(basec);

	check_hash = "hmac(sha256)";
	if (0 == strncmp(basen, "sha256sum", 9)) {
		names = NAMES_SHA256;
	} else if (0 == strncmp(basen, "sha512sum", 9)) {
		names = NAMES_SHA512;
	} else if (0 == strncmp(basen, "sha1sum", 7)) {
		names = NAMES_SHA1;
	} else if (0 == strncmp(basen, "sha224sum", 9)) {
		names = NAMES_SHA224;
	} else if (0 == strncmp(basen, "sha384sum", 9)) {
		names = NAMES_SHA384;
	} else if (0 == strncmp(basen, "md5sum", 6)) {
		names = NAMES_MD5;
	} else if (0 == strncmp(basen, "fipshmac", 8)) {
		names = NAMES_SHA256;
		hmac = 1;
		hmackey = fipscheck_hmackey;
		hmackeylen = strlen((char *)fipscheck_hmackey);
		fipshmac = 1;
	} else if (0 == strncmp(basen, "fipscheck", 9)) {
		names = NAMES_SHA256;
		hmac = 1;
		hmackey = fipscheck_hmackey;
		hmackeylen = strlen((char *)fipscheck_hmackey);
		fipscheck = 1;
	} else if (0 == strncmp(basen, "sha1hmac", 8)) {
		names = NAMES_SHA1;
		hmac = 1;
		hmackey = hmaccalc_hmackey;
		hmackeylen = strlen((char *)hmaccalc_hmackey);
		check_hash = "hmac(sha512)";
		check_hmackey = hmaccalc_hmackey;
		check_hmackeylen = strlen((char *)hmaccalc_hmackey);
	} else if (0 == strncmp(basen, "sha224hmac", 10)) {
		names = NAMES_SHA224;
		hmac = 1;
		hmackey = hmaccalc_hmackey;
		hmackeylen = strlen((char *)hmaccalc_hmackey);
		check_hash = "hmac(sha512)";
		check_hmackey = hmaccalc_hmackey;
		check_hmackeylen = strlen((char *)hmaccalc_hmackey);
	} else if (0 == strncmp(basen, "sha256hmac", 10)) {
		names = NAMES_SHA256;
		hmac = 1;
		hmackey = hmaccalc_hmackey;
		hmackeylen = strlen((char *)hmaccalc_hmackey);
		check_hash = "hmac(sha512)";
		check_hmackey = hmaccalc_hmackey;
		check_hmackeylen = strlen((char *)hmaccalc_hmackey);
	} else if (0 == strncmp(basen, "sha384hmac", 10)) {
		names = NAMES_SHA384;
		hmac = 1;
		hmackey = hmaccalc_hmackey;
		hmackeylen = strlen((char *)hmaccalc_hmackey);
		check_hash = "hmac(sha512)";
		check_hmackey = hmaccalc_hmackey;
		check_hmackeylen = strlen((char *)hmaccalc_hmackey);
	} else if (0 == strncmp(basen, "sha512hmac", 10)) {
		names = NAMES_SHA512;
		hmac = 1;
		hmackey = hmaccalc_hmackey;
		hmackeylen = strlen((char *)hmaccalc_hmackey);
		check_hash = "hmac(sha512)";
		check_hmackey = hmaccalc_hmackey;
		check_hmackeylen = strlen((char *)hmaccalc_hmackey);
	} else {
		fprintf(stderr, "Unknown invocation name: %s\n", basen);
		goto out;
	}

	while (1) {
		int opt_index = 0;
		int c = getopt_long(argc, argv, "c:qsvk:b:h", opts, &opt_index);
		
		if (-1 == c)
			break;
		switch (c) {
			case 0:
				switch (opt_index) {
				case 0:
					if (checkfile)
						free(checkfile);
					checkfile = strdup(optarg);
					if (!checkfile) {
						fprintf(stderr, "Error copying file name: %s\n",
							strerror(errno));
						goto out;
					}
					break;
				case 1:
					loglevel = CHK_QUIET;
					break;
				case 2:
					loglevel = CHK_STATUS;
					break;
				case 3:
					version(argv[0]);
					ret = 0;
					goto out;
					break;
				case 4:
					if (hmackey &&
					    hmackey != fipscheck_hmackey &&
					    hmackey != hmaccalc_hmackey) {
						kcapi_memset_secure(hmackey, 0,
								    hmackeylen);
						free(hmackey);
						hmackey = NULL;
					}
					if (hex2bin_alloc(optarg,
							  strlen(optarg),
							  &hmackey,
							  &hmackeylen)) {
						fprintf(stderr, "Cannot allocate memory for HMAC key\n");
						goto out;
					}
					hmac = 1;
					break;
				case 5:
					if (hmackey &&
					    hmackey != fipscheck_hmackey &&
					    hmackey != hmaccalc_hmackey) {
						kcapi_memset_secure(hmackey, 0,
								    hmackeylen);
						free(hmackey);
						hmackey = NULL;
					}
					hmackey = (uint8_t *)strdup(optarg);
					if (!hmackey) {
						fprintf(stderr, "Cannot allocate memory for HMAC key\n");
						goto out;
					}
					hmackeylen = strlen(optarg);
					hmac = 1;
					break;
				case 6:
					usage(argv[0]);
					ret = 0;
					goto out;
				case 7:
					bsd_style = 1;
					break;
				}
				break;

			case 'v':
				version(argv[0]);
				ret = 0;
				goto out;
			case 'c':
				if (checkfile)
					free(checkfile);
				checkfile = strdup(optarg);
				if (!checkfile) {
					fprintf(stderr, "Error copying file name: %s\n",
						strerror(errno));
					goto out;
				}
				break;
			case 'q':
				loglevel = CHK_QUIET;
				break;
			case 's':
				loglevel = CHK_STATUS;
				break;
			case 'h':
				usage(argv[0]);
				ret = 0;
				goto out;
			case 'k':
				if (hmackey && hmackey != fipscheck_hmackey &&
				    hmackey != hmaccalc_hmackey) {
					kcapi_memset_secure(hmackey, 0,
							    hmackeylen);
					free(hmackey);
					hmackey = NULL;
				}
				if (hex2bin_alloc(optarg, strlen(optarg),
						  &hmackey, &hmackeylen)) {
					fprintf(stderr, "Cannot allocate memory for HMAC key\n");
					goto out;
				}
				hmac = 1;
				break;
			case 'b':
				if (hmackey && hmackey != fipscheck_hmackey &&
				    hmackey != hmaccalc_hmackey) {
					kcapi_memset_secure(hmackey, 0,
							    hmackeylen);
					free(hmackey);
					hmackey = NULL;
				}
				hmackey = (uint8_t *)strdup(optarg);
				if (!hmackey) {
					fprintf(stderr, "Cannot allocate memory for HMAC key\n");
					goto out;
				}
				hmackeylen = strlen(optarg);
				hmac = 1;
				break;
			default:
				usage(argv[0]);
				goto out;
		}
	}

	if (fipscheck_self(check_hash, check_hmackey, check_hmackeylen)) {
		fprintf(stderr, "Integrity check of application %s failed\n",
			basen);
		goto out;
	}

	if (fipscheck) {
		if (optind >= argc) {
			fprintf(stderr, "No file to check given for fipscheck\n");
			goto out;
		}

		targetfile = argv[optind];
		if (checkfile)
			free(checkfile);
		checkfile = get_hmac_file(targetfile);
		if (!checkfile)
			goto out;
		optind++;
	}

	hash = names[hmac].kcapiname;
	bsdhash = bsd_style ? names[hmac].bsdname : NULL;

	if (checkfile) {
		ret = process_checkfile(hash, bsdhash, checkfile, targetfile,
					loglevel, hmackey, hmackeylen);
		if (ret)
			goto out;
	} else if (optind == argc)
		ret = hash_files(hash, bsdhash, NULL, 0, hmackey, hmackeylen,
				 fipshmac);

	if (optind < argc)
		ret = hash_files(hash, bsdhash, argv + optind, (argc - optind),
				 hmackey, hmackeylen, fipshmac);


out:
	if (basec)
		free(basec);
	if (checkfile)
		free(checkfile);
	if (hmackey && hmackey != fipscheck_hmackey &&
	    hmackey != hmaccalc_hmackey) {
		kcapi_memset_secure(hmackey, 0, hmackeylen);
		free(hmackey);
	}
	
	return ret;
}
