/*
 * Copyright (C) 2015 - 2022, Stephan Mueller <smueller@chronox.de>
 * Copyright (C) 2022, Red Hat, Inc. All rights reserved.
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
 * Program implements a drop-in replacement (i.e. mostly the same output,
 * behavior and command line switches) for:
 *	* sha1sum
 *	* sha224sum
 *	* sha256sum
 *	* sha384sum
 *	* sha512sum
 *	* sm3sum
 *	* sha3sum
 *	* md5sum
 *	* fipscheck with hard coded key from libfipscheck
 *	* fipshmac with hard coded key from libfipscheck
 *	* sha1hmac
 *	* sha224hmac
 *	* sha256hmac
 *	* sha384hmac
 *	* sha512hmac
 *	* sm3hmac
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
#include <inttypes.h>

#include <kcapi.h>

#include "app-internal.h"

#define GCC_VERSION (__GNUC__ * 10000 \
			+ __GNUC_MINOR__ * 100 \
			+ __GNUC_PATCHLEVEL__)

struct hash_name {
	const char *kcapiname;
	const char *bsdname;
};

struct hash_key {
	const char *checkdir;
	const uint8_t *data;
	off_t len;
};

struct hash_params {
	struct hash_name name;
	struct hash_key key;
	uint32_t hashlen;
	int bsd_style;
	uint32_t newline;
};

static const struct hash_name NAMES_MD5[2] = {
	{ "md5", "MD5" }, { "hmac(md5)", "HMAC(MD5)" }
};
static const struct hash_name NAMES_SHA1[2] = {
	{ "sha1", "SHA1" }, { "hmac(sha1)", "HMAC(SHA1)" }
};
static const struct hash_name NAMES_SHA224[2] = {
	{ "sha224", "SHA224" }, { "hmac(sha224)", "HMAC(SHA224)" }
};
static const struct hash_name NAMES_SHA256[2] = {
	{ "sha256", "SHA256" }, { "hmac(sha256)", "HMAC(SHA256)" }
};
static const struct hash_name NAMES_SHA384[2] = {
	{ "sha384", "SHA384" }, { "hmac(sha384)", "HMAC(SHA384)" }
};
static const struct hash_name NAMES_SHA512[2] = {
	{ "sha512", "SHA512" }, { "hmac(sha512)", "HMAC(SHA512)" }
};
static const struct hash_name NAMES_SM3[2] = {
	{ "sm3", "SM3" }, { "hmac(sm3)", "HMAC(SM3)" }
};
static const struct hash_name NAMES_SHA3_224[1] = {
	{ "sha3-224", "SHA3-224" }
};
static const struct hash_name NAMES_SHA3_256[1] = {
	{ "sha3-256", "SHA3-256" }
};
static const struct hash_name NAMES_SHA3_384[1] = {
	{ "sha3-384", "SHA3-384" }
};
static const struct hash_name NAMES_SHA3_512[1] = {
	{ "sha3-512", "SHA3-512" }
};

static const char fipscheck_hmackey[] = "orboDeJITITejsirpADONivirpUkvarP";
static const char hmaccalc_hmackey[] = "FIPS-FTW-RHT2009";

static const struct hash_key KEY_FIPSCHECK = {
	.data = (const uint8_t *)fipscheck_hmackey,
	.len = sizeof(fipscheck_hmackey) - 1,
#ifdef CHECK_DIR
	.checkdir = CHECK_DIR"/fipscheck",
#else
	.checkdir = NULL,
#endif
};
static const struct hash_key KEY_HMACCALC = {
	.data = (const uint8_t *)hmaccalc_hmackey,
	.len = sizeof(hmaccalc_hmackey) - 1,
#ifdef CHECK_DIR
	.checkdir = CHECK_DIR"/hmaccalc",
#else
	.checkdir = NULL,
#endif
};

static void usage(char *name, int fipscheck)
{
	const char *base = basename(name);
	fprintf(stderr, "\n%s - calculation of hash sum (Using Linux Kernel Crypto API)\n", basename(name));
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t%s [-n BASENAME] [OPTION]... -S|-L\n", base);
	if (fipscheck)
		fprintf(stderr, "\t%s [-n BASENAME] [OPTION]... FILE\n", base);
	else {
		fprintf(stderr, "\t%s [-n BASENAME] [OPTION]... -c FILE\n", base);
		fprintf(stderr, "\t%s [-n BASENAME] [OPTION]... FILE...\n", base);
	}
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "\t-n --name\t\tForce given application name (sha512hmac/...)\n");
	fprintf(stderr, "\t-S --self-sum\t\tPrint checksum of this binary and exit\n");
	fprintf(stderr, "\t-L --self-sum-lib\tPrint checksum of the libkcapi library and exit\n");
	if (!fipscheck)
		fprintf(stderr, "\t-c --check FILE\t\tVerify hash sums from file\n");
	fprintf(stderr, "\t-u --unkeyed\t\tForce unkeyed hash\n");
	fprintf(stderr, "\t-h --hash HASH\t\tUse given hash algorithm\n");
	fprintf(stderr, "\t-t --truncate N\t\tUse hash truncated to N bits\n");
	fprintf(stderr, "\t-q --status\t\tSuppress verification output\n");
	fprintf(stderr, "\t   --quiet\t\tSuppress only success messages\n");
	fprintf(stderr, "\t-k --key-file FILE\tUse HMAC key from given file\n");
	fprintf(stderr, "\t-K --key KEY\t\tUse KEY as the HMAC key\n");
	fprintf(stderr, "\t   --tag\t\tCreate a BSD-style checksum\n");
	fprintf(stderr, "\t-d\t\t\tCheck directory for fipshmac; otherwise ignored\n");
	fprintf(stderr, "\t-b, -P\t\t\tCompatibility hmaccalc options; ignored\n");
	fprintf(stderr, "\t-z\t\t\tNUL line termination\n");
	fprintf(stderr, "\t   --help\t\tPrint this help text\n");
	fprintf(stderr, "\t-v --version\t\tShow version\n");
}

static void version(char *name)
{
	char version[20];

	memset(version, 0, 20);
	kcapi_versionstring(version, 20);
	
	fprintf(stderr, "%s: %s\n", basename(name), version);
}

static int mmap_file(const char *filename, uint8_t **memory, off_t *size,
		     size_t *mapped, off_t offset)
{
	int fd = -1;
	int ret = 0;
	struct stat sb;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file %s: %s\n", filename,
		        strerror(errno));
		return -EIO;
	}

	if (*size) {
		if ((*size - offset) < (off_t)*mapped )
			*mapped = (size_t)(*size - offset);
	} else {
		ret = check_filetype(fd, &sb, filename);
		if (ret)
			goto out;
		*size = sb.st_size;
		if (*size <= (off_t)*mapped) {
			*mapped = (size_t)*size;
		if (*size == 0)
			goto out;
		}
	}

	*memory = mmap(NULL, *mapped, PROT_READ, MAP_PRIVATE | MAP_POPULATE, fd,
		       offset);
	if (*memory == MAP_FAILED) {
		*memory = NULL;
		ret = -errno;
		goto out;
	}
	madvise(*memory, *mapped, MADV_SEQUENTIAL | MADV_WILLNEED);

out:
	close(fd);
	return ret;
}

static int load_file(const char *filename, uint8_t **memory, off_t *size)
{
	int fd = -1;
	int ret = 0;
	uint8_t *buffer = NULL;
	off_t buffer_size = 4096;
	off_t offset = 0;
	ssize_t rdbytes;

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file %s: %s\n", filename,
		        strerror(errno));
		return -EIO;
	}

	buffer = malloc(TMPBUFLEN);
	if (buffer == NULL) {
		fprintf(stderr, "Key memory allocation failed\n");
		ret = -ENOMEM;
		goto out;
	}

	while ((rdbytes = read(fd, buffer + offset, (size_t)(buffer_size - offset))) != 0) {
		if (rdbytes < 0) {
			fprintf(stderr, "Error reading file %s: %s\n", filename,
			        strerror(errno));
			ret = -EIO;
			goto out;
		}

		offset += (off_t)rdbytes;
		if (offset == buffer_size) {
			uint8_t *new_buffer;

			if (buffer_size == UINT32_MAX) {
				fprintf(stderr, "Key longer than UINT32_MAX\n");
				ret = -ERANGE;
				goto out;
			} else if (buffer_size * 2 < buffer_size)
				buffer_size = UINT32_MAX;
			else
				buffer_size *= 2;

			new_buffer = realloc(buffer, (size_t)buffer_size);
			if (new_buffer == NULL) {
				fprintf(stderr, "Key memory allocation failed\n");
				ret = -ENOMEM;
				goto out;
			}

			buffer = new_buffer;
		}
	}

	*memory = buffer;
	*size = offset;

	close(fd);
	return 0;

out:
	if (buffer)
		free(buffer);
	close(fd);
	return ret;
}

static int hasher(struct kcapi_handle *handle, const struct hash_params *params,
		  const char *filename, const char *comphash, uint32_t comphashlen,
		  FILE *outfile)
{
	/* Mapping file in 16M segments */
	size_t mapped = 16<<20;
	off_t offset = 0, size = 0;
	uint32_t hashlen = params->hashlen;
	ssize_t ret = 0;
	uint8_t *memblock = NULL;
	uint8_t *memblock_p;
	uint8_t md[64];

	if (filename) {
		do {
			ret = mmap_file(filename, &memblock, &size, &mapped,
					offset);
			if (ret) {
				fprintf(stderr,
					"Use of mmap failed mapping %zu bytes at offset %" PRId64 " of file %s (%zd)\n",
					mapped, (int64_t)offset, filename, ret);
				return (int)ret;
			}
			/* Compute hash */
			memblock_p = memblock;
			size_t left = mapped;
			do {
				uint32_t todo = (left > INT_MAX) ?
						 INT_MAX : (uint32_t)left;

				ret = kcapi_md_update(handle, memblock_p, todo);
				if (ret < 0) {
					munmap(memblock, mapped);
					return (int)ret;
				}
				left -= todo;
				memblock_p += todo;
			} while (left);
			munmap(memblock, mapped);
			offset = offset + (off_t)mapped;
		} while (offset ^ size);
	} else {
		uint8_t tmpbuf[TMPBUFLEN] __aligned(KCAPI_APP_ALIGN);
		uint32_t bufsize;

		while ((bufsize =
			(uint32_t)fread(tmpbuf, sizeof(uint8_t), TMPBUFLEN,
					stdin))) {

			ret = kcapi_md_update(handle, tmpbuf, bufsize);
			if (ret < 0)
				return (int)ret;
		}
		kcapi_memset_secure(tmpbuf, 0, sizeof(tmpbuf));
	}

	ret = kcapi_md_final(handle, md, sizeof(md));

	if (ret > 0) {
		if (hashlen > (uint32_t)ret) {
			fprintf(stderr, "Invalid truncated hash size: %lu > %zd\n",
			        (unsigned long)hashlen, ret);
			return (int)ret;
		}

		if (!hashlen)
			hashlen = (uint32_t)ret;

		if (comphash && comphashlen) {
			uint8_t compmd[64];

			memset(compmd, 0, sizeof(compmd));
			hex2bin(comphash, comphashlen, compmd, sizeof(compmd));
			if ((comphashlen != hashlen * 2) ||
			    memcmp(compmd, md, hashlen))
				ret = 1;
			else
				ret = 0;
		} else {
			if (outfile == NULL) { /* only print hash (hmaccalc -S) */
				bin2print(md, hashlen, NULL, stdout,
					  params->newline);
			} else if (params->bsd_style) {
				fprintf(outfile, "%s (%s) = ",
					params->name.bsdname,
					filename ? filename : "-");
				bin2print(md, hashlen, NULL, outfile,
					  params->newline);
			} else {
				bin2print(md, hashlen, filename ? filename : "-",
					  outfile, params->newline);
			}
			ret = 0;
		}
	} else {
		fprintf(stderr, "Generation of hash for file %s failed (%zd)\n",
			filename ? filename : "stdin", ret);
	}
	return (int)ret;
}

/*
 * GCC v8.1.0 introduced -Wstringop-truncation and GCC v8.2.0 introduced
 * -Wstringop-overflow but it is not smart enough to find that cursor string
 * will be NULL-terminated after all paste() calls and warns with:
 * error: 'strncpy' destination unchanged after copying no bytes [-Werror=stringop-truncation]
 * error: 'strncpy' output truncated before terminating nul copying 5 bytes from a string of the same length [-Werror=stringop-truncation]
 * error: 'strncpy' specified bound depends on the length of the source argument [-Werror=stringop-overflow=]
 */
#pragma GCC diagnostic push
#if GCC_VERSION >= 80100
#pragma GCC diagnostic ignored "-Wstringop-truncation"
#endif
#if GCC_VERSION >= 80200
#pragma GCC diagnostic ignored "-Wstringop-overflow"
#endif
static char *paste(char *dst, const char *src, size_t size)
{
	strncpy(dst, src, size);
	return dst + size;
}

/*
 * Convert a given file name into its respective HMAC file name
 *
 * return: NULL when malloc failed, a pointer that the caller must free
 * otherwise.
 */
static char *get_hmac_file(const char *filename, const char *checkdir)
{
	size_t i, filelen, pathlen, namelen, basenamestart = 0;
	const char *check_prefix = CHECK_PREFIX;
	size_t prefixlen = strlen(check_prefix);
	size_t suffixlen = strlen(CHECK_SUFFIX);
	char *cursor, *checkfile = NULL;

	if (prefixlen == 0 && checkdir == NULL) {
		check_prefix = ".";
		prefixlen = 1;
	}

	filelen = strlen(filename);
	if (filelen > 4096) {
		fprintf(stderr, "File too long\n");
		return NULL;
	}
	for (i = 0; i < filelen; i++) {
		if (!strncmp(filename + i, "/", 1))
			basenamestart = i + 1;
	}

	namelen = filelen - basenamestart;
	pathlen = checkdir ? strlen(checkdir) + 1 : basenamestart;

	checkfile = malloc(pathlen + namelen + prefixlen + 1 /* "." */ +
		suffixlen + 1 /* null character */);
	if (!checkfile)
		return NULL;

	cursor = checkfile;
	if (checkdir) {
		cursor = paste(cursor, checkdir, strlen(checkdir));
		cursor = paste(cursor, "/", 1);
	} else if (pathlen > 0)
		cursor = paste(cursor, filename, pathlen);

	cursor = paste(cursor, check_prefix, prefixlen);
	cursor = paste(cursor, filename + basenamestart, namelen);
	cursor = paste(cursor, "."CHECK_SUFFIX, 1 + suffixlen);
	strncpy(cursor, "\0", 1);
	return checkfile;
}
#pragma GCC diagnostic pop /* -Wstringop-truncation -Wstringop-overflow */

static int hash_files(const struct hash_params *params,
		      char *filenames[], uint32_t files,
		      int fipshmac, const char *checkdir, int just_print)
{
	struct kcapi_handle *handle;
	const char *hashname = params->name.kcapiname;
	uint32_t i = 0;
	int ret = 0;
	
	ret = kcapi_md_init(&handle, hashname, 0);
	if (ret) {
		fprintf(stderr, "Allocation of %s cipher failed (ret=%d)\n",
			hashname, ret);
		return -EFAULT;
	}
	if (params->key.data) {
		ret = kcapi_md_setkey(handle, params->key.data,
				      (uint32_t)params->key.len);
		if (ret) {
			fprintf(stderr, "Setting HMAC key for %s failed (%d)\n",
				hashname, ret);
			kcapi_md_destroy(handle);
			return -EINVAL;
		}
	}
	
	if (files) {
		for (i = 0; i < files; i++) {
			FILE *out = just_print ? NULL : stdout;
			const char *filename = filenames[i];

			if (fipshmac) {
				char *outfile = get_hmac_file(filenames[i], checkdir);
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
			} else if (strcmp(filename, "-") == 0) {
				filename = NULL;
			}
			ret = hasher(handle, params, filename, NULL, 0, out);
			if (fipshmac)
				fclose(out);
			if (ret)
				break;
		}
	} else {
		ret = hasher(handle, params, NULL, NULL, 0, stdout);
	}

	kcapi_md_destroy(handle);
	return ret;
}

#define CHK_QUIET (1)
#define CHK_STATUS (2)

static int process_checkfile(const struct hash_params *params,
			     const char *checkfile, const char *targetfile, int log)
{
	FILE *file = NULL;
	int ret = 0;
	int checked_any = 0;
	struct kcapi_handle *handle;
	const char *hashname = params->name.kcapiname;

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
	if (params->key.data) {
		ret = kcapi_md_setkey(handle, params->key.data,
				      (uint32_t)params->key.len);
		if (ret) {
			fprintf(stderr, "Setting HMAC key for %s failed (%d)\n",
				hashname, ret);
			ret = -EINVAL;
			goto out;
		}
	}

	file = strcmp(checkfile, "-") ? fopen(checkfile, "r") : stdin;
	if (!file) {
		fprintf(stderr, "Cannot open file %s\n", checkfile);
		ret = 253;
		goto out;
	}

	while (fgets(buf, sizeof(buf), file)) {
		char *filename = NULL;   // parsed file name
		char *hexhash = NULL;    // parsed hex value of hash
		uint32_t hexhashlen = 0; // length of hash hex value
		uint32_t linelen = (uint32_t)strlen(buf);
		uint32_t i;
		uint32_t bsd_style = 0; // >0 if --tag formatted style

		if (linelen == 0)
			break;

		/* remove trailing CR and reduce buffer length */
		for (i = linelen - 1; i > 0; i--) {
			if (!isprint(buf[i])) {
				buf[i] = '\0';
				linelen--;
			} else
				break;
		}

		for (i = 1; i < linelen; i++) {
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
				hexhashlen++;

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
			hexhashlen = linelen - bsd_style + 1;

			/* remove closing parenthesis behind filename */
			if (buf[(bsd_style - 4)] == ')')
				buf[(bsd_style - 4)] = '\0';
		}

		if (!hexhash || !hexhashlen) {
			fprintf(stderr, "Invalid checkfile format\n");
			ret = 1;
			goto out;
		}

		/* fipscheck does not have the filename in the check file */
		if (targetfile) {
			ret = hasher(handle, params, targetfile,
			             hexhash, hexhashlen, stdout);
			checked_any = 1;
			goto out;
		}

		if (filename) {
			int r;

			if (!bsd_style) {
				if (!isblank(filename[0]) ||
				    (!isblank(filename[1]) && filename[1] != '*')) {
					fprintf(stderr, "Invalid checkfile format\n");
					ret = 1;
					goto out;
				}
				filename += 2;
			}

			r = hasher(handle, params, filename, hexhash, hexhashlen, stdout);

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
			checked_any = 1;
		}
	}

out:
	if (file)
		fclose(file);
	kcapi_md_destroy(handle);

	/*
	 * If we found no lines to check, return an error.
	 * (See https://pagure.io/hmaccalc/c/1afb99549816192eb8e6bc8101bc417c2ffa764c)
	 */
	return ret != 0 ? ret : !checked_any;

}

/* self-check modes: */
#define SELFCHECK_CHECK		0
#define SELFCHECK_PRINT_SELF	1
#define SELFCHECK_PRINT_LIB	2

static int fipscheck_self(const struct hash_params *params_bin,
                          const struct hash_params *params_lib, int mode)
{
	char *checkfile = NULL;
	uint32_t n = 0;
	int ret = -EINVAL;
	char fipsflag[1];
#define BUFSIZE 4096
	char selfname[BUFSIZE];
	char *names[] = { selfname };
	ssize_t selfnamesize = 0;
	Dl_info info;
	void *dl = NULL, *sym;

#ifdef HAVE_SECURE_GETENV
	if (secure_getenv("KCAPI_HASHER_FORCE_FIPS") || mode != SELFCHECK_CHECK) {
#else
	if (getenv("KCAPI_HASHER_FORCE_FIPS") || mode != SELFCHECK_CHECK) {
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

		n = (uint32_t)fread((void *)fipsflag, 1, 1, fipsfile);
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
	if (mode == SELFCHECK_CHECK || mode == SELFCHECK_PRINT_SELF) {
		memset(selfname, 0, sizeof(selfname));
		selfnamesize = readlink("/proc/self/exe", selfname, BUFSIZE);
		if (selfnamesize >= BUFSIZE || selfnamesize < 0) {
			fprintf(stderr, "Cannot obtain my filename\n");
			ret = -EFAULT;
			goto out;
		}

		if (mode == SELFCHECK_PRINT_SELF) {
			ret = hash_files(params_bin, names, 1, 0, NULL, 1);
			goto out;
		}

		checkfile = get_hmac_file(selfname, params_bin->key.checkdir);
		if (!checkfile) {
			ret = -ENOMEM;
			goto out;
		}

		ret = process_checkfile(params_bin, checkfile, selfname, CHK_STATUS);
		if (ret)
			goto out;
	}

	/* Integrity check of shared libkcapi.so file. */
	if (mode == SELFCHECK_CHECK || mode == SELFCHECK_PRINT_LIB) {
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

		if (mode == SELFCHECK_PRINT_LIB) {
			ret = hash_files(params_lib, names, 1, 0, NULL, 1);
			goto out;
		}

		if (checkfile)
			free(checkfile);
		checkfile = get_hmac_file(selfname, params_lib->key.checkdir);
		if (!checkfile) {
			ret = -ENOMEM;
			goto out;
		}

		ret = process_checkfile(params_lib, checkfile, selfname, CHK_STATUS);
	}

out:
	if (checkfile)
		free(checkfile);
	if (dl)
		dlclose(dl);
	return ret;
}

int strtou32(const char *str, uint32_t *out)
{
	char *end;
	unsigned long value = strtoul(str, &end, 10);
	if (*str == '\0' || *end != '\0' || value > UINT32_MAX)
		return -EINVAL;
	*out = (uint32_t)value;
	return 0;
}

int main(int argc, char *argv[])
{
	const struct hash_name *names = NULL;
	struct hash_params params = {
		.name = { NULL, NULL },
		.key = { NULL, NULL, 0 },
		.hashlen = 0,
		.bsd_style = 0,
		.newline = 1,
	};
	const struct hash_params *params_self;
	char *basec = NULL;
	const char *basen = NULL;
	int ret = -EFAULT;
	/* File memory-mapping size limit set at 64MB in 32bit and 1GB in 64bit virtual memory space */
	size_t mapped = (sizeof(void*) == 4) ? 64<<20 : 1<<30;

	char *checkfile = NULL;
	const char *targetfile = NULL;
	const char *checkdir = NULL;
	uint8_t *hmackey_alloc = NULL;
	uint8_t *hmackey_mmap = NULL;
	int opt_index = 0;
	int loglevel = 0;
	int hmac = 0;
	int fipscheck = 0;
	int fipshmac = 0;
	int selfcheck_mode = SELFCHECK_CHECK;

	static const char *opts_name_short = "n:";
	static const struct option opts_name[] = {
		{"name", 1, 0, 'n'},
		{0, 0, 0, 0}
	};

	static const char *opts_short = "c:uh:t:SLqk:K:vbd:Pz";
	static const struct option opts[] = {
		{"help", 0, 0, 0},
		{"tag", 0, 0, 0},
		{"quiet", 0, 0, 0},
		{"check", 1, 0, 'c'},
		{"unkeyed", 0, 0, 'u'},
		{"hash", 1, 0, 'h'},
		{"truncate", 1, 0, 't'},
		{"self-sum", 0, 0, 'S'},
		{"self-sum-lib", 0, 0, 'L'},
		{"status", 0, 0, 'q'},
		{"key-file", 1, 0, 'k'},
		{"key", 1, 0, 'K'},
		{"version", 0, 0, 'v'},
		{0, 0, 0, 0}
	};

	/*
	 * Self-integrity check:
	 *	* fipscheck/fipshmac and sha*sum equivalents are using the
	 *	  fipscheck key and hmac(sha256)
	 *	* hmaccalc applications are using the hmaccalc key and
	 *	  hmac(sha512)
	 */
	const struct hash_params PARAMS_SELF_FIPSCHECK = {
		.name = NAMES_SHA256[1],
		.bsd_style = 0,
		.hashlen = 0,
		.key = KEY_FIPSCHECK,
		.newline = 1,
	};
	const struct hash_params PARAMS_SELF_HMACCALC = {
		.name = NAMES_SHA512[1],
		.bsd_style = 0,
		.hashlen = 0,
		.key = KEY_HMACCALC,
		.newline = 1,
	};

	basec = strdup(argv[0]);
	if (!basec) {
		fprintf(stderr, "Error copying file name: %s\n",
			strerror(errno));
		return 255;
	}
	basen = basename(basec);

	opterr = 0;
	if (getopt_long(argc, argv, opts_name_short, opts_name, &opt_index) == 'n')
		basen = optarg;
	else
		optind = 1;
	opterr = 1;

	params_self = &PARAMS_SELF_FIPSCHECK;
	if (0 == strncmp(basen, "kcapi-hasher", 12)) {
		// called directly, hash must be set with -h
	} else if (0 == strncmp(basen, "sha256sum", 9)) {
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
	} else if (0 == strncmp(basen, "sm3sum", 6)) {
		names = NAMES_SM3;
	} else if (0 == strncmp(basen, "sha3sum", 7)) {
		names = NAMES_SHA3_224;
	} else if (0 == strncmp(basen, "fipshmac", 8)) {
		names = NAMES_SHA256;
		hmac = 1;
		params.key = KEY_FIPSCHECK;
		fipshmac = 1;
	} else if (0 == strncmp(basen, "fipscheck", 9)) {
		names = NAMES_SHA256;
		hmac = 1;
		params.key = KEY_FIPSCHECK;
		fipscheck = 1;
	} else if (0 == strncmp(basen, "sha1hmac", 8)) {
		names = NAMES_SHA1;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else if (0 == strncmp(basen, "sha224hmac", 10)) {
		names = NAMES_SHA224;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else if (0 == strncmp(basen, "sha256hmac", 10)) {
		names = NAMES_SHA256;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else if (0 == strncmp(basen, "sha384hmac", 10)) {
		names = NAMES_SHA384;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else if (0 == strncmp(basen, "sha512hmac", 10)) {
		names = NAMES_SHA512;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else if (0 == strncmp(basen, "sm3hmac", 7)) {
		names = NAMES_SM3;
		hmac = 1;
		params.key = KEY_HMACCALC;
		params_self = &PARAMS_SELF_HMACCALC;
	} else {
		fprintf(stderr, "Unknown invocation name: %s\n", basen);
		usage(argv[0], fipscheck);
		ret = 1;
		goto out;
	}

	while (1) {
		int c = getopt_long(argc, argv, opts_short, opts, &opt_index);
		
		if (-1 == c)
			break;
		switch (c) {
			case 0:
				switch (opt_index) {
				case 0:
					usage(argv[0], fipscheck);
					ret = 0;
					goto out;
				case 1:
					params.bsd_style = 1;
					break;
				case 2:
					loglevel = CHK_QUIET;
					break;
				}
				break;
			case 'c':
				if (checkfile)
					free(checkfile);
				checkfile = strdup(optarg);
				if (!checkfile) {
					fprintf(stderr, "Error copying file name: %s\n",
					        strerror(errno));
					ret = 1;
					goto out;
				}
				break;
			case 'u':
				if (hmackey_alloc) {
					kcapi_memset_secure(hmackey_alloc, 0,
						(uint32_t)params.key.len);
					free(hmackey_alloc);
					hmackey_alloc = NULL;
				} else if (hmackey_mmap) {
					munmap(hmackey_mmap,
					       (size_t)params.key.len);
					hmackey_mmap = NULL;
				}
				params.key.data = NULL;
				params.key.len = 0;
				hmac = 0;
				break;
			case 'h':
				if (0 == strcmp(optarg, "sha1"))
					names = NAMES_SHA1;
				else if (0 == strcmp(optarg, "sha224"))
					names = NAMES_SHA224;
				else if (0 == strcmp(optarg, "sha256"))
					names = NAMES_SHA256;
				else if (0 == strcmp(optarg, "sha384"))
					names = NAMES_SHA384;
				else if (0 == strcmp(optarg, "sha512"))
					names = NAMES_SHA512;
				else if (0 == strcmp(optarg, "sm3"))
					names = NAMES_SM3;
				else if (0 == strcmp(optarg, "sha3-224"))
					names = NAMES_SHA3_224;
				else if (0 == strcmp(optarg, "sha3-256"))
					names = NAMES_SHA3_256;
				else if (0 == strcmp(optarg, "sha3-384"))
					names = NAMES_SHA3_384;
				else if (0 == strcmp(optarg, "sha3-512"))
					names = NAMES_SHA3_512;
				else {
					fprintf(stderr, "Invalid hash: %s\n", optarg);
					ret = 1;
					goto out;
				}
				break;
			case 't':
				if (strtou32(optarg, &params.hashlen)) {
					fprintf(stderr, "Invalid number: %s\n", optarg);
					ret = 1;
					goto out;
				}
				if (params.hashlen % 8 != 0) {
					fprintf(stderr, "Truncated hash size must be "
					                "a multiple of 8 bits!\n");
					ret = 1;
					goto out;
				}
				params.hashlen /= 8;
				break;
			case 'S':
				selfcheck_mode = SELFCHECK_PRINT_SELF;
				break;
			case 'L':
				selfcheck_mode = SELFCHECK_PRINT_LIB;
				break;
			case 'q':
				loglevel = CHK_STATUS;
				break;
			case 'k':
				if (hmackey_alloc) {
					kcapi_memset_secure(hmackey_alloc, 0,
						(uint32_t)params.key.len);
					free(hmackey_alloc);
					hmackey_alloc = NULL;
				} else if (hmackey_mmap) {
					munmap(hmackey_mmap,
					       (size_t)params.key.len);
					hmackey_mmap = NULL;
				}
				params.key.len = 0;
				ret = mmap_file(optarg, &hmackey_mmap,
						&params.key.len,
						&mapped, 0);
				if (!ret) {
					params.key.data = hmackey_mmap;
					hmac = 1;
					break;
				}
				/* fallback to normal file I/O: */
				ret = load_file(optarg, &hmackey_alloc,
						&params.key.len);
				if (ret) {
					ret = 1;
					goto out;
				}
				params.key.data = hmackey_alloc;
				hmac = 1;
				break;
			case 'K':
				if (hmackey_alloc) {
					kcapi_memset_secure(hmackey_alloc, 0,
						(uint32_t)params.key.len);
					free(hmackey_alloc);
					hmackey_alloc = NULL;
				} else if (hmackey_mmap) {
					munmap(hmackey_mmap,
					       (size_t)params.key.len);
					hmackey_mmap = NULL;
				}
				hmackey_alloc = (uint8_t *)strdup(optarg);
				if (!hmackey_alloc) {
					fprintf(stderr, "Cannot allocate memory for HMAC key\n");
					ret = 1;
					goto out;
				}
				params.key.data = hmackey_alloc;
				params.key.len = (off_t)strlen(optarg);
				hmac = 1;
				break;
			case 'v':
				version(argv[0]);
				ret = 0;
				goto out;
			case 'd':
				checkdir = optarg;
				break;
			case 'b':
			case 'P':
				/* Compatibility options, just ignore */
				break;
			case 'z':
				params.newline = 2;
				break;
			default:
				usage(argv[0], fipscheck);
				ret = 1;
				goto out;
		}
	}

	if (!names) {
		fprintf(stderr, "Unknown invocation: hash nor name are set.\n");
		usage(argv[0], fipscheck);
		ret = 1;
		goto out;
	}

	if (0 == strncmp(names[0].kcapiname, "sha3-", 5) && hmac) {
		fprintf(stderr, "KMAC is not defined\n");
		ret = 1;
		goto out;
	}

	if (selfcheck_mode != SELFCHECK_CHECK) {
		if (checkfile) {
			fprintf(stderr, "-S/-L and -c cannot be combined\n");
			ret = 1;
			goto out;
		}
		if (optind != argc) {
			fprintf(stderr, "-S/-L cannot be used with input files\n");
			ret = 1;
			goto out;
		}
	}

	/* library self-check must be consistent across apps: */
	if (fipscheck_self(params_self, &PARAMS_SELF_FIPSCHECK, selfcheck_mode)) {
		fprintf(stderr, "Integrity check of application %s failed\n",
			basen);
		ret = 1;
		goto out;
	}

	if (selfcheck_mode != SELFCHECK_CHECK) {
		ret = 0;
		goto out;
	}

	params.name = names[hmac];

	if (fipscheck) {
		if (optind >= argc) {
			fprintf(stderr, "No file to check given for fipscheck\n");
			ret = 1;
			goto out;
		}
		if (checkfile) {
			fprintf(stderr, "-c is not valid for fipscheck\n");
			ret = 1;
			goto out;
		}

		targetfile = argv[optind];
		if (checkfile)
			free(checkfile);
		checkfile = get_hmac_file(targetfile, params.key.checkdir);
		if (!checkfile) {
			ret = 1;
			goto out;
		}
		optind++;
	}

	if (!checkfile)
		ret = hash_files(&params, argv + optind,
				 (uint32_t)(argc - optind),
		                 fipshmac, checkdir, 0);
	else if (optind == argc)
		ret = process_checkfile(&params, checkfile, targetfile, loglevel);
	else {
		fprintf(stderr, "-c cannot be used with input files\n");
		ret = 1;
	}


out:
	if (basec)
		free(basec);
	if (checkfile)
		free(checkfile);
	if (hmackey_alloc) {
		kcapi_memset_secure(hmackey_alloc, 0, (uint32_t)params.key.len);
		free(hmackey_alloc);
	} else if (hmackey_mmap) {
		munmap(hmackey_mmap, (size_t)params.key.len);
	}

	return ret;
}
