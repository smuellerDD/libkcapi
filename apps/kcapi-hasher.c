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

#include <kcapi.h>

static void usage(char *hashname)
{
	fprintf(stderr, "\n%ssum - calculation of hash sum (Using Linux Kernel Crypto API)\n", hashname);
	fprintf(stderr, "\nUsage:\n");
	fprintf(stderr, "\t%ssum [OPTION] ... [FILE] ...\n", hashname);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "\t-c --check\tVerify hash sums from file\n");
	fprintf(stderr, "\t-q --quiet\tDo not print out verification result for every file\n");
	fprintf(stderr, "\t-s --status\tResult of verification given with return code\n");
	fprintf(stderr, "\t-v --version\tShow version\n");
}

static void version(char *hashname)
{
	char version[20];

	memset(version, 0, 20);
	kcapi_versionstring(version, 20);
	
	fprintf(stderr, "%ssum: %s\n", hashname, version);
}

static char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(unsigned int bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

static void bin2hex(const unsigned char *bin, size_t binlen,
		    char *hex, size_t hexlen, int u)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

static int bin_char(unsigned char hex)
{
	if (48 <= hex && 57 >= hex)
		return (hex - 48);
	if (65 <= hex && 70 >= hex)
		return (hex - 55);
	if (97 <= hex && 102 >= hex)
		return (hex - 87);
	return 0;
}

static void hex2bin(const char *hex, size_t hexlen,
		    unsigned char *bin, size_t binlen)
{
	size_t i = 0;
	size_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		bin[i] = bin_char(hex[(i*2)]) << 4;
		bin[i] |= bin_char(hex[((i*2)+1)]);
	}
}

static void bin2print(const unsigned char *bin, size_t binlen,
		      const char *filename)
{
	char *hex;
	size_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	fprintf(stdout, "%s  %s\n", hex, filename);
	free(hex);
}

static int hasher(struct kcapi_handle *handle, char *filename,
		  const char *comphash, unsigned int comphashlen)
{	
	int fd;
	int ret = 0;
	struct stat sb;
	char *memblock = NULL;
	unsigned char md[64];

	fd = open(filename, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "Cannot open file %s: %s\n", filename,
			strerror(errno));
		return -3;
	}
	
	fstat(fd, &sb);
	memblock = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (memblock == MAP_FAILED)
	{
		fprintf(stderr, "Use of mmap failed\n");
		ret = -4;
		goto out;
	}

	/* Compute hash */
	ret = kcapi_md_digest(handle, (unsigned char*)memblock, sb.st_size, md,
			      sizeof(md));
	if (ret > 0) {
		if (comphash && comphashlen) {
			unsigned char compmd[64];
			memset(compmd, 0, sizeof(compmd));
			hex2bin(comphash, comphashlen, compmd, sizeof(compmd));
			if ((comphashlen != (unsigned int)(ret * 2)) ||
			    memcmp(compmd, md, ret)) {

				ret = 1;
			} else {

				ret = 0;
			}

		} else {
			bin2print(md, ret, filename);
			ret = 0;
		}
	} else {
		fprintf(stderr, "Generation of hash for file %s failed (%d)\n",
			filename, ret);
	}

	/* Clean up */
out:
	if (memblock)
		munmap(memblock, sb.st_size);
	if (fd >= 0)
		close(fd);

	return ret;
}

static int hash_files(char *hashname, char *filename[], unsigned int files)
{
	struct kcapi_handle handle;
	unsigned int i = 0;
	int ret = 0;
	
	ret = kcapi_md_init(&handle, hashname, 0);
	if (ret) {
		fprintf(stderr, "Allocation of %s cipher failed (ret=%d)\n",
			hashname, ret);
		return -2;
	}
	
	for (i = 0; i < files; i++) {
		ret = hasher(&handle, filename[i], NULL, 0);
		if (ret)
			break;
	}

	kcapi_md_destroy(&handle);
	return ret;
}

#define CHK_QUIET (1)
#define CHK_STATUS (2)

static int process_checkfile(char *hashname, char *checkfile, int log)
{
	FILE *file = NULL;
	int ret = 0;
	struct kcapi_handle handle;
	char buf[(4096 + 64 + 2)];

	ret = kcapi_md_init(&handle, hashname, 0);
	if (ret) {
		fprintf(stderr, "Allocation of %s cipher failed (ret=%d)\n",
			hashname, ret);
		return -2;
	}

	file = fopen(checkfile, "r");
	if (!file) {
		fprintf(stderr, "Cannot open file %s\n", checkfile);
		ret = 253;
		goto out;
	}

	while (fgets(buf, sizeof(buf), file)) {
		int foundsep = 0;
		unsigned int hashlen = 0;
		size_t linelen = strlen(buf);
		size_t i;

		/* remove trailing CR */
		for (i = linelen; i > 0; i--) {
			if (!isalpha(buf[i]))
				buf[i] = 0;
			else
				break;
		}

		for (i = 0; i < linelen; i++) {
			if (isblank(buf[i])) {
				foundsep = 1;
				continue;
			}

			if (!foundsep) {
				hashlen++;
			} else {
				char *filename = buf + i;
				int r = hasher(&handle, filename, buf, hashlen);

				if (r == 0) {
					if (log < CHK_QUIET)
						printf("%s: OK\n", filename);
				} else if (r == 1) {
					if (log < CHK_STATUS)
						printf("%s: Not OK\n",
						       filename);
					ret++;
				} else
					goto out;
				break;
			}
		}
	}

out:
	if (file)
		fclose(file);
	kcapi_md_destroy(&handle);
	return ret;

}

int main(int argc, char *argv[])
{
	char *basec = NULL;
        char *basen = NULL;
#define HASHNAMESIZE 6
	char hash[(HASHNAMESIZE + 1)];
	int ret = 255;

	char *checkfile = NULL;
	int loglevel = 0;
	
	static struct option opts[] =
	{
		{"check", 1, 0, 'c'},
		{"quiet", 0, 0, 'q'},
		{"status", 0, 0, 's'},
		{"version", 0, 0, 'v'},
		{0, 0, 0, 0}
	};

	basec = strdup(argv[0]);
	if (!basec) {
		fprintf(stderr, "Error copying file name: %s\n",
			strerror(errno));
		return 255;
	}
	basen = basename(basec);
	
	memset(hash, 0, sizeof(hash));
	if (0 == strncmp(basen, "sha256sum", 9))
		strncpy(hash, "sha256", HASHNAMESIZE);
	else if (0 == strncmp(basen, "sha512sum", 9))
		strncpy(hash, "sha512", HASHNAMESIZE);
	else if (0 == strncmp(basen, "sha1sum", 7))
		strncpy(hash, "sha1", HASHNAMESIZE);
	else if (0 == strncmp(basen, "sha224sum", 9))
		strncpy(hash, "sha224", HASHNAMESIZE);
	else if (0 == strncmp(basen, "sha384sum", 9))
		strncpy(hash, "sha384", HASHNAMESIZE);
	else if (0 == strncmp(basen, "md5sum", 6))
		strncpy(hash, "md5", HASHNAMESIZE);
	else {
		fprintf(stderr, "Unknown invocation name: %s\n", basen);
		goto out;
	}
	
	while (1) {
		int opt_index = 0;
		int c = getopt_long(argc, argv, "c:qsv", opts, &opt_index);
		
		if (-1 == c)
			break;
		switch (c) {
			case 'v':
				version(hash);
				return 0;
			case 'c':
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
			default:
				usage(hash);
				goto out;
		}
	}
	
	if (checkfile) {
		ret = process_checkfile(hash, checkfile, loglevel);
		if (ret)
			goto out;
	}

	if (optind < argc)
		ret = hash_files(hash, argv + optind, (argc - optind));

out:
	if (basec)
		free(basec);
	if (checkfile)
		free(checkfile);
	
	return ret;
}
