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

#include <getopt.h>
#include "cryptoperf.h"

#define MAXNAMELEN 30
struct test_array {
	struct cp_test *array;
	size_t entries;
};

struct test_array tests[4];

static void print_tests(struct test_array *tests, int print)
{
	size_t i = 0;

	if (!print)
		return;

	for (i = 0; i < tests->entries; i++) {
		printf("%-9s | %-35s | %s | %s\n", tests->array[i].type,
		       tests->array[i].testname,
		       tests->array[i].driver_name,
		       tests->array[i].enc ? "e" : "d");
	}
}

static void register_tests(int print)
{
	cp_hash_register(&tests[0].array, &tests[0].entries);
	print_tests(&tests[0], print);

	cp_skcipher_register(&tests[1].array, &tests[1].entries);
	print_tests(&tests[1], print);

	cp_rng_register(&tests[2].array, &tests[2].entries);
	print_tests(&tests[2], print);

	cp_aead_register(&tests[3].array, &tests[3].entries);
	print_tests(&tests[3], print);
}

static int exec_all_tests(struct test_array *tests, unsigned int exectime,
			  size_t len)
{
	size_t i;

	for (i = 0; i < tests->entries; i++) {
		char *out = NULL;

		if (cp_exec_test(&tests->array[i], exectime, len))
			return -EFAULT;
		out = cp_print_status(&tests->array[i], 0);
		if (!out)
			return -ENOMEM;
		printf("%s\n", out);
		free(out);
	}

	return 0;
}

static int find_test(const char *name, struct test_array *tests, int start,
		     struct cp_test **test)
{
	int i = start;

	if (i < 0)
		i = 0;

	for (; (unsigned int)i < tests->entries; i++) {
		if (!strncmp(tests->array[i].driver_name, name, strlen(name)) ||
		    !strncmp(tests->array[i].testname, name, strlen(name)) ||
		    !strncmp(tests->array[i].type, name, strlen(name))) {
			*test = &tests->array[i];
			return i;
		}
	}
	return -EFAULT;
}

static int exec_subset_test(const char *name, unsigned int exectime, size_t len,
			    int raw, int access)
{
	struct cp_test *test = NULL;
	int i = 0;

	for (i = 0; i < 4; i++) {
		int ret = 0;

		while (1) {
			char *out = NULL;

			ret = find_test(name, &tests[i], ret, &test);
			if (ret < 0)
				break;
			ret++;
			test->accesstype = access;
			if (cp_exec_test(test, exectime, len))
				return -EFAULT;
			out = cp_print_status(test, raw);
			if (!out)
				return -ENOMEM;
			printf("%s\n", out);
			free(out);
		}
	}

	return 0;
}

static void usage(void)
{
	char version[20];
	unsigned int ver = kcapi_version();

	memset(version, 0, 20);
	kcapi_versionstring(version, 20);

	fprintf(stderr, "\nAF_ALG Kernel Crypto API Speed Test\n");
	fprintf(stderr, "\nKernel Crypto API interface library version: %s\n", version);
	fprintf(stderr, "Reported numeric version number %u\n\n", ver);
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\t-a --all\tExecute all ciphers\n");
	fprintf(stderr, "\t-l --list\tList available ciphers\n");
	fprintf(stderr, "\t-c --cipher\tCipher/cipher type to test\n");
	fprintf(stderr, "\t-t --time\tExecution time in seconds\n");
	fprintf(stderr, "\t-b --blocks\tNumber of blocks to process\n");
	fprintf(stderr, "\t-r --raw\tPrint out raw numbers for postprocessing\n");
	fprintf(stderr, "\t-v --vmsplice\tUse vmsplice kernel interface\n");
	fprintf(stderr, "\t-s --sendmsg\tUse sendmsg kernel interface\n");
}

int main(int argc, char *argv[])
{
	int c = 0;
	unsigned int exectime = 0;
	unsigned long blocks = 1;
	char *cipher = NULL;
	int raw = 0;
	int ret = 1;
	int i = 0;
	int accesstype = KCAPI_ACCESS_HEURISTIC;

	register_tests(0);

	while(1)
	{
		int opt_index = 0;
		static struct option opts[] =
		{
			{"all", 0, 0, 'a'},
			{"list", 0, 0, 'l'},
			{"cipher", 1, 0, 'c'},
			{"time", 1, 0, 't'},
			{"blocks", 1, 0, 'b'},
			{"raw", 1, 0, 'r'},
			{"sendmsg", 0, 0, 's'},
			{"vmsplice", 0, 0, 'v'},
			{0, 0, 0, 0}
		};
		c = getopt_long(argc, argv, "alc:t:b:rsv", opts, &opt_index);
		if(-1 == c)
			break;
		switch(c)
		{
			case 'a':
				for (i = 0; i < 4; i++)
					exec_all_tests(&tests[i], 0, 1);
				return 0;
			case 'l':
				for (i = 0; i < 4; i++)
					print_tests(&tests[i], 1);
				return 0;
			case 'c':
				cipher = strndup(optarg, 50);
				break;
			case 't':
				exectime = (unsigned int)atoi(optarg);
				break;
			case 'b':
				blocks = (unsigned int)atoi(optarg);
				break;
			case 'r':
				raw = 1;
				break;
			case 'v':
				accesstype = KCAPI_ACCESS_VMSPLICE;
				break;
			case 's':
				accesstype = KCAPI_ACCESS_SENDMSG;
				break;

			default:
				usage();
				goto out;
		}
	}

	if (!cipher) {
		usage();
		goto out;
	}

	ret = exec_subset_test(cipher, exectime, blocks, raw, accesstype);

out:
	if (cipher)
		free(cipher);
	return ret;
}
