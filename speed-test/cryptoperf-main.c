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

#include <stdio.h>
#include <string.h>
#include "cryptoperf.h"

#define MAXNAMELEN 30
struct test_array {
	struct cp_test *array;
	size_t entries;
};

struct test_array tests[4];

static void print_tests(struct test_array *tests)
{
	size_t i = 0;

	for (i = 0; i < tests->entries; i++) {
		printf("%-9s | %-35s | %s | %s\n", tests->array[i].type,
		       tests->array[i].testname,
		       tests->array[i].driver_name,
		       tests->array[i].enc ? "e" : "d");
	}
}

static void register_tests(void)
{
	cp_hash_register(&tests[0].array, &tests[0].entries);
	print_tests(&tests[0]);

	cp_skcipher_register(&tests[1].array, &tests[1].entries);
	print_tests(&tests[1]);

	cp_rng_register(&tests[2].array, &tests[2].entries);
	print_tests(&tests[2]);

	cp_aead_register(&tests[3].array, &tests[3].entries);
	print_tests(&tests[3]);
}

static int exec_all_tests(struct test_array *tests, unsigned int exectime,
			  size_t len)
{
	size_t i = 0;
	char *out = NULL;

	for (i = 0; i < tests->entries; i++) {
		if (cp_exec_test(&tests->array[i], exectime, len))
			return -EFAULT;
		out = cp_print_status(&tests->array[i]);
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

static int exec_subset_test(const char *name, unsigned int exectime, size_t len)
{
	struct cp_test *test = NULL;
	int i = 0;

	for (i = 0; i < 4; i++) {
		int ret = 0;
		char *out = NULL;
		while (1) {
			ret = find_test(name, &tests[i], ret, &test);
			if (ret < 0)
				break;
			ret++;
			if (cp_exec_test(test, exectime, len))
				return -EFAULT;
			out = cp_print_status(test);
			if (!out)
				return -ENOMEM;
			printf("%s\n", out);
			free(out);
		}
	}

	return 0;
}

int main(int argc, char *argv[])
{
	register_tests();
	if (argc == 1)
		return exec_all_tests(&tests[0], 0, 1);
	else if (argc == 2)
		return exec_subset_test(argv[1], 0, 1);
	else if (argc == 3)
		return exec_subset_test(argv[1], 0, atoi(argv[2]));
	else
		return -1;
}
