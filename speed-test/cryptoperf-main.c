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

struct test_array {
	struct cp_test *array;
	size_t entries;
};

struct test_array hash_tests;
struct test_array skcipher_tests;
struct test_array rng_tests;

static void register_tests(void)
{
	cp_hash_register(&hash_tests.array, &hash_tests.entries);
	cp_skcipher_register(&skcipher_tests.array, &skcipher_tests.entries);
	cp_rng_register(&rng_tests.array, &rng_tests.entries);
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

static int find_test(const char *name, struct test_array *tests,
		     struct cp_test **test)
{
	size_t i = 0;

	for (i = 0; i < tests->entries; i++) {
		if (!strncmp(tests->array[i].driver_name, name, strlen(name))) {
			*test = &tests->array[i];
			return 0;
		}
	}
	return -EFAULT;
}

static int exec_one_test(const char *name, unsigned int exectime, size_t len)
{
	struct cp_test *test = NULL;
	char *out = NULL;

	if (find_test(name, &hash_tests, &test))
		if (find_test(name, &skcipher_tests, &test))
			if (find_test(name, &rng_tests, &test))
				return -EINVAL;

	if (cp_exec_test(test, exectime, len))
		return -EFAULT;
	out = cp_print_status(test);
	if (!out)
		return -ENOMEM;
	printf("%s\n", out);
	free(out);

	return 0;
}


int main(int argc, char *argv[])
{
	register_tests();
	if (argc == 1)
		return exec_all_tests(&hash_tests, 0, 1);
	else if (argc == 2)
		return exec_one_test(argv[1], 0, 1);
	else if (argc == 3)
		return exec_one_test(argv[1], 0, atoi(argv[2]));
	else
		return -1;
}
