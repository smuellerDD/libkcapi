/*
 * Copyright (C) 2015 - 2021, Stephan Mueller <smueller@chronox.de>
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

#include "cryptoperf.h"

/**
 * Execute one particular test and record the timing information
 * @test: test case definition
 *
 * result: 0 on success, error otherwise
 */
int cp_exec_test(struct cp_test *test)
{
	uint64_t testduration = 0;
	uint64_t nano = 1;
	unsigned int i = 0;
	struct cp_test_param *params = test->test_params;

	nano = nano << 32;

	testduration = nano * test->exectime;

	if (params->exectime)
		testduration = nano * params->exectime;

	if (test->init_test) {
		int ret = test->init_test(test);
		if (ret) {
			printf(DRIVER_NAME": initialization for %s failed\n",
			       test->testname);
			return ret;
		}
	}

	dbg("Starting test %s for %lu seconds\n", test->testname,
	    (unsigned long)(testduration / nano));
	test->results.totaltime = 0;
	test->results.rounds = 0;
	test->results.byteperop = test->exec_test(test);
	if (params->aio)
		test->results.byteperop *= params->aio;

	/* prime the test */
	for (i = 0; i < 10; i++)
		test->results.chunksize = test->exec_test(test);

	while (test->results.totaltime < testduration) {
		struct timespec start;
		struct timespec end;

		cp_get_nstime(&start);
		test->results.chunksize = test->exec_test(test);
		cp_get_nstime(&end);
		test->results.totaltime +=
			(cp_ts2u64(&end) - cp_ts2u64(&start));
		test->results.rounds++;
	}
	dbg("Finished test %s for %lu ns with %lu rounds\n", test->testname,
	    (unsigned long)test->results.totaltime,
	    (unsigned long)test->results.rounds);

	if (test->fini_test)
		test->fini_test(test);

	dbg("Finished test %s\n", test->testname);

	return 0;
}

/*
 * Convert an integer value into a string value that displays the integer
 * in either bytes, kB, or MB
 *
 * @bytes value to convert -- input
 * @str already allocated buffer for converted string -- output
 * @strlen size of str
 */
static void cp_bytes2string(uint64_t bytes, char *str, size_t strlen)
{
	if (1UL<<30 < bytes) {
		uint64_t abs = (bytes>>30);
		uint64_t part = ((bytes - (abs<<30)) / (10000000));
		snprintf(str, strlen, "%lu.%lu GB", (unsigned long)abs,
			 (unsigned long)part);
		return;

	} else if (1UL<<20 < bytes) {
		uint64_t abs = (bytes>>20);
		uint64_t part = ((bytes - (abs<<20)) / (10000));
		snprintf(str, strlen, "%lu.%lu MB", (unsigned long)abs,
			 (unsigned long)part);
		return;
	} else if (1UL<<10 < bytes) {
		uint64_t abs = (bytes>>10);
		uint64_t part = ((bytes - (abs<<10)) / (10));
		snprintf(str, strlen, "%lu.%lu kB", (unsigned long)abs,
			 (unsigned long)part);
		return;
	}
	snprintf(str, strlen, "%lu B", (unsigned long)bytes);
	str[strlen] = '\0';
}

/*
 * Format the test results nicely
 *
 * This function should be called after a test execution to present
 * the test results properly formatted
 *
 * @test test definition
 *
 * result: pointer to newly allocated character string with formatted output.
 *	   The caller must free that pointer.
 */
char *cp_print_status(struct cp_test *test, int raw)
{
	char *str = NULL;
	uint64_t processed_bytes = test->results.rounds * test->results.byteperop;
	uint64_t totaltime = test->results.totaltime>>32;
	uint64_t ops = 0;

	str = calloc(1, 121);
	if (!str)
		return str;

	if (!totaltime) {
		snprintf(str, 120, "%-35s | untested\n", test->testname);
		return str;
	}

	ops = test->results.rounds / totaltime;

	if (raw) {
		snprintf(str, 120, "%s,%s,%lu,%lu,%lu",
			 test->testname,
			test->enc ? "e" : "d",
			(unsigned long)test->results.chunksize,
			(unsigned long)(processed_bytes/totaltime),
			(unsigned long)ops);
	} else {
		#define VALLEN 23
		char byteseconds[VALLEN + 1];

		memset(byteseconds, 0, sizeof(byteseconds));
		cp_bytes2string((processed_bytes / totaltime), byteseconds,
				VALLEN);
		snprintf(str, 120, "%-24s|%s|%8lu bytes|%*s/s|%lu ops/s",
			test->testname,
			test->enc ? "e" : "d",
			(unsigned long)test->results.chunksize,
			VALLEN,
			byteseconds,
			(unsigned long)ops);
	}

	return str;
}

int cp_read_random(unsigned char *buf, size_t buflen)
{
	int fd = 0;
	ssize_t ret = 0;
	size_t len = 0;

	fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC);
	if(0 > fd)
		return fd;
	do {
		ret = read(fd, (buf + len), (buflen - len));
		if(0 < ret)
			len += (size_t)ret;
	} while ((0 < ret || EINTR == errno || ERESTART == errno)
		 && buflen > len);

	close(fd);

	if(buflen == len)
		return SUCCESS;
	else
		return FAILURE;
}
