#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <kcapi.h>

void pt(unsigned char *md, unsigned int len)
{
	unsigned int i;

	for (i = 0; i < len; i++)
		printf("%02x",md[i]);
	printf("\n");
}

int main( int argc, char **argv )
{
	int fd;
	int ret = 0;
	struct stat sb;
	const char* memblock;
	struct kcapi_handle handle;
	unsigned char md[64];

	if (argc != 3) {
		printf("argc failed\n");
		return -1;
	}

	ret = kcapi_md_init(&handle, argv[1]);
	if (ret) {
		printf("Allocation of sha1 cipher failed (ret=%d)\n", ret);
		return 1;
#if 0
	} else {
		int ds = kcapi_md_digestsize(&handle);
		printf("Digest Size=%d\n", ds);
#endif
	}

	/* mmap file */
	fd = open(argv[2], O_RDONLY);
	fstat(fd, &sb);
	/* printf("Size: %lu\n", (uint64_t)sb.st_size); */
	memblock = mmap(NULL, sb.st_size, PROT_READ, MAP_SHARED, fd, 0);

	if (memblock == MAP_FAILED)
	{
		perror("mmap");
		exit(EXIT_FAILURE);
	}

	/* Compute hash */
	memset(md, 0, sizeof(md));
	ret = kcapi_md_digest(&handle, (unsigned char*) memblock, sb.st_size, md, sizeof(md));
	/* printf("Size of message digest computed=%d\n", ret);*/
	pt(md, ret);

	/* Clean up */
	kcapi_md_destroy(&handle);

	return ret;
}

/* colorgcc -Wall -lkcapi -o kcapitest kcapi-oneshot.c */
