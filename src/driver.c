#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "cache.h"

uint32_t convert(char *s) {

	char *endptr;

	errno = 0;

	uint32_t num = strtol(s, &endptr, 10);
	if (errno == ERANGE) {
		fprintf(stderr, "convert(): assoc:%s overflow occurred\n", s);
		usage();
		exit(EXIT_FAILURE);
	}
	if(*endptr != '\0') {
		fprintf(stderr, "convert(): assoc:%s is not a number\n", s);
		usage();
		exit(EXIT_FAILURE);
	}

	return num;
}

int main(int argc, char *argv[]) {

	if((argc-1) != 8) {
		fprintf(stderr, "main(): incorrect number of inputs");
		usage();
		exit(EXIT_FAILURE);
	}


	uint32_t size = 2;

	cache_ **L = malloc(size*sizeof(cache_ *));

	uint32_t cache_size;
	uint32_t block_size = convert(argv[4]);

	for(uint32_t i = 0; i < size; ++i) {

		uint32_t indx = 1+(i*4);

		cache_size = convert(argv[indx]);
		// TODO change back block_size = convert(argv[indx+3]);

		L[i] = cache_init(cache_size, block_size, argv[indx+1], argv[indx+2]);
	}


	simulator(L, size, argv[argc-1]);


	for (uint32_t i = 0; i < size; ++i) {
		cache_destroy(L[i]);
	}
	free(L);

	return EXIT_SUCCESS;
}