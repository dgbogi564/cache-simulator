#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <math.h>

#include "cache.h"

#ifdef CACHE_DEBUG
#define CACHE_DEBUG 1
#else
#define CACHE_DEBUG 0
#endif

#if !defined(DISABLE_PRINT) || defined(CACHE_DEBUG)
#define err(format, ...) {\
	fprintf(stderr, format, ##__VA_ARGS__);\
	usage();\
	exit(EXIT_FAILURE);\
}
#else
#define err(str)
#endif

uint64_t tick_count = 0;

uint32_t hierarchy = 0;



/* ========================== STRUCTURES ============================ */


/* Replacement Policy */
typedef enum replacement_policy {
	fifo = 0,
	lru = 1
} replacement_policy;

/* Block */
typedef struct block_ {
	uint8_t  valid;                         /* valid bit                            */
	uint32_t count;                         /* tick count at the time of insertion  */
	uint64_t set_index;                     /* set index of block in cache          */
	uint64_t tag;                           /* the unique block identifier          */
	uint64_t data;                          /* data stored in block                 */
	#if CACHE_DEBUG
		uint64_t orig_address;		/* original address parsed to the block */
	#endif
} block_;

/* Cache */
typedef struct cache_ {
	uint32_t sets;                          /* # of sets in the cache               */
	uint32_t ways;                          /* # of blocks in each set              */
	uint32_t set_bits;                      /* # of set bits in a trace address     */
	uint32_t offset_bits;                   /* # of offset bits in a trace address  */
	uint32_t hit;                           /* # of cache misses                    */
	uint32_t miss;                          /* # of cache hits                      */
	replacement_policy repl_policy;         /* replacement policy                   */
	block_ ***cache;                        /* cache storage                        */
} cache_;




/* ========================== PROTOTYPES ============================ */


static bool IPPo2(uint32_t x);  // Is positive power of two

static block_ *block_init(const uint64_t bd[], uint32_t count);

static uint64_t *parse(cache_ *cache, uint64_t address);
static uint64_t unparse(cache_ *cache, block_ *block);

static bool search(cache_ *L[], uint64_t address);
static void insert(cache_ *L[], uint64_t address);


/* ============================ CACHE =============================== */


static bool IPPo2(uint32_t x) {  // Is positive power of two
	return (x > 0) && ((x & (x - 1)) == 0);
}

static block_ *block_init(const uint64_t bd[], uint32_t count) {

	block_ *block = malloc(sizeof(struct block_));
	if (block == NULL) {
		err("block_init(): Failed to allocate memory for block\n");
	}

	block->tag = bd[0];
	block->set_index = bd[1];
	block->data = bd[2];
	block->count = count;
	block->valid = 1;

	return block;
}

cache_ *cache_init(uint32_t cache_size, uint32_t block_size, char *assoc_type, char *repl_policy) {

	/* Verify cache and block size */
	if (cache_size < block_size) {
		err("cache_init():: @cache_size (%u) is less than the @block_size (%u)\n", cache_size, block_size)
	}
	if (!IPPo2(cache_size)) {
		err("cache_init(): @cache_size (%u) is not a positive power of two\n", cache_size)
	}
	if (!IPPo2(block_size)) {
		err("cache_init(): @block_size (%u) is not a positive power of two\n", block_size)
	}


	/* Initialize cache */
	cache_ *cache;
	cache = (struct cache_ *)malloc(sizeof(struct cache_));
	if (cache == NULL) {
		err("cache_init(): Failed to allocate memory for cache\n");
	}


	/* Calculate associativity */
	char *token = strtok(assoc_type, ":");
	char *endptr;
	if (!strcmp(token, "direct")) {
		cache->sets = cache_size / block_size;
		cache->ways = 1;
	} else {
		if (strcmp(token, "assoc") != 0) {
			err("cache_init(): @assoc_type (\"%s\") is not the correct syntax\n", assoc_type);
		}

		uint32_t blocks = cache_size / block_size;
		token = strtok(NULL, ":");
		if (token == NULL) {
			cache->sets = 1;
			cache->ways = blocks;
		} else {

			errno = 0;

			uint32_t ways = strtol(token, &endptr, 10);
			if (errno == ERANGE) {
				err("cache_init(): assoc:%s overflow occurred\n", token);
			}
			if(*endptr != '\0') {
				err("cache_init(): assoc:%s is not a number\n", token);
			}

			if (!IPPo2(ways)) {
				err("cache_init(): assoc:%u is not a positive power of two\n", cache->ways);
			}

			cache->sets = blocks / ways;
			cache->ways = ways;
		}
	}


	/* Parse replacement policy */
	if (!strcmp("fifo", repl_policy)) {
		cache->repl_policy = 0;
	} else if (!strcmp("lru", repl_policy)) {
		cache->repl_policy = 1;
	} else {
		err("cache_init(): %s is not a valid replacement policy\n", repl_policy);
	}


	/* Initialize cache storage */
	cache->cache = malloc(cache->sets * sizeof(struct block **));
	if (cache->cache == NULL) {
		err("cache_init(): Failed to allocate memory for cache storage\n");
	}
	for (uint32_t i = 0; i < cache->sets; ++i) {
		cache->cache[i] = calloc(sizeof(struct block *), cache->ways);
		if (cache->cache[i] == NULL) {
			err("cache_init(): Failed to allocate memory for cache storage\n");
		}
	}


	/* Calculate trace address format */
	cache->offset_bits = (uint32_t) log2(block_size);
	cache->set_bits = (uint32_t) log2(cache->sets);

	/* Set variables to 0 */
	cache->hit = 0;
	cache->miss = 0;


	return cache;
}

void cache_destroy(cache_ *cache) {
	for (uint32_t i = 0; i < cache->sets; ++i) {
		for (uint32_t j = 0; j < cache->ways; ++j) {
			if(cache->cache[i][j] != NULL) {
				free(cache->cache[i][j]);
			}
		}
		free(cache->cache[i]);
	}
	free(cache->cache);
	free(cache);
}


/* ======================= ADDRESS PARSING ========================== */

#if CACHE_DEBUG
	static char* brep(uint64_t n, uint32_t bits) {

		static char binary[64];
		int i;

		for (i = bits-1; i >= 0; --i) {
			if(n & 1) {
				binary[i] = '1';
			} else {
				binary[i] = '0';
			}
			n >>= 1;
		}

		binary[bits] = '\0';

		return binary;
	}
#endif


static uint64_t *parse(cache_ *cache, uint64_t address) {

	#if CACHE_DEBUG
		block->orig_address = address;
	#endif

	static uint64_t bd[3]; // block descriptor

	uint64_t mask;
	uint32_t shift = 0;

	/* Parse data */
	shift += 0;
	mask = (uint64_t)pow(2, cache->offset_bits) - 1;
	bd[2] = (address >> shift) & mask;

	/* Parse set index */
	shift += cache->offset_bits;
	mask = (uint64_t)pow(2, cache->set_bits) - 1;
	bd[1] = (address >> shift) & mask;

	/* Parse tag */
	shift += cache->set_bits;
	bd[0] = address >> shift;


	return bd;
}

static uint64_t unparse(cache_ *cache, block_ *block) {

	uint64_t address = 0;
	uint32_t shift = 0;

	/* Unparse data */
	shift += 0;
	address += block->data << shift;

	/* Unparse set index */
	shift += cache->offset_bits;
	address += block->set_index << shift;

	/* Unparse tag */
	shift += cache->set_bits;
	address += block->tag << shift;

	#if CACHE_DEBUG
		if(address != block->orig_address) {
			fprintf(stderr, "unparse(): failure\n\n");
			fprintf(stderr, "unparse(): failure\n\n");

			/* Print original address in binary and hexadecimal */
			uint32_t max = 39;


			char *borig_address = brep(block->orig_address, max);
			fprintf(stderr, "orig:\t\t\t0x%012lx\t%s\n", block->orig_address, borig_address);

			/* Print unparsed address in binary and hexadecimal */
			char *baddress = brep(address, max);
			uint32_t baddress_len = strlen(baddress);
			fprintf(stderr, "unparsed:\t\t0x%012lx\t%s\n\n", address, baddress);


			/* Print block */

			char *bdata = brep(block->data, cache->offset_bits);
			uint32_t bdata_len = strlen(bdata);
			fprintf(stderr, "data:\t\t\t\t\t\t\t%*c%s\n", (baddress_len - bdata_len),' ', bdata);

			char *bset = brep(block->set_index, cache->set_bits);
			uint32_t bset_len = strlen(bset);
			fprintf(stderr,"set:\t\t\t\t\t\t\t%*c%s\n", ((max - bset_len) - bdata_len), ' ', bset);

			char *btag = brep(block->tag, (max - 8 - (cache->offset_bits + cache->set_bits)));
			uint32_t btag_len = strlen(btag);
			fprintf(stderr,"tag:\t\t\t\t\t\t\t%*c%s\n", ((max - btag_len) - (bdata_len + bset_len)), ' ', btag);

			exit(EXIT_FAILURE);
		}
	#endif

	return address;
}


/* ========================== OPERATIONS ============================ */


static bool search(cache_ *L[], uint64_t address) {

	uint64_t *bd;

	for(uint32_t i = 0; i < hierarchy; ++i) {

		bd = parse(L[i], address);

		for (uint32_t j = 0; j < L[i]->ways; ++j) {

			if(L[i]->cache[bd[1]][j] != NULL &&
			   L[i]->cache[bd[1]][j]->tag == bd[0]) {

				if(i > 0) {
					free(L[i]->cache[bd[1]][j]);
					L[i]->cache[bd[1]][j] = NULL;
					insert(L, address);
				}

				if(L[i]->repl_policy == lru) {
					L[i]->cache[bd[1]][j]->count = ++tick_count;
				}

				L[i]->hit++;
				return true;
			}
		}

		L[i]->miss++;
	}


	return false;
}

static void insert(cache_ *L[], uint64_t address) {

	uint64_t *bd;
	uint64_t evict = address;
	uint32_t block_index;
	uint32_t least;
	uint32_t i;

	for (i = 0; i < hierarchy; ++i) {

		bd = parse(L[i], evict);

		least = 0xFFFFFFFF;
		block_index = -1;

		for (uint32_t j = 0; j < L[i]->ways; ++j) {

			if (L[i]->cache[bd[1]][j] == NULL) {
				L[i]->cache[bd[1]][j] = block_init(bd, ++tick_count);
				return;
			}

			if(least > L[i]->cache[bd[1]][j]->count) {
				least = L[i]->cache[bd[1]][j]->count;
				block_index = j;
			}
		}

		evict = unparse(L[i], L[i]->cache[bd[1]][block_index]);
		free(L[i]->cache[bd[1]][block_index]);
		L[i]->cache[bd[1]][block_index] = block_init(bd, ++tick_count);
	}
}





/* ========================== SIMULATOR ============================= */


void simulator(cache_ *L[], uint32_t size, char *path) {

	hierarchy = size;

	uint32_t memread = 0;
	uint32_t memwrite = 0;


	uint64_t address;

	char mode;
	char buf[1024];
	char *endptr;

	FILE *trace = fopen(path, "r");
	if(trace == NULL) {
		err("simulator(): Failed to open trace file\n");
	}

	while(fscanf(trace, "%c 0x%s\n", &mode, buf) != EOF) {

		errno = 0;

		address = strtoull(buf, &endptr, 16);
		if (errno == ERANGE) {
			err("simulator(): %s overflow occurred\n", buf);
		}
		if (*endptr != '\0') {
			err("simulator(): %s not a hexadecimal value\n", buf);
		}

		if(mode == 'W') {
			memwrite++;
		}

		#if CACHE_DEBUG
			printf("inserting: %lx\n", address);
		#endif

		if (!search(L, address)) {
			memread++;
			insert(L, address);
		}
	}

	fclose(trace);


	printf("memread:%d\n", memread);
	printf("memwrite:%d\n", memwrite);
	if(hierarchy == 1) {
		printf("cachehit:%d\n", L[0]->hit);
		printf("cachemiss:%d\n", L[0]->miss);
	} else {
		for (uint32_t i = 0; i < hierarchy; ++i) {
			printf("l%dcachehit:%d\n", (i + 1), L[i]->hit);
			printf("l%dcachemiss:%d\n", (i + 1), L[i]->miss);
		}
	}
}





/* ============================ USAGE =============================== */


void usage() {
	fprintf(stderr, "\n");
	fprintf(stderr,"cache-simulator: simulates a multi-level cache up to two levels of hierarchy\n");
	fprintf(stderr,"\n");
	fprintf(stderr,"usage: cache-simulator \\\n");
	fprintf(stderr,"[L1 cache_size] [L1 assoc_type] [L1 cache_policy] [L1 block_size] \\\n");
	fprintf(stderr,"...\n");
	fprintf(stderr,"[Ln cache_size] [Ln assoc_type] [Ln cache_policy] [Ln block_size] \\\n");
	fprintf(stderr,"trace_file\n");
	fprintf(stderr,"\n");
}
