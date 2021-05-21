#ifndef _CACHE_
#define _CACHE_

typedef struct cache_ cache_;

cache_ *cache_init(uint32_t cache_size, uint32_t block_size, char *assoc_type, char *repl_policy);

void cache_destroy(cache_ *cache);

void simulator(cache_ *L[], uint32_t size, char *path);

void usage();

#endif // _CACHE_