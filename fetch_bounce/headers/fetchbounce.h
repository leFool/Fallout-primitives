#ifndef FETCHBOUNCE_H_
#define FETCHBOUNCE_H_

#include "cacheutils.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <x86intrin.h>
#include <fcntl.h>
#include <time.h>
#include <memory.h>

#define PAGE_SIZE (4096)
#define PAGE_POOL_SIZE (3000)
#define DEFAULT_POSSIBLE_RESULTS (3)
#define LOAD_BYTE (88)
#define TEST_BYTE (99)
#define TOTAL_INDEX 0
#define SUCCESS_INDEX 1
#define RETRIES (3)
#define PAGE_NAME "./victims/victim"

void *gnrmap(void);
char *gnrname(int);
void report(void);

enum result {hit, miss, invalid};
enum result_type {expected, actual};
enum result rawresults[2][PAGE_POOL_SIZE];

int debug = 0;
int fixedresult = -1;
int presults = DEFAULT_POSSIBLE_RESULTS;

uint8_t lut[256 * PAGE_SIZE];

#endif // FETCHBOUNCE_H_
