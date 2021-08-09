#ifndef FALLOUT_H_
#define FALLOUT_H_

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
#include "cacheutils.h"
#include <memory.h>

#define PAGE_SIZE (4096)
#define PAGE_POOL_SIZE (1000)
#define OFFSET (8)
#define SECRET_MIN_LEN (10)
#define SECRET_MAX_LEN (50)
#define RETRIES (10)
#define PAGE_NAME "./victims/victim"

char __attribute__((aligned(4096))) lut[256 * PAGE_SIZE];

void *gnrmap();
char *gnrname(int);
void gnrsecret();

/*
* Using the WTF shortcut mentioned in the article, reads from the page.
* Returns: number of succesful bytes reads
*/
void fallout(int, char *);
enum flags {debug = 1, fixed = 2};
int args = 0;
int slen = SECRET_MAX_LEN - 1;

char secret[SECRET_MAX_LEN] = "This page has been compromised! you are not safe!";
char decoded[SECRET_MAX_LEN];

#endif // FALLOUT_H_
