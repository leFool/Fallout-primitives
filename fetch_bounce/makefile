all: dirs fetchbounce

.PHONEY: dirs

MKDIR_P = mkdir -p
dirs: victims

victims:
	@${MKDIR_P} victims

fetchbounce: src/main.c headers/fetchbounce.h headers/cacheutils.h
	gcc -std=gnu11 -Os -Iheaders src/main.c -o fetchbounce

clean:
	rm -rf ./*.o fetchbounce ./victims/*
