all: dirs fallout

.PHONEY: dirs

MKDIR_P = mkdir -p
dirs: victims

victims:
	@${MKDIR_P} victims

fallout: src/main.c headers/cacheutils.h
	gcc -std=gnu11 -Os -Iheaders src/main.c -o fallout

#main.o: main.c
#	gcc -c -std=c99 -o main.o main.c

clean:
	rm -rf ./*.o fallout ./victims/*
