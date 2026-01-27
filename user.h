#pragma once
void *malloc(U32 size);
void *realloc(void* ptr, U32 size);
void free(void *p);

int open(char *path, U32 flags, U32 mode);

void exit(int code);

#define assert(cond) \
	do { \
		if(!cond) { \
			printf("%s:%d assertion failed: \"%s\"\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
	} while(0)

