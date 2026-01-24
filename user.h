#pragma once
U32 readfile(char *filename, U8 *buf, U32 buf_len);
U32 writefile(char *filename, U8 *buf, U32 buf_len);

void *malloc(U32 size);
void free(void *p);

void exit(int code);

#define assert(cond) \
		if (!(cond)) { \
			printf("%s:%d: assertion '%s' failed\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} 
