#pragma once
#define DIR_DEFAULT_BUF_SIZE (8 * sizeof(DirEntry))
typedef struct {
	int fd;
	U8 *buf;
	U32 buf_size;
	U32 buf_pos; // current position inside userspace buffer
	U32 offset;  // directory position in the kernel / filesystem
	bool end_reached; // gets set to true when all entries in the dir have been read into the buffer
} DIR;

void *malloc(U32 size);
void *realloc(void* ptr, U32 size);
void *calloc(U32 num_objs, U32 obj_size);
void free(void *p);

void exit(int code);

int open(char *path, U32 flags, U32 mode);
int read(int fd, void *buf, U32 size);
int cwd(char *buf, U32 size);


DIR *open_dir(char *path);
DirEntry *read_dir(DIR *dir);

#define assert(cond) \
	do { \
		if(!(cond)) { \
			printf("%s:%d assertion failed: \"%s\"\n", __FILE__, __LINE__, #cond); \
			exit(1); \
		} \
	} while(0)

extern int errno;
