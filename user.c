#include "common.h"
#include "user.h"

extern char __stack_top[];
int errno;
S32 syscall(S32 syscall_num, S32 arg0, S32 arg1, S32 arg2);

// userspace "modules" split into other files just for code organization
#include "malloc.c"

S32 syscall(S32 syscall_num, S32 arg0, S32 arg1, S32 arg2) {
	register int a0 __asm__("a0") = arg0;
	register int a1 __asm__("a1") = arg1;
	register int a2 __asm__("a2") = arg2;
	register int a3 __asm__("a3") = syscall_num;
	__asm__ __volatile__("ecall"
		: "=r"(a0)
		: "r"(a0), "r"(a1), "r"(a2), "r"(a3)
		: "memory");

	if (a0 < 0) {
		errno = -a0;
		return -1;
	}

	return a0;
}

void putchar(char c) {
	syscall(SYSCALL_PUTCHAR, c, 0, 0);
}

int getchar(void) {
	return syscall(SYSCALL_GETCHAR, 0, 0, 0);
}

int open(char *path, U32 flags, U32 mode) {
	return syscall(SYSCALL_OPEN, (S32)path, (S32)flags, (S32)mode);
}

int read(int fd, void *buf, U32 size) {
	return syscall(SYSCALL_READ, (S32)fd, (S32)buf, (S32)size);
}

int cwd(char *buf, U32 size) {
	return syscall(SYSCALL_CWD, (S32)buf, (S32)size, 0);
}

/*
On  success,  the  number of bytes read is returned.  On end of directory, 0 is returned.  On error, -1 is re‐
turned, and errno is set appropriately.
ERRORS
   EBADF  Invalid file descriptor fd.
   EFAULT Argument points outside the calling process's address space.
   EINVAL Result buffer is too small.
   ENOENT No such directory.
*/
int dir_entries(int fd, void *buf, U32 buf_size) {
	return syscall(SYSCALL_DIR_ENTRIES, (S32)fd, (S32)buf, (S32)buf_size);
}

DIR *open_dir(char *path) {
	int fd = syscall(SYSCALL_OPEN, (S32)path, O_READ_ONLY | O_DIRECTORY, 0);
	if (fd < 0) {
		errno = -fd;
		return NULL;
	}

	DIR *dir = calloc(1, sizeof(DIR));
	if (!dir) {
		return NULL;
	}
	dir->fd = fd;
	dir->buf_size = DIR_DEFAULT_BUF_SIZE;
	dir->buf_pos = dir->buf_size; // set so that first read will refill buffer
	dir->buf = malloc(dir->buf_size);
	if (!dir->buf) {
		return NULL;
	}

	return dir;
}

void close_dir(DIR *d) {
	// TODO: call close on fd
	free(d);
}

DirEntry *read_dir(DIR *dir) {
	// if you can still read DirEntries from buffer, read the next one
	// else refill buffer of DirEntries via syscall_dir_entries
	if (dir->buf_pos >= dir->buf_size && !dir->end_reached) {
		memset(dir->buf, 0, dir->buf_size);
		dir->buf_pos = 0;
		int rc = dir_entries(dir->fd, dir->buf, dir->buf_size);
		if (rc < 0) {
			printf("Error: read_dir: dir_entries failed\n");
			return NULL;
		} else if (rc == 0) {
			dir->end_reached = true;
		}
	}

	DirEntry *entry = (DirEntry*)(dir->buf + dir->buf_pos);
	if (entry->inode_num == 0) {
		// end reached
		return NULL;
	}
	dir->buf_pos += sizeof(DirEntry);
	return entry;
}


__attribute__((noreturn)) 
void exit(int code) {
	syscall(SYSCALL_EXIT, code, 0, 0);
	//
	// TODO: release resources such as memory and open files
	// 
	for (;;){} // so compiler doesnt warn about noreturn 
}

__attribute__((section(".text.start")))
__attribute__((naked))
void start(void) {
	__asm__ __volatile__(
		"mv sp, %[stack_top] \n"
		"call main\n"
		"call exit\n"
		:
		: [stack_top] "r" (__stack_top)
	);
}
