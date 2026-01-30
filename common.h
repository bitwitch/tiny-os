#pragma once

#define va_list    __builtin_va_list
#define va_start   __builtin_va_start
#define va_end     __builtin_va_end
#define va_arg     __builtin_va_arg
#define align_up   __builtin_align_up
#define is_aligned __builtin_is_aligned
#define offsetof   __builtin_offsetof

#define UINT32_MAX 4294967295

#define true  1
#define false 0
#define NULL  ((void *) 0)

#define KILOBYTES(n) (n * 1024)
#define MEGABYTES(n) (n * 1024 * 1024)
#define PAGE_SIZE    KILOBYTES(4)

#define MIN(a, b)    ((a) < (b) ? (a) : (b))
#define MAX(a, b)    ((a) > (b) ? (a) : (b))
#define ARRAY_LEN(a) sizeof(a) / sizeof(a[0])

typedef int bool;
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef int S32;
typedef unsigned long long U64;
typedef U32 Paddr;                 // physical address
typedef U32 Vaddr;                 // virtual address

enum {
	SYSCALL_INVALID   = 0, 
	SYSCALL_PUTCHAR   = 1,
	SYSCALL_GETCHAR   = 2,
	SYSCALL_EXIT      = 3,
	SYSCALL_GETPAGES  = 5,
	SYSCALL_OPEN      = 6,
};

// syscall open flags
#define O_READ_ONLY    (1 << 0)
#define O_WRITE_ONLY   (1 << 1)
#define O_READ_WRITE   (1 << 2)
#define O_CREATE       (1 << 3)
#define O_DIRECTORY    (1 << 4)
#define O_APPEND       (1 << 5)
#define O_TRUNCATE     (1 << 6)

void *memset(void *buf, U8 val, U32 count);
void *memcpy(void *dest, void *src, U32 count);
void *memmove(void *dest,  void *src, U32 count);
int memcmp(void *lhs, void *rhs, U32 count);
int strcmp(char *str1, char *str2);
U32 strlen(char *s);
char *strcpy(char *dest, char *src);
char *strncpy(char *dest, char *src, U32 size);
void printf(char *fmt, ...);
void putchar(char c);
int getchar(void);
bool isspace(int c);

