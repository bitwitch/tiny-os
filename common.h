#pragma once

#define va_list    __builtin_va_list
#define va_start   __builtin_va_start
#define va_end     __builtin_va_end
#define va_arg     __builtin_va_arg
#define align_up   __builtin_align_up
#define is_aligned __builtin_is_aligned
#define offsetof   __builtin_offsetof

#define true  1
#define false 0
#define NULL  ((void *) 0)

#define KILOBYTES(n) (n * 1024)
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

typedef int bool;
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long U64;
typedef U32 Paddr;                 // physical address
typedef U32 Vaddr;                 // virtual address

enum {
	SYSCALL_INVALID = 0, 
	SYSCALL_PUTCHAR = 1,
	SYSCALL_GETCHAR = 2,
	SYSCALL_EXIT    = 3,
};

void *memset(void *buf, U8 val, U32 count);
void *memcpy(void *dest, void *src, U32 count);
void *memmove(void *dest,  void *src, U32 count);
int memcmp(void *lhs, void *rhs, U32 count);
int strcmp(char *str1, char *str2);
void printf(char *fmt, ...);
void putchar(char c);
int getchar(void);
void exit(int code);
