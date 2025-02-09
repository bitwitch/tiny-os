#include "common.h"

extern char __stack_top[];

int syscall(int syscall_num, int arg0, int arg1, int arg2) {
	register int a0 __asm__("a0") = arg0;
	register int a1 __asm__("a1") = arg1;
	register int a2 __asm__("a2") = arg2;
	register int a3 __asm__("a3") = syscall_num;
	__asm__ __volatile__("ecall"
		: "=r"(a0)
		: "r"(a0), "r"(a1), "r"(a2), "r"(a3)
		: "memory");
	return a0;
}

void putchar(char c) {
	syscall(SYSCALL_PUTCHAR, c, 0, 0);
}

int getchar(void) {
	return syscall(SYSCALL_GETCHAR, 0, 0, 0);
}

U32 readfile(char *filename, U8 *buf, U32 buf_len) {
	return (U32)syscall(SYSCALL_READFILE, (int)filename, (int)buf, (int)buf_len);
}

__attribute__((noreturn)) 
void exit(int code) {
	syscall(SYSCALL_EXIT, code, 0, 0);
	printf("well shit....\n");
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
