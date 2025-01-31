#define va_list  __builtin_va_list
#define va_start __builtin_va_start
#define va_end   __builtin_va_end
#define va_arg   __builtin_va_arg

typedef unsigned char U8;
typedef unsigned int U32;

typedef struct {
	long error;
	union {
		long value;
		unsigned long uvalue;
	};
} SBI_Ret;

extern U8 __bss[], __bss_end[], __stack_top[];

SBI_Ret sbi_call(long arg0, long arg1, long arg2, long arg3, long arg4, long arg5,
		         long fid, long eid)
{
    register long a0 __asm__("a0") = arg0;
    register long a1 __asm__("a1") = arg1;
    register long a2 __asm__("a2") = arg2;
    register long a3 __asm__("a3") = arg3;
    register long a4 __asm__("a4") = arg4;
    register long a5 __asm__("a5") = arg5;
    register long a6 __asm__("a6") = fid;
    register long a7 __asm__("a7") = eid;

    __asm__ __volatile__("ecall"
                         : "=r"(a0), "=r"(a1)
                         : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5),
                           "r"(a6), "r"(a7)
                         : "memory");
    return (SBI_Ret){.error = a0, .value = a1};
}

void putchar(char ch) {
	long eid = 1; // Console Putchar
    sbi_call(ch, 0, 0, 0, 0, 0, 0, eid);
}

void printf(char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	char *c = fmt;
	while (*c != 0) {
		if (*c == '%') {
			++c;
			switch (*c) {
			case 'd': {
				int val = va_arg(args, int);

				if (val < 0) {
					putchar('-');
					val *= -1;
				}

				int divisor = 1;
				while (val / (divisor*10)) divisor *= 10;
				
				while (divisor > 0) {
					int digit = val / divisor;
					putchar(digit + '0');
					val %= divisor;
					divisor /= 10;
				}

				break;
			}
			case 'x': {
				U32 val = va_arg(args, U32);

				U32 divisor = 1;
				while (divisor < 0x10000000 && val / (divisor*16)) {
					divisor *= 16;
				}
				
				putchar('0');
				putchar('x');
				while (divisor > 0) {
					char c = "0123456789abcdef"[val / divisor];
					putchar(c);
					val %= divisor;
					divisor /= 16;
				}
				break;
			}
			case 's': {
				for (char *s = va_arg(args, char*); *s; ++s) {
					putchar(*s);
				}
				break;
			}
			case '%':
				putchar('%');
				break;
			default: 
				break;
			}
		} else {
			putchar(*c);
		}
		++c;
	}

	va_end(args);
}

void *memset(void *buf, U8 val, U32 count) {
	U8 *p = (U8*)buf;
	for (U32 i=0; i<count; ++i) {
		p[i] = val;
	}
	return buf;
}

void kernel_main(void) {
	memset(__bss, 0, (U32)__bss_end - (U32)__bss);
	printf("\nWord!\n");
	printf("Word %s!\n", "up");
	printf("%d\n", 420);
	printf("%d\n", -69);
	printf("%x\n", 105);
	printf("%x\n", 0x69);
	printf("%x\n", -105);
	for (;;) {
		__asm__ __volatile__("wfi");
	}
}

__attribute__((section(".text.boot")))
__attribute__((naked))
void boot(void) {
    __asm__ __volatile__(
        "mv sp, %[stack_top]\n" // Set the stack pointer
        "j kernel_main\n"       // Jump to the kernel main function
        :
        : [stack_top] "r" (__stack_top) // Pass the stack top address as %[stack_top]
    );
}
