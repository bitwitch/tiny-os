#include "common.h"

void *memset(void *buf, U8 val, U32 count) {
	U8 *p = (U8*)buf;
	for (U32 i=0; i<count; ++i) {
		p[i] = val;
	}
	return buf;
}

void *memcpy(void *dest, void *src, U32 count) {
	U8 *dest_u8 = (U8*)dest;
	U8 *src_u8 = (U8*)src;
	for (U32 i=0; i<count; ++i) {
		dest_u8[i] = src_u8[i];
	}
	return dest;
}

void *memmove(void *dest,  void *src, U32 count) {
#define COPY_BUF_SIZE KILOBYTES(4u)
	if (count > COPY_BUF_SIZE) {
		printf("this temporary implementation of memmove only handles %x bytes, but %x were requested\n", 
			COPY_BUF_SIZE, count);
		exit(1);
	} 

	U8 src_copy[COPY_BUF_SIZE];
	memcpy(src_copy, src, count);
	U8 *dest_u8 = (U8*)dest;
	for (U32 i=0; i<count; ++i) {
		dest_u8[i] = src_copy[i];
	}
	return dest;
#undef COPY_BUF_SIZE 
}

int memcmp(void *lhs, void *rhs, U32 count) {
	for (U32 i=0; i<count; ++i) {
		U8 l = ((U8*)lhs)[i];
		U8 r = ((U8*)rhs)[i];
		if (l < r) return -1;
		if (l > r) return 1;
	}
	return 0;
}

int strcmp(char *str1, char *str2) {
	while (*str1 && *str2) {
		if (*str1 < *str2) return -1;
		if (*str1 > *str2) return 1;
		++str1; ++str2;
	}

	if (*str1 == 0 && *str2 != 0) return -1;
	if (*str1 != 0 && *str2 == 0) return 1;
	return 0;
}

U32 strlen(char *s) {
	int i = 0;
	for (; s[i] != 0; ++i);
	return i;
}

char *strcpy(char *dest, char *src) {
	int i;
	for (i=0; src[i] != 0; ++i) {
		dest[i]	= src[i];
	}
	dest[i]	= 0;
	return dest;
}

bool isspace(int c) {
	return c == ' ' || (unsigned)c-'\t' < 5;
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
			case 'c': {
				char c = (char)va_arg(args, int);
				putchar(c);
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

