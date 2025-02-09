#include "common.h"
#include "user.h"

#define BACKSPACE   127
#define MAX_CMDLINE 256

void evaluate(char *cmdline) {
	if (0 == strcmp(cmdline, "hello")) {
		printf("Hey boo, what it do?\n");
	} else if (0 == strcmp(cmdline, "exit")) {
		exit(0);
	} else if (0 == memcmp(cmdline, "readfile ", strlen("readfile "))) {
		char *filename = cmdline + strlen("readfile ");
		while (isspace(*filename)) ++filename;

		U8 buf[2048];
		U32 bytes_read = readfile(filename, buf, sizeof(buf));
		if (bytes_read > 0) {
			printf("%s\n", buf);
		}

	} else {
		printf("unknown command: %s\n", cmdline);
	}
}

void main(void) {
	for(;;) {
		char cmdline[MAX_CMDLINE] = {0};
		putchar('>');
		int i;
		for (i=0; i < MAX_CMDLINE; ++i) {
			int c = getchar();
			// TODO(shaw): handle backspace
			// if (c == BACKSPACE) {
				// i -= 2;
				// continue;
			// }
			if (c == '\r') {
				putchar('\n');
				break;
			}

			putchar(c);
			cmdline[i] = c;
		}

		if (i < MAX_CMDLINE) {
			evaluate(cmdline);
		} else {
			printf("command too long, max length is %d characters\n", MAX_CMDLINE);
		}
	}
}
