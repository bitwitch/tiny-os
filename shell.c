#include "common.h"
#include "user.h"

#define BACKSPACE   127
#define MAX_CMDLINE 256

#define ARRAY_LEN(a) sizeof(a) / sizeof(a[0])

// dynamic array macro: assumes struct with fields: items, len, cap
#define da_append(da, item)                                                       \
    do {                                                                          \
		if ((da)->len >= (da)->cap) {                                             \
			(da)->cap = (da)->cap ? (da)->cap*2 : 32;                             \
			(da)->items = realloc((da)->items, (da)->cap*sizeof((da)->items[0])); \
		}                                                                         \
		(da)->items[(da)->len++] = item;                                          \
    } while (0)

// dir - Displays a list of files and subdirectories in a directory.
// pwd - print current working directory
// cd - change directory
// 
//

// typedef struct {
	// char **items;
	// U32 len;
	// U32 cap;
// } Arguments;

// typedef struct {
	// char *program;
	// Arguments args;
// } Command;

// typedef struct {
	// char *name;
	// void (*evaluate)(Command cmd);
// } Builtin;

// char *env_path;

// void eval_cd(Command cmd) {
	// printf("cd:");
	// for (int i=0; i<cmd.args.len; ++i) {
		// printf(" %s", cmd.args.items[i]);
	// }
// }

// void eval_dir(Command cmd) {
	// printf("dir:");
	// for (int i=0; i<cmd.args.len; ++i) {
		// printf(" %s", cmd.args.items[i]);
	// }
// }

// void eval_pwd(Command cmd) {
	// printf("pwd:");
	// for (int i=0; i<cmd.args.len; ++i) {
		// printf(" %s", cmd.args.items[i]);
	// }
// }

// Builtin *builtins[] = {
	// { .name = "cd",  .evaluate = eval_cd },
	// { .name = "dir", .evaluate = eval_dir },
	// { .name = "pwd", .evaluate = eval_pwd },
// };
// U32 num_builtins = ARRAY_LEN(builtins);


// // NOTE: parse modifies cmdline
// //       pointers in cmd struct point into same memory as cmdline
// Command parse(char *cmdline) {
	// Command cmd = {0};
	// cmd.program = cmdline;
	// bool start_arg = false;
	// char *c = cmdline;
	// for (; c != '\n'; ++c) {
		// if (*c == ' ' || *c == '\t' || *c == '\v' || *c == '\f') {
			// start_arg = true;
			// *c = 0;
		// } else {
			// if (start_arg) {
				// da_append(&cmd.args, c);
				// start_arg = false;
			// }
		// }
	// }
	// *c = 0;

	// return cmd;
// }

// void evaluate(Command cmd) {
	// bool is_builtin = false;
	// for (int i=0; i<num_builtins; ++i) {
		// // TODO: string interning
		// if (cmd.program == builtins[i].name) {
			// is_builtin = true;
			// builtins[i].evaluate(cmd);
		// }
	// }

	// if (!is_builtin) {
		// // search through PATH env variable for first matching program
	// }

	// if (cmd.program == str_intern("hello")) {
	// }

	// if (0 == strcmp(cmdline, "hello")) {
		// printf("Hey boo, what it do?\n");
	// } else if (0 == strcmp(cmdline, "exit")) {
		// exit(0);
	// } else if (0 == memcmp(cmdline, "readfile ", strlen("readfile "))) {
		// char *filename = cmdline + strlen("readfile ");
		// while (isspace(*filename)) ++filename;

		// U8 buf[2048];
		// U32 bytes_read = readfile(filename, buf, sizeof(buf));
		// if (bytes_read > 0) {
			// printf("%s\n", buf);
		// }
	// } else if (0 == memcmp(cmdline, "writefile ", strlen("writefile "))) {
		// char *filename = cmdline + strlen("writefile ");
		// while (isspace(*filename)) ++filename;

		// char *data = filename;
		// while (!isspace(*data)) ++data;
		// *data++ = 0; // null terminate filename
		// while (isspace(*data))  ++data;

		// U32 data_len = strlen(data);
		// U32 bytes_written = writefile(filename, (U8*)data, data_len);
		// if (bytes_written == data_len) {
			// printf("successfully wrote %s\n", filename);
		// } else {
			// printf("error: writefile: tried to write %u bytes to %s, only %u were written\n", 
				// data_len, filename, bytes_written);
		// }
	// } else {
		// printf("unknown command: %s\n", cmdline);
	// }
// }

// // void init_builtins(void) {
	// // for (int i=0; i<num_builtins; ++i) {
		// // builtins[i].name = str_intern(builtins[i].name);
	// // }
// // }

// void main2(void) {
	// char cmdline[MAX_CMDLINE];
	// Command cmd;

	// // init_builtins();

	// for(;;) {
		// memset(cmdline, 0, sizeof(cmdline));
		// memset(cmd, 0, sizeof(cmd));
		// putchar('>');
		// int i;
		// for (i=0; i < MAX_CMDLINE; ++i) {
			// int c = getchar();
			// if (c == BACKSPACE) {
				// if (i > 0) {
					// putchar('\b');
					// putchar(0);
					// putchar('\b');

					// cmdline[i-1] = 0;
					// i -= 2;
				// } else {
					// i = -1;
				// }
				// continue;
			// }
			// if (c == '\r') {
				// putchar('\n');
				// cmdline[i] = '\n';
				// break;
			// }

			// putchar(c);
			// cmdline[i] = c;
		// }

		// if (i < MAX_CMDLINE) {
			// cmd = parse(cmdline);
			// evaluate(cmd);
		// } else {
			// printf("command too long, max length is %d characters\n", MAX_CMDLINE);
		// }
	// }
// }

int main(void) {

	U32 size = 32;
	U8 *mem = malloc(size);
	*mem = 0x69;
	// printf("mem = %x(%x)\n", *mem, mem);

	free(mem);
	mem = malloc(size);
	*mem = 0x42;
	// printf("mem = %x(%x)\n", *mem, mem);

	U8* page = malloc(KILOBYTES(4));
	// printf("page = %x(%x)\n", *page, page);

	U8* page_2 = malloc(KILOBYTES(8));
	// printf("page_2 = %x(%x)\n", *page_2, page_2);


	return 0;
}




