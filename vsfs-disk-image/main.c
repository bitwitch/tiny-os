#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <io.h>

#ifndef MAX_PATH
#if defined _MAX_PATH
#define MAX_PATH _MAX_PATH
#elif defined PATH_MAX
#define MAX_PATH PATH_MAX
#else
#error "No suitable MAX_PATH surrogate"
#endif
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define INODE_NUM_DIRECT_POINTERS  12
#define ROOT_INODE_NUM             1    // zero is reserved for a non-existent file
#define DIR_LINK_ENTRY_MIN         12

#define KILOBYTES(n)        (n * 1024)
#define MEGABYTES(n)        (n * 1024 * 1024)
#define BLOCK_SIZE          KILOBYTES(4)
#define SUPERBLOCK_START    KILOBYTES(4)
#define INODE_BITMAP_START  KILOBYTES(8)
#define DATA_BITMAP_START   KILOBYTES(12)
#define INODE_TABLE_START   KILOBYTES(16)
#define DATA_REGION_START   KILOBYTES(272)

#define VSFS_MAGIC 0x73667376

enum {
	INODE_NONE,
	INODE_DIR,
	INODE_FILE,
};


typedef uint32_t U32;
typedef uint8_t  U8;

// ---------------------------------------------------------------------------
// stretchy buffer, a la sean barrett
// ---------------------------------------------------------------------------
typedef struct {
	size_t len;
	size_t cap;
	char buf[]; // flexible array member
} BufHeader;

// get the metadata of the array which is stored before the actual buffer in memory
#define buf__header(b) ((BufHeader*)((char*)b - offsetof(BufHeader, buf)))
// checks if n new elements will fit in the array
#define buf__fits(b, n) (buf_lenu(b) + (n) <= buf_cap(b))
// if n new elements will not fit in the array, grow the array by reallocating 
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = buf__grow((b), buf_lenu(b) + (n), sizeof(*(b)))))

#define BUF(x) x // annotates that x is a stretchy buffer
#define buf_len(b)  ((b) ? (int)buf__header(b)->len : 0)
#define buf_lenu(b) ((b) ?      buf__header(b)->len : 0)
#define buf_set_len(b, l) buf__header(b)->len = (l)
#define buf_cap(b) ((b) ? buf__header(b)->cap : 0)
#define buf_end(b) ((b) + buf_lenu(b))
#define buf_push(b, ...) (buf__fit(b, 1), (b)[buf__header(b)->len++] = (__VA_ARGS__))
#define buf_free(b) ((b) ? (free(buf__header(b)), (b) = NULL) : 0)
#define buf_printf(b, ...) ((b) = buf__printf((b), __VA_ARGS__))

void *buf__grow(void *buf, size_t new_len, size_t elem_size) {
	size_t new_cap = MAX(1 + 2*buf_cap(buf), new_len);
	assert(new_len <= new_cap);
	size_t new_size = offsetof(BufHeader, buf) + new_cap*elem_size;

	BufHeader *new_header;
	if (buf) {
		new_header = realloc(buf__header(buf), new_size);
	} else {
		new_header = malloc(new_size);
		new_header->len = 0;
	}
	new_header->cap = new_cap;
	return new_header->buf;
}
// ---------------------------------------------------------------------------

typedef struct {
	int type;
	U32 size_in_bytes;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
} DiskInode;

#pragma pack(4)
typedef struct {
  U32 magic;         // Must be "vsfs"
  U32 size_in_blocks; 
  U32 num_data_blocks;
  U32 num_inodes;    
  U32 inode_start;   // Block number of first inode block
  U32 data_start;    // Block number of first data block
} Superblock; 

typedef struct {
	U32 inode_num;
	U32 entry_size; // size of name plus any empty space, this is used so that new files can reuse old space
	U32 name_size;  // including null-terminator
	char *name;
} DirLink;

typedef struct {
	int inode_type;
	U32 inode_num;
	char *path;             // for file
	BUF(DirLink *dir_links); // for dir
} DiskImgEntry;

typedef struct {
    char base[MAX_PATH];
    char name[MAX_PATH];
    size_t size;
    bool is_dir;
} DirEntry;

void path_normalize(char path[MAX_PATH]) {
    char *ptr;
    for (ptr = path; *ptr; ++ptr) {
        if (*ptr == '\\') {
            *ptr = '/';
        }
    }
	// remove trailing slash
    if (ptr != path && ptr[-1] == '/') {
        ptr[-1] = 0;
    }
}


void path_copy(char path[MAX_PATH], char *src) {
    strncpy(path, src, MAX_PATH);
    path[MAX_PATH - 1] = 0;
    path_normalize(path);
}

void path_join(char path[MAX_PATH], char *src) {
    char *ptr = path + strlen(path);
    if (ptr != path && ptr[-1] == '/') {
        ptr--;
    }
    if (*src == '/') {
        src++;
    }
    snprintf(ptr, path + MAX_PATH - ptr, "/%s", src);
}


// return a stretchy buf of directory entries
DirEntry *read_dir(char *path) {
	BUF(DirEntry *entries) = NULL;

    char filespec[MAX_PATH];
    path_copy(filespec, path);
    path_join(filespec, "*");

	intptr_t handle;
    struct _finddata_t fileinfo;

    handle = _findfirst(filespec, &fileinfo);
	if (handle == -1) {
		// no files
		return NULL;
	}

	do {
		if (0 == strcmp(fileinfo.name, ".") || 0 == strcmp(fileinfo.name, "..")) {
			continue;
		}
		DirEntry entry = {0};
		path_copy(entry.base, path);
		entry.size = fileinfo.size;
		memcpy(entry.name, fileinfo.name, sizeof(entry.name) - 1);
		entry.name[MAX_PATH - 1] = 0;
		entry.is_dir = fileinfo.attrib & _A_SUBDIR;
		buf_push(entries, entry);
	} while (_findnext(handle, &fileinfo) == 0);

	return entries;
}
/*
disk/
	code/
		hello.c
	documents/
		notes/
			todo.txt
		FOF.txt
		jabberwocky.txt
	notice.txt
*/

U32 align_up(U32 val, U32 size) {
	U32 remainder = val % size;
	return remainder ? val + (size - remainder) : val;
}

BUF(DiskInode *inodes) = NULL;
BUF(DiskImgEntry *entries) = NULL;

// insert new inode into inode_table
	// i->type known, but i->size and i->addrs must be computed later
// create new DiskDir
// create DiskDirEntries for . and ..
// read all directory entries (read_dir)
// for each direntry:
	// if dir
		// inode_num = traverse_dir()
	// if file
		// insert new inode into inode_table
		// insert a new DiskImgEntry into entries
	// insert new DirLink into DiskDir
// insert a new DiskImgEntry into entries for this dir
U32 traverse_dir(char *path, U32 parent_inode_num) {
	U32 inode_num = buf_len(inodes);
	buf_push(inodes, (DiskInode){.type = INODE_DIR});

	BUF(DirLink *dir_links) = NULL;

	DirLink dot = {
		.inode_num = inode_num,
		.name_size = 2,
		.entry_size = DIR_LINK_ENTRY_MIN,
		.name = ".",
	};
	buf_push(dir_links, dot);

	DirLink dot_dot = {
		.inode_num = parent_inode_num,
		.name_size = 3,
		.entry_size = DIR_LINK_ENTRY_MIN,
		.name = "..",
	};
	buf_push(dir_links, dot_dot);

	BUF(DirEntry *dir_entries) = read_dir(path);
	for (int i=0; i<buf_len(dir_entries); ++i) {
		DirEntry *entry = &dir_entries[i];
		char tmp[MAX_PATH];
		path_copy(tmp, entry->base);
		path_join(tmp, entry->name);
		char *sub_path = _strdup(tmp);

		U32 child_inode_num;
		if (entry->is_dir) {
			child_inode_num = traverse_dir(sub_path, inode_num);
		} else {
			child_inode_num = buf_len(inodes);
			buf_push(inodes, (DiskInode){.type = INODE_FILE});
			DiskImgEntry die = {0};
			die.inode_type = INODE_FILE;
			die.inode_num = child_inode_num;
			die.path = sub_path;
			buf_push(entries, die);
		}

		DirLink link = {0};
		link.inode_num = child_inode_num;
		link.name_size = (U32)strlen(sub_path) + 1;
		link.entry_size = align_up(link.name_size, DIR_LINK_ENTRY_MIN);
		link.name = sub_path;
		buf_push(dir_links, link);
	}

	DiskImgEntry die = {0};
	die.inode_type = INODE_DIR;
	die.inode_num = inode_num;
	die.dir_links = dir_links;
	buf_push(entries, die);

	return inode_num;
}

U32 diskimg_write_dir(FILE *fp, DiskImgEntry *dir) {
	U32 blocks_written = 0;
	// while not all data written
		// find first empty data block in data_bitmap, mark as in use
		// write dir data to data region
		// write block addr to inode table
	// write size_in_bytes to inode table
	return blocks_written;
}

U32 diskimg_write_file(FILE *fp, DiskImgEntry *file) {
	U32 blocks_written = 0;
	// open file
	// while not all data written
		// find first empty data block in data_bitmap, mark as in use
		// write dir data to data region
		// write block addr to inode table
	// close file
	// write size_in_bytes to inode table
	return blocks_written;
}

size_t diskimg_write_inode_bitmap(FILE *fp, int num_inodes) {
	assert(num_inodes <= BLOCK_SIZE);
	U8 buf[BLOCK_SIZE] = {0};
	U32 *cursor = (U32*)buf;
	for (int iterations = num_inodes/32; iterations > 0; --iterations) {
		*cursor++ = 0xFFFFFFFF;
	}

	int remainder = num_inodes % 32;
	if (remainder != 0) {
		U32 mask = (1 << remainder) - 1;
		*cursor++ = mask;
	}

	int rc = fseek(fp, INODE_BITMAP_START, SEEK_SET);
	if (rc != 0) {
		perror("fseek");
		return 0;
	}

	size_t written = fwrite(buf, sizeof(buf[0]), BLOCK_SIZE, fp);
	if (written != BLOCK_SIZE) {
		fprintf(stderr, "diskimg_write_inode_bitmap: fwrite expected to write %u bytes, but wrote %zu\n", 
			BLOCK_SIZE, written);
	}

	return written;
}

bool diskimg_write_superblock(FILE *fp, U32 num_inodes, U32 num_data_blocks) {
	Superblock superblock = {
		.magic = VSFS_MAGIC,
		.size_in_blocks = KILOBYTES(16656) / BLOCK_SIZE,
		.num_data_blocks = num_data_blocks,
		.num_inodes = num_inodes,
		.inode_start = INODE_TABLE_START,
		.data_start = DATA_REGION_START,
	};

	int rc = fseek(fp, SUPERBLOCK_START, SEEK_SET);
	if (rc != 0) {
		perror("fseek");
		return false;
	}

	if (fwrite(&superblock, sizeof(superblock), 1, fp) != 1) {
		perror("fwrite");
		return false;
	}

	return true;
}

bool diskimg_write(char *filepath, BUF(DiskInode *inodes), BUF(DiskImgEntry *entries)) {
	U32 num_data_blocks = 0;

	FILE *fp = fopen(filepath, "wb");
	int rc = fseek(fp, KILOBYTES(16656) - 1, SEEK_SET);
	if (rc != 0) {
		perror("fseek");
		return false;
	}
	U8 zero = 0;
	size_t b = fwrite(&zero, sizeof(zero), 1, fp);
	if (b != 1) {
		fprintf(stderr, "fwrite: expected to write 1 byte, but wrote %zu bytes\n", b);
		return false;
	}
	rc = fseek(fp, 0, SEEK_SET);
	if (rc != 0) {
		perror("fseek");
		return false;
	}

	diskimg_write_inode_bitmap(fp, buf_len(inodes));

	// for (int i=0; i<buf_len(entries); ++i) {
		// DiskImgEntry *entry = &entries[i];
		// U32 blocks_written = 0;
		// if (entry->inode_type == INODE_DIR) {
			// blocks_written = diskimg_write_dir(fp, entry);
		// } else {
			// blocks_written = diskimg_write_file(fp, entry);
		// }
		// num_data_blocks += blocks_written;
	// }

	diskimg_write_superblock(fp, buf_len(inodes), num_data_blocks);

	// write inode bitmap (however many inodes, write than many 1s)
	// write inode table (types and sizes, addrs will be filled in later)

	// for each DiskImgEntry:
	// if dir: write_dir()
	// if file: write_file()
	// increment num_data_blocks by how many written
	
	// write superblock

	fclose(fp);
	return num_data_blocks;
}

int main(int argc, char **argv) {
	if (argc < 2) {
		printf("Usage: %s directory_path\n", argv[0]);
		exit(1);
	}

	char *dir_path = argv[1];

	// make empty entries in inodes up to ROOT_INODE_NUM, to allow directly indexing 
	// (in our case its just 1 dummy entry)
	for (int i=0; i<ROOT_INODE_NUM; ++i) {
		buf_push(inodes, (DiskInode){0});
	}

	U32 root_inode_num = traverse_dir(dir_path, ROOT_INODE_NUM);
	assert(root_inode_num == ROOT_INODE_NUM);

	U32 blocks_written = diskimg_write("disk.img", inodes, entries);
	// assert(blocks_written > 0);
}

