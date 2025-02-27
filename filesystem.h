#pragma once
#include "common.h"

/*
Implementation of vsfs:

block size:          4KB
inode on disk:       64 bytes each
max inodes:          4096
bitmap size:         4KB (one block)
inode table size:    256KB (64 blocks)
data region size:    16MB (4096 blocks)
  __________________________________________________________________________________
 |       |       |        |        |           |                                    |
 | boot  | super | inode  |  data  |   inode   |                data                |
 | block | block | bitmap | bitmap |   table   |               region               |
 |_______|_______|________|________|___________|____________________________________|
0KB     4KB     8KB      12KB     16KB        272KB                              16656KB
*/

#define ROOT_INODE_NUM             1    // zero is reserved for a non-existent file
#define INODE_NUM_DIRECT_POINTERS  12
#define SYS_OPEN_FILES_MAX         128
#define PROC_OPEN_FILES_MAX        32
#define DISK_DIR_ENTRY_MIN         12

enum {
	INODE_NONE,
	INODE_DIR,
	INODE_FILE,
};

typedef struct {
	int type;
	U32 size_in_bytes;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
} DiskInode;

typedef struct {
	U32 inode_num;
	// TODO: some kind of lock for synchronization
	bool valid;

	// copy of on disk inode
	int type;
	U32 size_in_bytes;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
} Inode;

typedef struct {
  U32 magic;         // Must be "vsfs"
  U32 size_in_blocks; 
  U32 num_data_blocks;
  U32 num_inodes;    
  U32 inode_start;   // Block number of first inode block
  U32 data_start;    // Block number of first data block
} Superblock;

struct {
	// TODO: a lock here
	File files[SYS_OPEN_FILES_MAX];
} file_table;

