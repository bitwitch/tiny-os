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

#define PATH_MAX                   256
#define ROOT_INODE_NUM             1    // zero is reserved for a non-existent file
#define INODE_NUM_DIRECT_POINTERS  12
#define SYS_OPEN_FILES_MAX         128
#define PROC_OPEN_FILES_MAX        32
#define DISK_DIR_ENTRY_MIN         12
#define DISK_BLOCK_SIZE            KILOBYTES(4)
#define SUPERBLOCK_START           KILOBYTES(4)
#define FILE_SIZE_MAX              (INODE_NUM_DIRECT_POINTERS * DISK_BLOCK_SIZE)
#define FILES_MAX                  DISK_BLOCK_SIZE
#define VSFS_MAGIC                 0x73667376   // "vsfs"


enum {
	INODE_NONE,
	INODE_DIR,
	INODE_FILE,
};

typedef struct {
	U32 type;
	U32 num_addrs;
	U32 size;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
	U8 pad[48];
} Inode;

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
	U16 name_size_with_padding; // size of name plus any empty space, this is used so that new files can reuse old space
	U16 name_size;  // including null-terminator
	char name[];
} DirLink;

typedef struct {
	U32 inode_num;
	U32 ref_count;
	U32 size;
	U32 offset;
} File;


