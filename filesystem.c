#define INODE_NUM_DIRECT_POINTERS  12
#define INODES_ACTIVE_MAX          64
#define PROC_OPEN_FILES_MAX        32

typedef struct {
	int type;
	U32 size;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
} DiskInode;

typedef struct {
	U32 inode_num;
	// TODO: some kind of lock for synchronization
	bool valid;

	// copy of on disk inode
	int type; 
	U32 size;
	U32 addrs[INODE_NUM_DIRECT_POINTERS];
} Inode;

typedef struct {
  U32 magic;         // Must be "VSFS"
  U32 size_in_blocks;
  U32 num_data_blocks;
  U32 num_inodes;    
  U32 inode_start;   // Block number of first inode block
  U32 data_start;    // Block number of first data block
} Superblock;

struct {
	// TODO: a lock here
	Inode files[INODES_ACTIVE_MAX];
} file_table;

