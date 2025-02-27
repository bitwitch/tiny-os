#include "../filesystem.h"

typedef struct {
	U32 inode_num;
	U32 entry_size; // size of name plus any empty space, this is used so that new files can reuse old space
	U32 name_size;  // including null-terminator
	char *name;
} DiskDirEntry;

typedef struct {
	DiskDirEntry *entries;
	U32 num_entries;
} DiskDir;

typedef struct {
	int inode_type;
	U32 inode_num;
	char *path;       // for file
	DiskDir dir_data; // for dir
} DiskImgEntry;

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

U32 traverse_dir(char *path, U32 parent_inode_num, BUF(DiskInode *inodes), BUF(DiskImgEntry *entries)) {
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
		// insert new DiskDirEntry into DiskDir
	// insert a new DiskImgEntry into entries for this dir
	return inode_num;
}

bool write_disk_image(BUF(DiskInode *inodes), BUF(DiskImgEntry *entries)) {
	U32 num_data_blocks = 0;

	// write inode bitmap (however many inodes, write than many 1s)
	// write inode table (types and sizes, addrs will be filled in later)

	// for each filesystem entry:
	// if dir: write_dir()
	// if file: write_file()
	// increment num_data_blocks by how many written
	
	// write superblock
}

U32 diskimg_write_dir(DiskImgEntry *dir) {
	U32 blocks_written = 0;
	// while not all data written
		// find first empty data block in data_bitmap, mark as in use
		// write dir data to data region
		// write block addr to inode table
	return blocks_written;
}

U32 diskimg_write_file(DiskImgEntry *file) {
	U32 blocks_written = 0;
	// open file
	// while not all data written
		// find first empty data block in data_bitmap, mark as in use
		// write dir data to data region
		// write block addr to inode table
	// close file
	return blocks_written;
}

int main(int argc, char **argv) {
	char *dir_path = argv[1];

	BUF(DiskInode *inodes) = NULL;
	// make empty entries in inodes up to ROOT_INODE_NUM, to allow directly indexing 
	// (in our case its just 1 dummy entry)

	BUF(DiskImgEntry *entries) = NULL;

	U32 root_inode_num = traverse_dir(dir_path, ROOT_INODE_NUM, inodes, entries);
	assert(root_inode_num == ROOT_INODE_NUM);

	write_disk_image(inodes, entries);
}


