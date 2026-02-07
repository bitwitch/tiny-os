#include "common.h"
#include "user.h"

extern char __stack_top[];
int errno;

S32 syscall(S32 syscall_num, S32 arg0, S32 arg1, S32 arg2) {
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

int open(char *path, U32 flags, U32 mode) {
	int result = syscall(SYSCALL_OPEN, (U32)path, flags, mode);
	if (result < 0) {
		errno = -result;
		return -1;
	}
	return result;
}

int read(int fd, void *buf, U32 size) {
	int result = syscall(SYSCALL_READ, (U32)fd, (U32)buf, size);
	if (result < 0) {
		errno = -result;
		return -1;
	}
	return result;
}


int cwd(char *buf, U32 size) {
	int result = syscall(SYSCALL_CWD, (U32)buf, size, 0);
	if (result < 0) {
		// errno = -result;
		return -1;
	}
	return result;
}

// DirHandle *open_dir(char *path) {
	// U32 fd = (U32)syscall(SYSCALL_OPEN, path, 0, 0);

	// // TODO: check if path is a valid dir

	// DirHandle *handle = malloc(sizeof(*handle));
	// *handle = (DirHandle){
		// .fd = fd,
		// .offset = 0
	// }

	// return handle;
// }

// DirEntry read_dir(DirHandle *handle) {
	// // get the next entry in the directory pointed to by handle	
	// //
// }





/*
Heap Block Header
-----------------------------
31                     2|1|0|
+---------------------------+   
|      block size       |0|a|   a=1: allocated
+---------------------------+   a=0: free
|                           | 
|         payload           |
|                           |
+---------------------------+
|      padding (maybe)      |
+---------------------------+


32 bit header, the high 30 bits encode block size (always 4 byte aligned so low 2 bits would be 0)
the least significant bit is the "allocated bit", 0 means free
*/

#define HEADER_SIZE sizeof(U32)

#define HDR_GET_SIZE(hp)          ((*(U32*)(hp)) & ~0x3)
#define HDR_GET_ALLOCATED(hp)     ((*(U32*)(hp)) & 1)
#define HDR_PACK(size, allocated) (((size) & ~1) | allocated)

#define HDR_PTR(bp)                    (U8*)(bp) - HEADER_SIZE
#define BLK_GET_SIZE(bp)               (HDR_GET_SIZE(HDR_PTR(bp)))
#define BLK_GET_ALLOCATED(bp)          (HDR_GET_ALLOCATED(HDR_PTR(bp)))
#define HDR_WRITE(bp, size, allocated) (*(U32*)(HDR_PTR(bp))) = HDR_PACK((size), allocated)
#define NEXT_BLKP(bp)                  (HDR_GET_SIZE(HDR_PTR(bp)) + ((U8*)(bp)))


static struct {
	bool initialized;
	U32 num_pages;
	U8 *heap;      // pointer to one header size after prologue block
} malloc_state;

/*
  Prologue block is a special block at start of heap, it is created during init and never freed
  Epilogue block is a special block at end of heap, it has zero-size and is marked "allocated" 
*/

void malloc_init(U32 size) {
	malloc_state.initialized = true;
	U32 num_pages = size ? align_up(size, PAGE_SIZE) / PAGE_SIZE : 1;
	U8 *new_memory = (U8*)syscall(SYSCALL_GETPAGES, num_pages, 0, 0);
	malloc_state.num_pages = num_pages;
	malloc_state.heap = new_memory + HEADER_SIZE;

	U8 *bp = malloc_state.heap;

	// setup prologue block
	HDR_WRITE(bp, 4, 1);
	bp = NEXT_BLKP(bp);

	// setup first regular block
	U32 first_block_size = (num_pages * PAGE_SIZE) - (2 * HEADER_SIZE);
	HDR_WRITE(bp, first_block_size, 0);
	bp = NEXT_BLKP(bp);

	// setup epilogue block
	HDR_WRITE(bp, 0, 1);
}

void dump_heap(void) {
	U8 *heap_end = HDR_PTR(malloc_state.heap) + malloc_state.num_pages * PAGE_SIZE;
	U8 *bp = malloc_state.heap;
	printf("\n----------------------------------------------------------------\nHeap\n\n");
	for (; bp <= heap_end; bp = NEXT_BLKP(bp)) {
		printf("bp=%x, size=%u, allocated=%u\n", bp, BLK_GET_SIZE(bp), BLK_GET_ALLOCATED(bp));
		if (BLK_GET_SIZE(bp) == 0 && BLK_GET_ALLOCATED(bp) == 1) break;
		assert(BLK_GET_SIZE(bp) > 0);
	}
	printf("----------------------------------------------------------------\n\n");
}

U8 *malloc_find_fit(U32 size) {
	U8 *heap_end = HDR_PTR(malloc_state.heap) + malloc_state.num_pages * PAGE_SIZE;
	U8 *bp = NEXT_BLKP(malloc_state.heap); // skip prologue block, start at first regular block
	for (; bp <= heap_end; bp = NEXT_BLKP(bp)) {
		if (!BLK_GET_ALLOCATED(bp) && (BLK_GET_SIZE(bp) >= size)) return bp;
		if (BLK_GET_SIZE(bp) == 0 && BLK_GET_ALLOCATED(bp) == 1) return NULL;
	}

	// UNREACHABLE
	assert(0 && "Unreachable");
	return NULL;
}

// split the block into an allocated block of size and a free block of remainder size
void malloc_place_block(U8 *bp, U32 size) {
	U32 old_size = BLK_GET_SIZE(bp);
	HDR_WRITE(bp, size, 1);
	bp = NEXT_BLKP(bp);
	if (old_size > size) {
		HDR_WRITE(bp, old_size - size, 0);
	}
}

void *malloc(U32 size) {
	if (!size) return NULL;
	
	size = align_up(size + HEADER_SIZE, 4);

	if (!malloc_state.initialized) {
		malloc_init(size);
	}

	U8* bp = malloc_find_fit(size);

	if (!bp) {
		U32 num_pages = align_up(size, PAGE_SIZE) / PAGE_SIZE;
		U8 *new_block = (U8*)syscall(SYSCALL_GETPAGES, num_pages, 0, 0);
		malloc_state.num_pages += num_pages;

		// overwrite epilogue header with new free block
		// NOTE(shaw): we don't have to subtract the epilogue header from the new block size here, 
		// because the header for the new block is replacing the old epilogue header which actually 
		// lives in the previous page in the heap
		HDR_WRITE(new_block, num_pages * PAGE_SIZE, 0);

		// write epilogue
		U8* epilogue = NEXT_BLKP(new_block);
		HDR_WRITE(epilogue, 0, 1);

		bp = new_block;
	} 

	malloc_place_block(bp, size);

	dump_heap();
	return bp;
}


void free(void *p) {
	if (!p) return;
	U32 size = BLK_GET_SIZE(p);
	HDR_WRITE(p, size, 0);
	// TODO(shaw): coalesce free blocks
}

void *realloc(void *ptr, U32 new_size) {
	if (!ptr) {
		return malloc(new_size);
	}

	U32 new_block_size = align_up(new_size + HEADER_SIZE, 4);

	if (!malloc_state.initialized) {
		malloc_init(new_block_size);
	}
	
	U8 *bp = ptr;

	U32 old_block_size = BLK_GET_SIZE(ptr);
	if (new_block_size > old_block_size) {
		bp = malloc(new_size);
		memcpy(bp, ptr, old_block_size - HEADER_SIZE);
		HDR_WRITE(ptr, old_block_size, 0);

	}  else if (new_block_size < old_block_size) {
		HDR_WRITE(bp, new_block_size, 1);
		bp = NEXT_BLKP(bp);
		HDR_WRITE(bp, old_block_size - new_block_size, 0);
	}

	return bp;
}


__attribute__((noreturn)) 
void exit(int code) {
	syscall(SYSCALL_EXIT, code, 0, 0);
	//
	// TODO: release resources such as memory and open files
	// 
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
