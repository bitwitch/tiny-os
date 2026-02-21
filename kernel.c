#include "common.h"
#include "filesystem.h"
#include "kernel.h"

// kernel "modules" split into other files just for code organization
#include "slab.c"
#include "arena.c"
#include "dcache.c"

U32 virtio_reg_read32(U32 offset) {
    return *((volatile U32 *) (VIRTIO_BLK_PADDR + offset));
}

U64 virtio_reg_read64(U32 offset) {
    return *((volatile U64 *) (VIRTIO_BLK_PADDR + offset));
}

void virtio_reg_write32(U32 offset, U32 value) {
    *((volatile U32 *) (VIRTIO_BLK_PADDR + offset)) = value;
}

void virtio_reg_fetch_and_or32(U32 offset, U32 value) {
    virtio_reg_write32(offset, virtio_reg_read32(offset) | value);
}

// see legacy interface virtq configuration in spec:
// https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-1560004
Virtq *virtq_init(int index) {
	virtio_reg_write32(VIRTIO_REG_GUEST_PAGE_SIZE, PAGE_SIZE);

	virtio_reg_write32(VIRTIO_REG_QUEUE_SEL, index); 

	if (virtio_reg_read32(VIRTIO_REG_QUEUE_PFN) != 0) {
		// queue already in use
		printf("error: failed to initialize virtqueue %d: already in use\n", index);
		return NULL;
	}

	U32 queue_num_max = virtio_reg_read32(VIRTIO_REG_QUEUE_NUM_MAX);
	if (queue_num_max == 0) {
		printf("error: failed to initialize virtqueue %d: not available\n", index);
		return NULL;
	}

	if (VIRTQ_MAX_ENTRIES > queue_num_max) {
		printf("warning: virtio-blk device has a max queue size of %d, but the driver is using a queue size of %d\n",
			queue_num_max, VIRTQ_MAX_ENTRIES);
	}

	U32 num_pages = align_up(sizeof(Virtq), PAGE_SIZE) / PAGE_SIZE;
	Paddr paddr = alloc_pages(num_pages);

	virtio_reg_write32(VIRTIO_REG_QUEUE_NUM, VIRTQ_MAX_ENTRIES);
	virtio_reg_write32(VIRTIO_REG_QUEUE_ALIGN, PAGE_SIZE);
	virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, paddr / PAGE_SIZE);

	Virtq *virtq = (Virtq*)paddr;
	virtq->queue_index = index;
	virtq->used_index_ptr = (volatile U16*)&virtq->used.index;

	return virtq;
}

// see https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-910003
void virtio_blk_init(void) {
	U32 magic = virtio_reg_read32(VIRTIO_REG_MAGIC);
	if (magic != VIRTIO_MAGIC)
		PANIC("virtio: invalid magic value: %x", magic);

	U32 virtio_version = virtio_reg_read32(VIRTIO_REG_VERSION);
	if (virtio_version != 1)
		PANIC("virtio: invalid version: %u", virtio_version);

	U32 device_id = virtio_reg_read32(VIRTIO_REG_DEVICE_ID);
	if (device_id != VIRTIO_DEVICE_BLK)
		PANIC("virtio: invalid device id: %u", device_id);

	virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, 0); // reset the device
	virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_ACK);
	virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER);

	// TODO(shaw);
	// Read device feature bits, and write the subset of feature bits
	// understood by the OS and driver to the device. During this step the
	// driver MAY read (but MUST NOT write) the device-specific configuration
	// fields to check that it can support the device before accepting it.

	virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_FEATS_OK); 

	U32 device_status = virtio_reg_read32(VIRTIO_REG_DEVICE_STATUS);
	if ((device_status & VIRTIO_STATUS_FEATS_OK) == 0) {
		PANIC("virtio: virtio-blk device does not support the driver's subset of features");
	}
	
	virtio_blk_virtq = virtq_init(0);
	if (virtio_blk_virtq == NULL) {
		PANIC("virtio: failed to initialize virtqueue");
	}

	virtio_reg_write32(VIRTIO_REG_DEVICE_STATUS, VIRTIO_STATUS_DRIVER_OK);

	// see https://docs.oasis-open.org/virtio/virtio/v1.1/csprd01/virtio-v1.1-csprd01.html#x1-2440004
	// for device configuration layout
	virtio_blk_num_sectors = virtio_reg_read64(VIRTIO_REG_DEVICE_CONFIG + 0);

	printf("virtio-blk device initialized\n");
}

void virtq_kick(Virtq *vq, int desc_head_index) {
	vq->avail.ring[vq->avail.index % VIRTQ_MAX_ENTRIES] = desc_head_index;
	++vq->avail.index;
	__sync_synchronize();
	virtio_reg_write32(VIRTIO_REG_QUEUE_NOTIFY, vq->queue_index);
	++vq->last_used_index;
}

bool virtq_is_busy(Virtq *vq) {
	return vq->last_used_index != *vq->used_index_ptr;
}

bool virtio_blk_read_write_sector(void *buf, U64 sector, bool is_write) {
	if (sector >= virtio_blk_num_sectors) {
		printf("virtio: tried to %s sector %d, but virtio-blk device only contains %d sectors\n",
				is_write ? "write" : "read", (U32)sector, (U32)virtio_blk_num_sectors);
		return false;
	}

	VirtioBlkRequest req = {0};
	req.type = is_write ? VIRTIO_BLK_T_OUT : VIRTIO_BLK_T_IN;
	req.sector = sector;

	if (is_write) memcpy(req.data, buf, SECTOR_SIZE);

	Virtq *vq = virtio_blk_virtq;
	U64 req_addr = (U64)&req;
	vq->descs[0].addr  = req_addr;
	vq->descs[0].len   = sizeof(U32) * 2 + sizeof(U64);
	vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
	vq->descs[0].next  = 1;

	vq->descs[1].addr  = req_addr + offsetof(VirtioBlkRequest, data);
	vq->descs[1].len   = SECTOR_SIZE;
	// confusingly, if this is a read we set VIRTQ_DESC_F_WRITE, because we are setting the buffer as DEVICE writable
	vq->descs[1].flags = VIRTQ_DESC_F_NEXT | (is_write ? 0 : VIRTQ_DESC_F_WRITE); 
	vq->descs[1].next  = 2;

	vq->descs[2].addr  = req_addr + offsetof(VirtioBlkRequest, status);
	vq->descs[2].len   = sizeof(U8);
	vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

	virtq_kick(vq, 0);

	while (virtq_is_busy(vq));

	if (req.status != 0) {
		printf("virtio: failed to read sector=%d status=%d\n", sector, req.status);
		return false;
	}

	if (!is_write) memcpy(buf, req.data, SECTOR_SIZE);

	return true;
}

inline bool virtio_blk_read_sector(void *buf, U64 sector) {
	return virtio_blk_read_write_sector(buf, sector, false);
}

inline bool virtio_blk_write_sector(void *buf, U64 sector) {
	return virtio_blk_read_write_sector(buf, sector, true);
}

bool disk_read_block(void *buf, U32 block) {
	KERNEL_ASSERT(DISK_BLOCK_SIZE % SECTOR_SIZE == 0, "");
	U32 sectors_per_block = DISK_BLOCK_SIZE / SECTOR_SIZE;
	U32 sector_start = block * sectors_per_block;
	for (U32 i=0; i<sectors_per_block; ++i) {
		if (!virtio_blk_read_sector(buf + i * SECTOR_SIZE, sector_start + i)) return false;
	}
	return true;
}

U32 u32_from_octal(char *oct, int len) {
	int dec = 0;
	for (int i=0; i<len; ++i) {
		if (oct[i] < '0' || oct[i] > '7')
			break;
		dec = dec * 8 + (oct[i] - '0');
	}
	return dec;
}

U32 pow_u32(U32 base, U32 power) {
	U32 result = 1;
	for (U32 i=0; i<power; ++i) {
		result *= base;
	}
	return result;
}

void octal_from_u32(U32 u32, char *oct, int len) {
	int power;
	for (power = 0; (u32/pow_u32(8, power+1)) > 0; ++power);
	if (power > len - 1) {
		PANIC("octal_from_32: u32=%u will not fit in octal string with length %d", u32, len);
	}

	memset(oct, '0', len);
	for (; power >= 0; --power) {
		int i = len - 1 - power - 1;
		U32 divisor = pow_u32(8, power);
		oct[i] = (char)(u32 / divisor + '0');
		u32 %= divisor;
	}
	oct[len-1] = 0;
}


void filesystem_init(void) {
	// read superblock into memory
	// verify magic and size_in_blocks
	// ?? make sure device size is enough for size_in_blocks ??
	// ?? make sure num_inodes is <= max inodes (FILES_MAX) ??

	U32 device_size = virtio_blk_num_sectors * SECTOR_SIZE;

	U32 superblock_block_id = SUPERBLOCK_START / DISK_BLOCK_SIZE;
	if (!disk_read_block(&superblock, superblock_block_id)) {
		PANIC("failed to initialize filesystem: failed to read superblock");
	}

	if (superblock.magic != VSFS_MAGIC) {
		PANIC("invalid magic number for filesystem: %x (\"%c%c%c%c\")", superblock.magic, 
			((char*)&superblock.magic)[0],
			((char*)&superblock.magic)[1],
			((char*)&superblock.magic)[2],
			((char*)&superblock.magic)[3]);
	}

	U32 disk_img_size = superblock.size_in_blocks * DISK_BLOCK_SIZE;
	if (disk_img_size > device_size) {
		printf("Warning: virtio-blk device size is %u, but disk image size is %u.\n", device_size, disk_img_size); 
	}

	if (superblock.num_inodes > FILES_MAX) {
		printf("Warning: filesystem only supports %u files, but superblock in disk image reports %u files.\n", FILES_MAX, superblock.num_inodes);
	}

	U32 inode_table_first_block = INODE_TABLE_START / DISK_BLOCK_SIZE;
	U32 inodes_per_block = DISK_BLOCK_SIZE / sizeof(Inode);
	U32 inode_table_size_in_blocks = 64;
	for (U32 i=0; i<inode_table_size_in_blocks; ++i) {
		if (!disk_read_block(inodes + i * inodes_per_block, inode_table_first_block + i)) {
			PANIC("failed to initialize filesystem: failed to read inode table");
		}
	}
	
	// initialize the root DcacheEntry in dcache
	Inode *root_inode = &inodes[ROOT_INODE_NUM];
	if (!root_inode) {
		PANIC("failed to initialize filesystem: failed to locate root inode");
	}

	DcacheEntry *root_dir_entry = dcache_create_entry(root_inode, NULL, "/");
	KERNEL_ASSERT(root_dir_entry != NULL, "failed to create dcache entry for filesystem root");
	root_dir_entry->ref_count = INT32_MAX;
	dcache_put(&dcache, root_dir_entry);

	printf("filesystem initialized\n");
}

// void filesystem_flush(void) {
	// // write all files into tar format in "disk"
	// U32 off = 0;
	// U8 *disk_end = disk;
	// for (int i=0; i<FILES_MAX; ++i) {
		// File *f = &files[i];
		// if (f->in_use) {
			// TarHeader h = {0};
			// strcpy(h.name, f->name);
			// strcpy(h.mode, "000644");
			// octal_from_u32(f->size, h.size, sizeof(h.size));

			// h.type = '0';
			// strcpy(h.magic, "ustar");
			// strcpy(h.version, "00");

			// // calculate checksum
			// U32 checksum = 0;
			// for (U32 i=0; i < sizeof(h); ++i) {
				// checksum += *((U8*)(&h + i));
			// }
			// // with the eight checksum bytes taken to be ASCII spaces (decimal value 32)
			// checksum += 8 * 32;
			// octal_from_u32(checksum, h.checksum, 7);
			// h.checksum[7] = ' ';

			// U32 file_size_aligned = align_up(f->size, SECTOR_SIZE);
			// disk_end = disk + off + offsetof(TarHeader, data) + file_size_aligned;
			// if ((U32)(disk_end - disk) > DISK_SIZE_MAX) {
				// PANIC("not enough space in disk, max disk size is %d", (int)DISK_SIZE_MAX);
			// }

			// memcpy(disk + off, &h, sizeof(h));
			// memcpy(disk + off + offsetof(TarHeader, data), f->data, f->size);

			// U8 *start_zeros = disk + off + offsetof(TarHeader, data) + f->size;
			// U32 zeros_size = (U32)(disk_end - start_zeros);
			// memset(start_zeros, 0, zeros_size);

			// off = (U32)(disk_end - disk);
		// }
	// }

	// // write in memory disk out to virtio-blk device
	// U64 num_sectors = align_up((U32)(disk_end - disk), SECTOR_SIZE) / SECTOR_SIZE;
	// U64 sector = 0;
	// for (sector=0; sector < num_sectors; ++sector) {
		// virtio_blk_write_sector(disk + sector * SECTOR_SIZE, sector);
	// }

	// // fill the rest with 0s
	// U8 zero_sector[SECTOR_SIZE] = {0};
	// for (; sector < virtio_blk_num_sectors; ++sector) {
		// virtio_blk_write_sector(zero_sector, sector);
	// }
// }

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

int getchar(void) {
	long eid = 2; // Console Getchar
	SBI_Ret ret = sbi_call(0, 0, 0, 0, 0, 0, 0, eid);

	// NOTE(shaw): error is used here because getchar is a legacy extension in sbi, 
	// so it follows a different calling convention than most other sbi functions
	return (int)ret.error;
}

typedef struct FreePage FreePage;
struct FreePage {
	FreePage *prev;
	FreePage *next;
	U32 num_contiguous_pages;
};

static FreePage *free_page_list;

Paddr alloc_pages(U32 n) {
	// first check free list for n free pages
	bool found_free_page = false;
	Paddr result = 0;
	for (FreePage *free_page = free_page_list; free_page; free_page = free_page->next) {
		if (free_page->num_contiguous_pages > n) {
			// split free pages chunk in free list
			result = (Paddr)((U8*)free_page + (free_page->num_contiguous_pages - n) * PAGE_SIZE);
			free_page->num_contiguous_pages -= n;
			found_free_page = true;
			break;
		} else if (free_page->num_contiguous_pages == n) {
			// remove from free list
			if (free_page->prev) free_page->prev->next = free_page->next;
			if (free_page->next) free_page->next->prev = free_page->prev;
			result = (Paddr)free_page;
			found_free_page = true;
			break;
		}
	}
	
	U32 size = n * PAGE_SIZE;
	if (!found_free_page) {
		if (free_ram_cursor + size > (U32)__free_ram_end) {
			PANIC("out of memory, requested %d pages", n);
		}
		result = free_ram_cursor;
		free_ram_cursor += size;
	}

	memset((void*)result, 0, size);
	return result;
}

void free_pages(Paddr paddr, U32 n) {
	FreePage *freed = (FreePage*)paddr;
	freed->num_contiguous_pages = n;
	freed->prev = NULL;
	freed->next = free_page_list;
	if (free_page_list) free_page_list->prev = freed;
	free_page_list = freed;
}

void map_page(U32 *table1, Vaddr vaddr, Paddr paddr, U32 flags) {
	if (!is_aligned(vaddr, PAGE_SIZE)) PANIC("unaligned vaddr %x", vaddr);
	if (!is_aligned(paddr, PAGE_SIZE)) PANIC("unaligned paddr %x", paddr);

	U32 t1_index = (vaddr & VADDR_PAGE_LEVEL1_MASK) >> VADDR_PAGE_LEVEL1_SHIFT;
	if ((table1[t1_index] & PAGE_V) == 0) {
		// create level 0 page table if it doesn't exist yet
		Paddr table0 = alloc_pages(1);
		U32 t0_page_num = table0 / PAGE_SIZE;
		table1[t1_index] = (t0_page_num << PTE_PAGE_NUMBER_SHIFT) | PAGE_V;
	}

	U32 t0_page_num = (table1[t1_index] & PTE_PAGE_NUMBER_MASK) >> PTE_PAGE_NUMBER_SHIFT;
	U32 *table0 = (U32*)(t0_page_num * PAGE_SIZE);
	U32 t0_index = (vaddr & VADDR_PAGE_LEVEL0_MASK) >> VADDR_PAGE_LEVEL0_SHIFT;
	U32 physical_page_num = paddr / PAGE_SIZE;
	table0[t0_index] = (physical_page_num << PTE_PAGE_NUMBER_SHIFT) | flags | PAGE_V;
}

__attribute__((naked))
void user_entry(void) {
	__asm__ __volatile__(
		"csrw sepc, %[user_base]\n"   // set location for sret to jump to
		"csrw sstatus, %[sstatus]\n"  // enable hardware interrupts when entering U-Mode
		"sret\n"
		:
		: [user_base] "r" (USER_BASE),
		  [sstatus]   "r" (SSTATUS_SPIE)
	);
}

Process *create_process(void *image, U32 image_size) {
	Process *p = NULL;
	int pid;
	for (pid=0; pid<PROCS_MAX; ++pid) {
		if (procs[pid].state == PROC_UNUSED) {
			p = &procs[pid];
			break;
		}
	}

	if (!p) {
		PANIC("unable to spawn another process, max %d processes reached", PROCS_MAX);
	}

	// put callee saved registers on the stack, because the first time this process is 
	// entered a context switch happens popping these registers off the process's stack
	U32 *sp = (U32*)&p->stack[sizeof(p->stack)];
	*--sp = 0;               // s11
	*--sp = 0;               // s10
	*--sp = 0;               // s9
	*--sp = 0;               // s8
	*--sp = 0;               // s7
	*--sp = 0;               // s6
	*--sp = 0;               // s5
	*--sp = 0;               // s4
	*--sp = 0;               // s3
	*--sp = 0;               // s2
	*--sp = 0;               // s1
	*--sp = 0;               // s0
	*--sp = (U32)user_entry; // ra

	// map kernel pages
	U32 *page_table = (U32*)alloc_pages(1);
	for (Paddr paddr = (Paddr)__kernel_base; paddr < (Paddr)__free_ram_end; paddr += PAGE_SIZE) {
		map_page(page_table, paddr, paddr, PAGE_R|PAGE_W|PAGE_X);
	}

	// map virtio-blk device mmio region
	map_page(page_table, VIRTIO_BLK_PADDR, VIRTIO_BLK_PADDR, PAGE_R|PAGE_W);

	// map user pages
	U32 offset;
	for (offset=0; offset < image_size; offset += PAGE_SIZE) {
		U32 remaining = image_size - offset;
		U32 copy_size = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;

		Paddr page = alloc_pages(1);
		memcpy((void*)page, image + offset, copy_size);

		map_page(page_table, USER_BASE + offset, page, PAGE_U|PAGE_R|PAGE_W|PAGE_X);
	}
	
	p->pid = pid;
	p->state = PROC_RUNNABLE;
	p->sp = (Vaddr)sp;
	p->heap_start = USER_BASE + offset;
	p->heap_end = p->heap_start;
	p->working_directory = dcache_lookup(&dcache, "/");
	p->page_table = page_table;
	p->num_fds = 3; // reserve 3 fds for stdin, stdout, stderr

	if (!p->working_directory) {
		PANIC("failed to create process, root dir entry not found in dcache");
	}

	return p;
}

__attribute__((naked)) 
void switch_context(U32 *prev_sp, U32 *next_sp) {
	__asm__ __volatile__(
		"addi sp, sp, -13 * 4\n" // Allocate stack space for 13 4-byte registers

		// Save callee-saved registers onto the current process's stack.
		"sw ra,  0  * 4(sp)\n"   
		"sw s0,  1  * 4(sp)\n"
		"sw s1,  2  * 4(sp)\n"
		"sw s2,  3  * 4(sp)\n"
		"sw s3,  4  * 4(sp)\n"
		"sw s4,  5  * 4(sp)\n"
		"sw s5,  6  * 4(sp)\n"
		"sw s6,  7  * 4(sp)\n"
		"sw s7,  8  * 4(sp)\n"
		"sw s8,  9  * 4(sp)\n"
		"sw s9,  10 * 4(sp)\n"
		"sw s10, 11 * 4(sp)\n"
		"sw s11, 12 * 4(sp)\n"

		// Switch the stack pointer.
		// this only works assuming prev_sp is the stack pointer of the current process
		"sw sp, (a0)\n"         // *prev_sp = sp;
		"lw sp, (a1)\n"         // sp = *next_sp

		// Restore callee-saved registers from the next process's stack.
		"lw ra,  0  * 4(sp)\n"  
		"lw s0,  1  * 4(sp)\n"
		"lw s1,  2  * 4(sp)\n"
		"lw s2,  3  * 4(sp)\n"
		"lw s3,  4  * 4(sp)\n"
		"lw s4,  5  * 4(sp)\n"
		"lw s5,  6  * 4(sp)\n"
		"lw s6,  7  * 4(sp)\n"
		"lw s7,  8  * 4(sp)\n"
		"lw s8,  9  * 4(sp)\n"
		"lw s9,  10 * 4(sp)\n"
		"lw s10, 11 * 4(sp)\n"
		"lw s11, 12 * 4(sp)\n"

		"addi sp, sp, 13 * 4\n"  // We've popped 13 4-byte registers from the stack
		"ret\n"
	);
}

void yield(void) {
	Process *next = &idle_proc;
	for (int i=0; i<PROCS_MAX; ++i) {
		Process *p = &procs[(current_proc->pid + 1 + i) % PROCS_MAX];
		if (p->state == PROC_RUNNABLE) {
			next = p;
			break;
		}
	}

	if (next != current_proc) {
		if (next != &idle_proc) {
			__asm__ __volatile__(
				// enable paging, and set the page number where the level1 page table lives for this process
				"sfence.vma\n"
				"csrw satp, %[satp]\n"
				"sfence.vma\n"
				// save the next procs stack top in sscratch, this enables the exception
				// handler to have a stable reference to this procs stack, in the case that sp
				// is corrupted
				"csrw sscratch, %[stack_top]\n"
				:
				: [satp]      "r" (SATP_SV32 | ((U32)next->page_table / PAGE_SIZE)),
				  [stack_top] "r" ((U32)&next->stack[sizeof(next->stack)])
			);
		}
		Process *prev = current_proc;
		current_proc = next;
		switch_context(&prev->sp, &next->sp);
	}
}

void proc_back_vaddr_with_physical_page(Vaddr vaddr) {
	// currently assuming this is a process accessing memory in its heap for the first time
	KERNEL_ASSERT(vaddr >= current_proc->heap_start && vaddr < current_proc->heap_end, 
		"heap_start=%x, heap_end=%x, vaddr=%x", current_proc->heap_start, current_proc->heap_end, vaddr);

	Vaddr page_start = (vaddr % PAGE_SIZE) == 0 ? vaddr : align_up(vaddr, PAGE_SIZE) - PAGE_SIZE;
	Paddr new_page = alloc_pages(1);
	map_page(current_proc->page_table, page_start, new_page, PAGE_U|PAGE_R|PAGE_W|PAGE_X);
}

bool proc_is_first_access(Vaddr vaddr) {
	// check if level 1 PTE is valid
	U32 t1_index = (vaddr & VADDR_PAGE_LEVEL1_MASK) >> VADDR_PAGE_LEVEL1_SHIFT;
	U32 *table1 = current_proc->page_table;
	if ((table1[t1_index] & PAGE_V) == 0) {
		return true;
	} 

	// check if level 0 PTE is valid
	U32 t0_page_num = (table1[t1_index] & PTE_PAGE_NUMBER_MASK) >> PTE_PAGE_NUMBER_SHIFT;
	U32 *table0 = (U32*)(t0_page_num * PAGE_SIZE);
	U32 t0_index = (vaddr & VADDR_PAGE_LEVEL0_MASK) >> VADDR_PAGE_LEVEL0_SHIFT;
	if ((table0[t0_index] & PAGE_V) == 0) {
		return true;
	}

	return false;
}

int proc_add_fd(File *file) {
	if (current_proc->num_fds >= SYS_OPEN_FILES_MAX) {
		return -1;		
	}

	// reuse a previously closed fd if available
	int fd = -1;
	for (U32 i = 0; i < current_proc->num_fds; ++i) {
		if (current_proc->descriptor_table[i] == NULL) {
			fd = i;
			break;
		}
	}

	// append a new one if there are none available
	if (fd < 0) {
		fd = current_proc->num_fds++;
	}

	current_proc->descriptor_table[fd] = file;

	return fd;
}

// adds a new File to open file table and returns a pointer to it
File *append_open_file(Inode *inode, DcacheEntry *dentry, U32 flags) {
	if (num_open_files >= SYS_OPEN_FILES_MAX) {
		return NULL;
	}

	File *file = &open_files[num_open_files++];
	file->inode = inode;
	file->dentry = dentry;
	file->ref_count = 1;
	file->offset = 0;
	file->flags = flags;
	return file;
}

// search open file table for inode num
// returns File * if found or NULL if not
File *open_file_from_inode(Inode *inode) {
	File *file = NULL;
	for (U32 i=0; i<SYS_OPEN_FILES_MAX; ++i) {
		if (inode == open_files[i].inode) {
			file = &open_files[i];
			file->ref_count += 1;
			break;
		}
	}
	return file;
}

void print_inode(Inode *inode) {
	int inode_num = 0;
	for (int i=0; i<FILES_MAX; ++i) {
		if (&inodes[i] == inode) {
			inode_num = i;
			break;
		}
	}
	printf("inode[%d]: type=%u size=%u num_addrs=%u addrs[0]=%x\n", 
		inode_num, inode->type, inode->size, inode->num_addrs, inode->addrs[0]);
}

void print_inode_from_num(U32 inode_num) {
	Inode *inode = &inodes[inode_num];
	printf("inode[%d]: type=%u size=%u num_addrs=%u addrs[0]=%x\n", 
		inode_num, inode->type, inode->size, inode->num_addrs, inode->addrs[0]);
}

void path_normalize(char path[PATH_MAX]) {
	U32 path_len = strlen(path);
	if (path_len == 0) return;
	char *ptr = path + path_len - 1;
	// remove trailing slashes
	while (ptr != path && *ptr == '/') {
		*ptr-- = 0;
	}
}

void path_copy(char path[PATH_MAX], char *src) {
    strncpy(path, src, PATH_MAX);
    path[PATH_MAX - 1] = 0;
	path_normalize(path);
}

void path_join_n(char path[PATH_MAX], char *src, int size) {
	if (size == 0) return;
	U32 path_len = strlen(path);
	KERNEL_ASSERT(path_len + size < PATH_MAX, "");

    char *ptr = path + path_len;
    while (ptr != path && ptr[-1] == '/') {
        ptr--;
    }
	*ptr++ = '/';

    while (*src == '/') {
        src++;
		--size;
    }
	for (int i=0; i<size; ++i) {
		*ptr++ = src[i];
	}	
	*ptr++ = 0;
	path_normalize(path);
}

void path_join(char path[PATH_MAX], char *src) {
	U32 src_len = strlen(src);
	KERNEL_ASSERT(src_len < PATH_MAX, "");
	path_join_n(path, src, (int)src_len);
}

/* 
copies the first component in path to "comp" and returns a pointer to the start of the next component

EXAMPLE: 
	char *p = path_next_component("/documents/code/hello.c", comp)
	p    == "code/hello.c"
	comp == "documents"
*/

char *path_next_component(char path[PATH_MAX], char comp[PATH_MAX]) {
	while (*path == '/') ++path;
	char *start = path;
	U32 len = 0;
	while (*path && *path != '/') {
		++path;
		++len;
	}
	while (*path == '/') ++path;

	if (len == 0) return 0;

	len = MIN(len, PATH_MAX - 1);
	memcpy(comp, start, len);
	comp[len] = 0;

	return path;
}

void path_reverse(char path[PATH_MAX], char *src) {
	int src_len = strlen(src);
	KERNEL_ASSERT(src_len < PATH_MAX, "");

	// clear path & simultaneously handle when trying to reverse root path "/"
	path[0] = '/'; 
	path[1] = 0;  

	char *p = &src[src_len - 1];

	while (src_len > 0) {
		while (src_len > 0 && *p == '/') {
			--p;
			--src_len;
		}
		char *start = p;
		U32 len = 0;
		while (src_len > 0 && *p != '/') {
			start = p;
			--p;
			--src_len;
			++len;
		}
		path_join_n(path, start, len);
	}
}

Inode *find_inode_on_disk(char *path) {
	Inode *result = 0;

	// start at root
	Inode *subdir_inode = &inodes[ROOT_INODE_NUM];
	DcacheEntry *parent = dcache_lookup(&dcache, "/");

	Arena *arena = karena_get();

	char comp[PATH_MAX];
	while ((path = path_next_component(path, comp)) != 0) {
		// TODO: maybe cache blocks read from disk

		// read entire directory entry on disk
		U32 num_pages = align_up(subdir_inode->num_addrs * DISK_BLOCK_SIZE, PAGE_SIZE) / PAGE_SIZE;
		U32 pos = karena_pos(arena);
		U8 *buf = karena_push(arena, num_pages * PAGE_SIZE);

		for (U32 i=0; i < subdir_inode->num_addrs; ++i) {
			U32 block_id = subdir_inode->addrs[i] / DISK_BLOCK_SIZE;
			if (!disk_read_block(buf + i * DISK_BLOCK_SIZE, block_id)) {
				printf("%s:%d failed to read disk block %d\n", __FILE__, __LINE__, block_id);
				goto complete;
			}
		}

		// iterate the DiskDirEntry entries in subdir_inode
		bool found_component = false;
		for (U32 offset=0; offset < subdir_inode->size; ) {
			DiskDirEntry *disk_entry = (DiskDirEntry*)(buf + offset);

			// printf("\toffset=%u path=%s inode=%u\n", offset, disk_entry->name, disk_entry->inode_num);

			KERNEL_ASSERT(disk_entry->inode_num != 0, "syscall open: invalid inode %u", disk_entry->inode_num);

			if (0 == strcmp(comp, disk_entry->name)) {
				Inode *entry_inode = &inodes[disk_entry->inode_num];
				DcacheEntry *dc_entry = dcache_get(&dcache, parent, disk_entry->name);
				if (!dc_entry) {
					dc_entry = dcache_create_entry(entry_inode, parent, disk_entry->name);
					dcache_put(&dcache, dc_entry);
				}
				parent = dc_entry;
				subdir_inode = entry_inode;
				found_component = true;
				break;
			}

			U32 total_entry_size = align_up(sizeof(*disk_entry) + disk_entry->name_size_with_padding, 4);
			offset += total_entry_size;
		}
		if (!found_component) goto complete;
		karena_set_pos(arena, pos);
	}

	result = subdir_inode;
	
complete:
	karena_release(arena);
	return result;
}

void copy_to_from_userspace(void *dst, void *src, U32 size) {
	U32 status_reg = READ_CSR(sstatus);
	WRITE_CSR(sstatus, status_reg | SSTATUS_SUM);
	memcpy(dst, src, size);
	WRITE_CSR(sstatus, status_reg & ~SSTATUS_SUM);
}

void path_copy_to_from_userspace(char dst[PATH_MAX], char src[PATH_MAX]) {
	U32 status_reg = READ_CSR(sstatus);
	WRITE_CSR(sstatus, status_reg | SSTATUS_SUM);
	path_copy(dst, src);
	WRITE_CSR(sstatus, status_reg & ~SSTATUS_SUM);
}

int proc_cwd(char path[PATH_MAX]) {
	DcacheEntry *cwd = current_proc->working_directory;
	if (cwd) {
		char buf[PATH_MAX] = {0};
		while (cwd) {
			path_join(buf, cwd->name);
			if (!cwd->parent && 0 != strcmp(cwd->name, "/")) {
				printf("Error: proc_cwd: failed to build path for cwd: direntry %s has no parent in dcache\n", cwd->name);
				return -1;
			}
			cwd = cwd->parent;
		}
		path_reverse(path, buf);
		return 0;
	} else {
		printf("Error: proc_cwd: process has no valid working directory\n");
		return -1;
	}
}

// /code/hello.c
int syscall_open(char path[PATH_MAX], U32 flags, U32 mode) {
	(void)mode;
	// TODO: handle flags and mode

	int fd = -1;

	if (path[0] != '/') {
		char rel_path[PATH_MAX];
		path_copy(rel_path, path);

		int rc = proc_cwd(path);
		if (rc < 0) {
			printf("Error: syscall_open: relative path %s specified, but failed to get process working directory\n");
			return rc;
		}

		path_join(path, rel_path);
	}

	Inode *inode = NULL;
	DcacheEntry *dentry = dcache_lookup(&dcache, path);
	if (dentry) {
		inode = dentry->inode;
	} else {
		inode = find_inode_on_disk(path);
	}

	if (inode != NULL) {
		if ((flags & O_DIRECTORY) && inode->type != INODE_DIR) {
			return -ENOTDIR;
		}

		File *file = open_file_from_inode(inode);

		if (!file) {
			if (!dentry) dentry = dcache_lookup(&dcache, path);
			file = append_open_file(inode, dentry, flags);
			if (!file) {
				printf("Error: failed to open %s: kernel already has max files open\n");
				return -ENFILE;
			}
		}

		fd = proc_add_fd(file);
		if (fd < 0) {
			printf("Error: failed to open %s: proc %d already has max file descriptors\n", path, current_proc->pid);
			return -EMFILE;
		}
	}

	return fd;
}

int file_read(File *file, char *buf, U32 size, bool is_user_buf) {
	U32 bytes_read = 0;
	Inode *inode = file->inode;

	U32 max_blocks = MIN(inode->num_addrs, (align_up(size, DISK_BLOCK_SIZE) / DISK_BLOCK_SIZE));

	// TODO(shaw): cache disk blocks read
	Arena *arena = karena_get();
	char *tmp = karena_push(arena, max_blocks * DISK_BLOCK_SIZE);

	for (U32 i=0; i<max_blocks; ++i) {
		U32 block_id = inode->addrs[i] / DISK_BLOCK_SIZE;
		if (!disk_read_block(tmp + i * DISK_BLOCK_SIZE, block_id)) {
			printf("Error: file_read: failed to read disk block %d\n", block_id);
			bytes_read = -EIO;
			goto fail;
		}
	}

	U32 bytes_to_copy = MIN(size, inode->size);
	U32 offset = MAX(0, file->offset);
	if (offset + bytes_to_copy > inode->size) {
		bytes_to_copy = inode->size - offset;
	}

	if (is_user_buf) {
		copy_to_from_userspace(buf, tmp + offset, bytes_to_copy);
	} else {
		memcpy(buf, tmp + offset, bytes_to_copy);
	}
	bytes_read = bytes_to_copy;

fail:
	karena_release(arena);
	file->offset += bytes_read;
	return bytes_read;
}


int syscall_read(int fd, char *buf, U32 size, bool is_user_buf) {
	if (size == 0) return 0;

	KERNEL_ASSERT(fd >= 0, "");
	File *file = current_proc->descriptor_table[fd];
	if (!file) {
		printf("Error: syscall_read: fd %d is not associated with an open file\n");
		return -EBADF;
	}
	
	if (!file->inode) {
		printf("Error: syscall_read: invalid inode referenced in file pointed at by fd %d\n", fd);
		return -EBADF;
	}

	if (file->inode->type == INODE_DIR && (file->flags & O_DIRECTORY) == 0) {
		printf("Error: syscall_read: attempted to read from a directory that was not opened with the O_DIRECTORY flag: fd=%d\n", fd);
		return -EISDIR;
	}

	return file_read(file, buf, size, is_user_buf);
}

int syscall_close(int fd) {
	if (fd < 0) return -EBADF;

	File *file = current_proc->descriptor_table[fd];
	if (!file) return -EBADF;

	file->ref_count -= 1;
	if (file->ref_count <= 0) {
		file->offset = 0;
	}
	current_proc->descriptor_table[fd] = NULL;
	return 0;
}

int syscall_cwd(char *user_buf, U32 size) {
	char path[PATH_MAX];
	int rc = proc_cwd(path);
	if (rc == 0) {
		U32 len = MIN(size, strlen(path)+1);
		copy_to_from_userspace(user_buf, path, len);
	}
	return rc;
}

int syscall_dir_entries(int fd, U8 *user_buf, U32 user_buf_size) {
	// TODO: handle EFAULT argument points outside the calling process's address space
	// TODO: handle EINVAL Result buffer is too small.

	int rc = -1;
	File *file = current_proc->descriptor_table[fd];
	if (!file) {
		printf("Error: syscall_dir_entries: fd %d is not associated with an open file\n");
		return -EBADF;
	}

	if (!file->inode) {
		printf("Error: syscall_dir_entries: invalid inode referenced in file pointed at by fd %d\n", fd);
		return -EBADF;
	}

	if ((file->flags & O_DIRECTORY) == 0) {
		printf("Error: syscall_dir_entries: fd %d was not opened with the O_DIRECTORY flag\n", fd);
		return -ENOTDIR;
	}

	// TODO: ideally would check dcache first before reading from disk
	// but how can i lookup in the dcache without a path? i only have a fd here
	// the file has a dentry for dir in which we are looking for the children,
	// but how do i find the children in dcache without their name aready?
	// I think this would only work if syscall_dir_entries is restructured to
	// read one entry at a time, either from disk or from dcache. Currently it
	// reads large chunks of entries from disk at once.

	U32 max_entries = user_buf_size / sizeof(DirEntry);

	Arena *arena = karena_get();
	U32 disk_buf_size = max_entries * (sizeof(DiskDirEntry) + PATH_MAX);
	char *disk_buf = karena_push(arena, disk_buf_size);

	U32 buf_size = max_entries * sizeof(DirEntry);
	DirEntry *dir_entries = karena_push(arena, buf_size);

	U32 file_offset_start = file->offset;
	rc = file_read(file, disk_buf, disk_buf_size, false);
	if (rc < 0) {
		goto fail;
	}

	U32 entry_index = 0;
	for (U32 offset=0; offset < disk_buf_size && file_offset_start + offset < file->inode->size; ) {
		DiskDirEntry *disk_entry = (DiskDirEntry*)(disk_buf + offset);
		// printf("\toffset=%u path=%s inode=%u\n", offset, disk_entry->name, disk_entry->inode_num);
		KERNEL_ASSERT(disk_entry->inode_num != 0, "syscall dir_entries: invalid inode %u", disk_entry->inode_num);

		Inode *entry_inode = &inodes[disk_entry->inode_num];

		DirEntry *entry = &dir_entries[entry_index];
		entry->inode_num = disk_entry->inode_num;
		entry->type = entry_inode->type;
		entry->size = entry_inode->size;
		KERNEL_ASSERT(disk_entry->name_size < PATH_MAX, 
			"syscall_dir_entries: entry %s name is more than PATH_MAX=%u characters", disk_entry->name, PATH_MAX);
		memcpy(entry->name, disk_entry->name, disk_entry->name_size);

		if (file->dentry) {
			DcacheEntry *dentry = dcache_get(&dcache, file->dentry, entry->name);
			if (!dentry) {
				dentry = dcache_create_entry(entry_inode, file->dentry, entry->name);
				dcache_put(&dcache, dentry);
			}
		} 

		U32 total_entry_size = align_up(sizeof(*disk_entry) + disk_entry->name_size_with_padding, 4);
		offset += total_entry_size;
		entry_index += 1;
		if (entry_index >= max_entries) {
			// TODO: this is a @HACK to get around the problem inherent with a difference between DiskDirEntries and DirEntries. 
			// A user may want to read say 12 dir entries and give a buffer with that size, but because DiskDirEntries have 
			// variable size, there is no way to know how much of a buffer to allocate ahead of time in order to read from disk. You may read 
			file->offset = file_offset_start + offset;
			break;
		}
	}

	U32 size = entry_index * sizeof(dir_entries[0]);
	if (size > 0) {
		copy_to_from_userspace(user_buf, dir_entries, size);
		rc = size;
	}

	if (file->offset >= file->inode->size) {
		// end of directory reached
		rc =  0;
	}

fail:
	karena_release(arena);
	return rc;
}

int syscall_chdir(char path[PATH_MAX]) {
	int result = -1;

	if (path[0] != '/') {
		char rel_path[PATH_MAX];
		path_copy(rel_path, path);

		int rc = proc_cwd(path);
		if (rc < 0) {
			printf("Error: syscall_open: relative path %s specified, but failed to get process working directory\n");
			return rc;
		}

		path_join(path, rel_path);
	}

	Inode *inode = NULL;
	DcacheEntry *dentry = dcache_lookup(&dcache, path);
	if (dentry) {
		inode = dentry->inode;
	} else {
		inode = find_inode_on_disk(path);
	}

	if (inode != NULL) {
		if (inode->type != INODE_DIR) {
			return -ENOTDIR;
		}
		
		if (!dentry) dentry = dcache_lookup(&dcache, path);
		if (!dentry) return -ENOENT;

		current_proc->working_directory = dentry;
		result = 0;
	}

	return result;
}


// a3 -> syscall_num
// a0, a1, a2 -> arguments
// put return value in a0
void handle_syscall(TrapFrame *f) {
	switch (f->a3) {
		case SYSCALL_PUTCHAR:
			putchar(f->a0);
			break;
		case SYSCALL_GETCHAR: {
			int c;
			for (c = getchar(); c == -1; c = getchar()) {
				yield();
			}
			f->a0 = c;
			break;
		}
		case SYSCALL_EXIT: {
			current_proc->state = PROC_EXITED;
			printf("process %d exited with code %d\n", current_proc->pid, f->a0);
			// TODO(shaw): clean up process resources
			yield();
			PANIC("unreachable");
			break;
		}
		case SYSCALL_GETPAGES: {
			// TODO(shaw): ensure new heap size is valid
			Vaddr old_heap_end = current_proc->heap_end;
			current_proc->heap_end += PAGE_SIZE * (U32)f->a0;
			f->a0 = old_heap_end;
			break;
		}
		case SYSCALL_OPEN: {
			char *user_path = (char*)f->a0;

			char path[PATH_MAX] = {0};
			path_copy_to_from_userspace(path, user_path);

			U32 flags = f->a1;
			U32 mode = f->a2;
			f->a0 = syscall_open(path, flags, mode);

			break;
		}
		case SYSCALL_READ: {
			int fd = (int)f->a0;
			char *buf = (char*)f->a1;
			U32 size = f->a2;
			f->a0 = syscall_read(fd, buf, size, true);
			break;
		}
		case SYSCALL_CLOSE: {
			int fd = (int)f->a0;
			f->a0 = syscall_close(fd);
			break;
		}
		case SYSCALL_CWD: {
			char *user_buf = (char*)f->a0;
			U32 size = f->a1;
			f->a0 = syscall_cwd(user_buf, size);
			break;
		}
		case SYSCALL_CHDIR: {
			char *user_path = (char*)f->a0;
			char path[PATH_MAX];
			path_copy_to_from_userspace(path, user_path);
			f->a0 = syscall_chdir(path);
			break;
		}
		case SYSCALL_DIR_ENTRIES: {
			int fd = f->a0;
			U8 *user_buf = (U8*)f->a1;
			U32 user_buf_size = f->a2;
			f->a0 = syscall_dir_entries(fd, user_buf, user_buf_size);
			break;
		}
		default:
			PANIC("unimplemented syscall: %u\n", f->a3);
			break;
	}
}

void handle_trap(TrapFrame *f) {
	(void)f;
    U32 scause  = READ_CSR(scause);
    U32 stval   = READ_CSR(stval);
    U32 user_pc = READ_CSR(sepc);

	switch (scause) {
		case SCAUSE_ECALL_FROM_U_MODE:  {
			handle_syscall(f);
			// advance past the ecall instruction so when we switch back to user
			// mode and jump to sepc, we continue after the ecall instruction
			user_pc += 4;             
			WRITE_CSR(sepc, user_pc); 
			break;
		}

		case SCAUSE_STORE_AMO_PAGE_FAULT: {
			if (proc_is_first_access(stval)) {
				proc_back_vaddr_with_physical_page(stval);
				break;
			}

			PANIC("%s, stval=%x, sepc=%x", scause_strings[scause], stval, user_pc);
			break;
		}

		case SCAUSE_LOAD_PAGE_FAULT: {
			if (proc_is_first_access(stval)) {
				proc_back_vaddr_with_physical_page(stval);
				break;
			}

			PANIC("%s, stval=%x, sepc=%x", scause_strings[scause], stval, user_pc);
			break;
		}

		default: {
			char *scause_description = scause <= SCAUSE_HARDWARE_ERROR ? scause_strings[scause] : "";
			PANIC("unexpected trap: scause=%x(%s), stval=%x, sepc=%x", scause, scause_description, stval, user_pc);
		}
	}
}

// entry point of the exception handler 
__attribute__((naked))
__attribute__((aligned(4)))
void kernel_entry(void) {
	__asm__ __volatile__(
		// Retrieve a stable reference to the stack of the running process from sscratch, and store current sp in sscratch
		"csrrw sp, sscratch, sp\n"

		"addi sp, sp, -4 * 31\n"
		"sw ra,  4 * 0(sp)\n"
		"sw gp,  4 * 1(sp)\n"
		"sw tp,  4 * 2(sp)\n"
		"sw t0,  4 * 3(sp)\n"
		"sw t1,  4 * 4(sp)\n"
		"sw t2,  4 * 5(sp)\n"
		"sw t3,  4 * 6(sp)\n"
		"sw t4,  4 * 7(sp)\n"
		"sw t5,  4 * 8(sp)\n"
		"sw t6,  4 * 9(sp)\n"
		"sw a0,  4 * 10(sp)\n"
		"sw a1,  4 * 11(sp)\n"
		"sw a2,  4 * 12(sp)\n"
		"sw a3,  4 * 13(sp)\n"
		"sw a4,  4 * 14(sp)\n"
		"sw a5,  4 * 15(sp)\n"
		"sw a6,  4 * 16(sp)\n"
		"sw a7,  4 * 17(sp)\n"
		"sw s0,  4 * 18(sp)\n"
		"sw s1,  4 * 19(sp)\n"
		"sw s2,  4 * 20(sp)\n"
		"sw s3,  4 * 21(sp)\n"
		"sw s4,  4 * 22(sp)\n"
		"sw s5,  4 * 23(sp)\n"
		"sw s6,  4 * 24(sp)\n"
		"sw s7,  4 * 25(sp)\n"
		"sw s8,  4 * 26(sp)\n"
		"sw s9,  4 * 27(sp)\n"
		"sw s10, 4 * 28(sp)\n"
		"sw s11, 4 * 29(sp)\n"

		"csrr a0, sscratch\n"
		"sw a0, 4 * 30(sp)\n"

		// Reset the stable reference to the stack
		"addi a0, sp, 4 * 31\n"
		"csrw sscratch, a0\n"

		"mv a0, sp\n"
		"call handle_trap\n"

		"lw ra,  4 * 0(sp)\n"
		"lw gp,  4 * 1(sp)\n"
		"lw tp,  4 * 2(sp)\n"
		"lw t0,  4 * 3(sp)\n"
		"lw t1,  4 * 4(sp)\n"
		"lw t2,  4 * 5(sp)\n"
		"lw t3,  4 * 6(sp)\n"
		"lw t4,  4 * 7(sp)\n"
		"lw t5,  4 * 8(sp)\n"
		"lw t6,  4 * 9(sp)\n"
		"lw a0,  4 * 10(sp)\n"
		"lw a1,  4 * 11(sp)\n"
		"lw a2,  4 * 12(sp)\n"
		"lw a3,  4 * 13(sp)\n"
		"lw a4,  4 * 14(sp)\n"
		"lw a5,  4 * 15(sp)\n"
		"lw a6,  4 * 16(sp)\n"
		"lw a7,  4 * 17(sp)\n"
		"lw s0,  4 * 18(sp)\n"
		"lw s1,  4 * 19(sp)\n"
		"lw s2,  4 * 20(sp)\n"
		"lw s3,  4 * 21(sp)\n"
		"lw s4,  4 * 22(sp)\n"
		"lw s5,  4 * 23(sp)\n"
		"lw s6,  4 * 24(sp)\n"
		"lw s7,  4 * 25(sp)\n"
		"lw s8,  4 * 26(sp)\n"
		"lw s9,  4 * 27(sp)\n"
		"lw s10, 4 * 28(sp)\n"
		"lw s11, 4 * 29(sp)\n"
		"lw sp,  4 * 30(sp)\n"
		"sret\n"
	);
}

void delay(U32 cycles) {
    for (U32 i = 0; i < cycles; i++)
        __asm__ __volatile__("nop");
}

void kernel_main(void) {
	putchar('\n');

	memset(__bss, 0, (U32)__bss_end - (U32)__bss);
	WRITE_CSR(stvec, (U32)kernel_entry);
	virtio_blk_init();

	filesystem_init();

	idle_proc.pid = -1;
	current_proc = &idle_proc;

	create_process(_binary_shell_bin_start, (U32)_binary_shell_bin_size);

	putchar('\n');

	yield();

	// filesystem_flush();
	PANIC("switched to idle process");
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
