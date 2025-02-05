#include "common.h"

#define PROCS_MAX 8

// SATP register (supervisor address translation and protection)
// |  31  |     30 - 22   |                 21 - 0                      |
// | Mode | addr space id | phyiscal page number where page table lives |
#define SATP_SV32 (1u << 31)

// SPIE is bit 5 in the sstatus csr, it indicates whether supervisor interrupts
// were enabled prior to trapping into supervisor mode
#define SSTATUS_SPIE (1 << 5)

// |   31 - 10   |       9 - 8      | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 |
// | Page number | for software use | D | A | G | U | X | W | R | V |
#define PAGE_V                  (1 << 0)     // valid
#define PAGE_R                  (1 << 1)     // readable
#define PAGE_W                  (1 << 2)     // writeable
#define PAGE_X                  (1 << 3)     // executable
#define PAGE_U                  (1 << 4)     // user
#define PAGE_G                  (1 << 5)     // global
#define PAGE_A                  (1 << 6)     // accessed
#define PAGE_D                  (1 << 7)     // dirty
#define PTE_PAGE_NUMBER_SHIFT   10
#define PTE_PAGE_NUMBER_MASK    (((1 << 22) - 1) << PTE_PAGE_NUMBER_SHIFT)

// |      31 - 22       |      21 - 12       |   11 - 0    |
// | index into level 1 | index into level 0 | page offset |
#define VADDR_PAGE_LEVEL0_SHIFT     12
#define VADDR_PAGE_LEVEL1_SHIFT     22
#define VADDR_PAGE_OFFSET_MASK      ((1 << 12) - 1)
#define VADDR_PAGE_LEVEL0_MASK      (((1 << 10) - 1) << 12)
#define VADDR_PAGE_LEVEL1_MASK      (VADDR_PAGE_LEVEL0_MASK << 10)

#define PAGE_SIZE      KILOBYTES(4)

// The base virtual address of an application image. This needs to match the
// starting address defined in user.ld
#define USER_BASE 0x1000000

#define PANIC(fmt, ...)                                                        \
	do {                                                                       \
		printf("PANIC: %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);  \
		while (1) {}                                                           \
	} while (0)

#define READ_CSR(reg)                                                          \
	({                                                                         \
		unsigned long __tmp;                                                   \
		__asm__ __volatile__("csrr %0, " #reg : "=r"(__tmp));                  \
		__tmp;                                                                 \
	})

#define WRITE_CSR(reg, value)                                                  \
	do {                                                                       \
		U32 __tmp = (value);                                                   \
		__asm__ __volatile__("csrw " #reg ", %0" ::"r"(__tmp));                \
	} while (0)

#define SECTOR_SIZE       512
#define VIRTQ_MAX_ENTRIES 16
#define VIRTIO_DEVICE_BLK 2
#define VIRTIO_BLK_PADDR  0x10001000
#define VIRTIO_MAGIC      0x74726976
#define VIRTIO_REG_MAGIC             0x00
#define VIRTIO_REG_VERSION           0x04
#define VIRTIO_REG_DEVICE_ID         0x08
#define VIRTIO_REG_VENDOR_ID         0x0c
#define VIRTIO_REG_DEVICE_FEATS      0x10
#define VIRTIO_REG_DEVICE_FEATS_SEL  0x14
#define VIRTIO_REG_DRIVER_FEATS      0x20
#define VIRTIO_REG_DRIVER_FEATS_SEL  0x24
#define VIRTIO_REG_QUEUE_SEL         0x30
#define VIRTIO_REG_QUEUE_NUM_MAX     0x34
#define VIRTIO_REG_QUEUE_NUM         0x38
#define VIRTIO_REG_QUEUE_ALIGN       0x3c
#define VIRTIO_REG_QUEUE_PFN         0x40
#define VIRTIO_REG_QUEUE_READY       0x44
#define VIRTIO_REG_QUEUE_NOTIFY      0x50
#define VIRTIO_REG_DEVICE_STATUS     0x70
#define VIRTIO_REG_DEVICE_CONFIG     0x100
#define VIRTIO_STATUS_ACK       (1 << 0)
#define VIRTIO_STATUS_DRIVER    (1 << 1)
#define VIRTIO_STATUS_DRIVER_OK (1 << 2)
#define VIRTIO_STATUS_FEATS_OK  (1 << 3)
#define VIRTQ_DESC_F_NEXT          1
#define VIRTQ_DESC_F_WRITE         2
#define VIRTQ_AVAIL_F_NO_INTERRUPT 1
#define VIRTIO_BLK_T_IN           0 // a read request
#define VIRTIO_BLK_T_OUT          1 // a write request
#define VIRTIO_BLK_T_FLUSH        4 
#define VIRTIO_BLK_T_DISCARD      11 
#define VIRTIO_BLK_T_WRITE_ZEROES 13 

typedef struct VirtqDesc VirtqDesc; // virtqueue descriptor
struct VirtqDesc {
	U64 addr;
	U32 len;
	U16 flags;
	U16 next;
} __attribute__((packed));

typedef struct VirtqAvail VirtqAvail;
struct VirtqAvail {
	U16 flags;
	U16 index;
	U16 ring[VIRTQ_MAX_ENTRIES];
} __attribute__((packed));

typedef struct VirtqUsedEntry VirtqUsedEntry;
struct VirtqUsedEntry {
	U32 id;
	U32 len;
} __attribute__((packed));

typedef struct VirtqUsed VirtqUsed;
struct VirtqUsed {
	U16 flags;
	U16 index;
	VirtqUsedEntry ring[VIRTQ_MAX_ENTRIES];
} __attribute__((packed));

typedef struct Virtq Virtq;
struct Virtq {
	VirtqDesc descs[VIRTQ_MAX_ENTRIES];
	VirtqAvail avail;
	VirtqUsed used __attribute__((aligned(PAGE_SIZE)));
	int queue_index;
	volatile U16 *used_index_ptr;
	U16 last_used_index;
} __attribute__((packed));

typedef struct VirtioBlkRequest VirtioBlkRequest;
struct VirtioBlkRequest {
	U32 type;
	U32 reserved;
	U64 sector;
	U8 data[SECTOR_SIZE];
	U8 status;
} __attribute__((packed));

typedef struct {
	long error;
	union {
		long value;
		unsigned long uvalue;
	};
} SBI_Ret;

typedef struct TrapFrame TrapFrame;
struct TrapFrame {
	U32 ra;
	U32 gp;
	U32 tp;
	U32 t0, t1, t2, t3, t4, t5, t6;
	U32 a0, a1, a2, a3, a4, a5, a6, a7;
	U32 s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11;
	U32 sp;
} __attribute__((packed));

typedef enum {
	PROC_UNUSED,
	PROC_RUNNABLE,
	PROC_EXITED,
} ProcState;

typedef struct {
	int pid;
	ProcState state;
	Vaddr sp;
	U32 *page_table; // pointer to 1st level page table
	U8 stack[8192]; 
} Process;

enum {
	SCAUSE_INST_ADDR_MISALIGNED = 0,
	SCAUSE_ACCESS_FAULT,
	SCAUSE_ILLEGAL_INST,
	SCAUSE_BREAKPOINT,
	SCAUSE_LOAD_ADDR_MISALIGNED,
	SCAUSE_LOAD_ACCESS_FAULT,
	SCAUSE_STORE_AMO_ADDR_MISALIGNED,
	SCAUSE_STORE_AMO_ACCESS_FAULT,
	SCAUSE_ECALL_FROM_U_MODE,
	SCAUSE_ECALL_FROM_S_MODE,
	SCAUSE_RESERVED_10,
	SCAUSE_RESERVED_11,
	SCAUSE_INST_PAGE_FAULT,
	SCAUSE_LOAD_PAGE_FAULT,
	SCAUSE_RESERVED_14,
	SCAUSE_STORE_AMO_PAGE_FAULT,
	SCAUSE_RESERVED_16,
	SCAUSE_RESERVED_17,
	SCAUSE_SOFTWARE_CHECK,
	SCAUSE_HARDWARE_ERROR,
};

static char *scause_strings[] = {
	[SCAUSE_INST_ADDR_MISALIGNED]      = "instruction address misaligned",
	[SCAUSE_ACCESS_FAULT]              = "access fault",
	[SCAUSE_ILLEGAL_INST]              = "illegal instruction",
	[SCAUSE_BREAKPOINT]                = "breakpoint",
	[SCAUSE_LOAD_ADDR_MISALIGNED]      = "load address misaligned",
	[SCAUSE_LOAD_ACCESS_FAULT]         = "load access fault",
	[SCAUSE_STORE_AMO_ADDR_MISALIGNED] = "store/amo address misaligned",
	[SCAUSE_STORE_AMO_ACCESS_FAULT]    = "store/amo access fault",
	[SCAUSE_ECALL_FROM_U_MODE]         = "environment call from U-Mode",
	[SCAUSE_ECALL_FROM_S_MODE]         = "environment call from S-Mode",
	[SCAUSE_RESERVED_10]               = "reserved",
	[SCAUSE_RESERVED_11]               = "reserved",
	[SCAUSE_INST_PAGE_FAULT]           = "instruction page fault",
	[SCAUSE_LOAD_PAGE_FAULT]           = "load page fault",
	[SCAUSE_RESERVED_14]               = "reserved",
	[SCAUSE_STORE_AMO_PAGE_FAULT]      = "store/amo page fault",
	[SCAUSE_RESERVED_16]               = "reserved",
	[SCAUSE_RESERVED_17]               = "reserved",
	[SCAUSE_SOFTWARE_CHECK]            = "software check",
	[SCAUSE_HARDWARE_ERROR]            = "hardware error",
};

// Linker symbols defined in kernel.ld
extern U8 __bss[], __bss_end[], __stack_top[], __free_ram[], __free_ram_end[], __kernel_base[];

// symbols definined in shell.bin.o
extern U8 _binary_shell_bin_size[], _binary_shell_bin_start[];

static Paddr free_ram_cursor = (Paddr)__free_ram;

static Process procs[PROCS_MAX]; 
static Process *current_proc;
static Process idle_proc;
static Virtq *virtio_blk_virtq;
static U64 virtio_blk_num_sectors;

Paddr alloc_pages(U32 n);

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
	// virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, paddr / PAGE_SIZE);
	virtio_reg_write32(VIRTIO_REG_QUEUE_PFN, paddr);

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
		PANIC("virtio: invalid version: %x", virtio_version);

	U32 device_id = virtio_reg_read32(VIRTIO_REG_DEVICE_ID);
	if (device_id != VIRTIO_DEVICE_BLK)
		PANIC("virtio: invalid device id: %x", device_id);

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

void virtio_blk_read(void *buf, U64 sector) {
	if (sector >= virtio_blk_num_sectors) {
		printf("virtio: tried to read sector %x, but virtio-blk device only contains %x sectors\n",
				sector, virtio_blk_num_sectors);
		return;
	}

	VirtioBlkRequest req = {0};
	req.type = VIRTIO_BLK_T_IN;
	req.sector = sector;

	Virtq *vq = virtio_blk_virtq;
	U64 req_addr = (U64)&req;
	vq->descs[0].addr  = req_addr;
	vq->descs[0].len   = sizeof(U32) * 2 + sizeof(U64);
	vq->descs[0].flags = VIRTQ_DESC_F_NEXT;
	vq->descs[0].next  = 1;

	vq->descs[1].addr  = req_addr + offsetof(VirtioBlkRequest, data);
	vq->descs[1].len   = SECTOR_SIZE;
	vq->descs[1].flags = VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE; // set the buffer as device writable
	vq->descs[1].next  = 2;

	vq->descs[2].addr  = req_addr + offsetof(VirtioBlkRequest, status);
	vq->descs[2].len   = sizeof(U8);
	vq->descs[2].flags = VIRTQ_DESC_F_WRITE;

	virtq_kick(vq, 0);

	while (virtq_is_busy(vq));

	if (req.status != 0) {
		printf("virtio: failed to read sector=%d status=%d\n", sector, req.status);
		return;
	}

	memcpy(buf, req.data, SECTOR_SIZE);
}

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

void exit(int code) {
	PANIC("exit called in kernel space with code %d", code);
}

Paddr alloc_pages(U32 n) {
	U32 size = n * PAGE_SIZE;
	if (free_ram_cursor + size > (U32)__free_ram_end) {
		PANIC("out of memory, requested %d pages", n);
	}
	Paddr result = free_ram_cursor;
	free_ram_cursor += size;
	memset((void*)result, 0, size);
	return result;
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
	for (U32 offset=0; offset < image_size; offset += PAGE_SIZE) {
		U32 remaining = image_size - offset;
		U32 copy_size = remaining < PAGE_SIZE ? remaining : PAGE_SIZE;

		Paddr page = alloc_pages(1);
		memcpy((void*)page, image + offset, copy_size);

		map_page(page_table, USER_BASE + offset, page, PAGE_U|PAGE_R|PAGE_W|PAGE_X);
	}
	
	p->pid = pid;
	p->state = PROC_RUNNABLE;
	p->sp = (Vaddr)sp;
	p->page_table = page_table;

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

// a3 -> syscall_num
// a0, a1, a2 -> arguments
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

	if (scause == SCAUSE_ECALL_FROM_U_MODE) {
		handle_syscall(f);
		// advance past the ecall instruction so when we switch back to user
		// mode and jump to sepc, we continue after the ecall instruction
		user_pc += 4;             
		WRITE_CSR(sepc, user_pc); 
	} else {
		char *scause_description = scause <= SCAUSE_HARDWARE_ERROR ? scause_strings[scause] : "";
		PANIC("unexpected trap: scause=%x(%s), stval=%x, sepc=%x", scause, scause_description, stval, user_pc);
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

	char buf[SECTOR_SIZE];
	virtio_blk_read(buf, 0);
	printf("first sector: %s\n", buf);

	idle_proc.pid = -1;
	current_proc = &idle_proc;

	create_process(_binary_shell_bin_start, (U32)_binary_shell_bin_size);

	putchar('\n');

	yield();
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
