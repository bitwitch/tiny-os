// This header should ONLY be included a single time in kernel.c
// it is split out just for code organization.

#define PROCS_MAX   8
#define DCACHE_MAX  32

// SATP register (Supervisor Address Translation and Protection)
// |  31  |     30 - 22   |                 21 - 0                      |
// | Mode | addr space id | phyiscal page number where page table lives |
#define SATP_SV32 (1u << 31)

// SPIE is bit 5 in the sstatus csr, it indicates whether supervisor interrupts
// were enabled prior to trapping into supervisor mode
#define SSTATUS_SPIE (1 << 5)
#define SSTATUS_SUM  (1 << 18)

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

#define SECTOR_SIZE    512

// The base virtual address of an application image. This needs to match the
// starting address defined in user.ld
#define USER_BASE 0x1000000

#define PANIC(fmt, ...)                                                        \
	do {                                                                       \
		printf("PANIC: %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__);  \
		while (1) {}                                                           \
	} while (0)

#define KERNEL_ASSERT(cond, fmt, ...)                                          \
	if (!(cond)) {                                                             \
		PANIC("assertion failed: '%s': " fmt, #cond, ##__VA_ARGS__);             \
	}                                                                          
 
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
#define VIRTIO_REG_GUEST_PAGE_SIZE   0x28
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

typedef struct DcacheEntry DcacheEntry;
struct DcacheEntry {
	Inode *inode;
	DcacheEntry *parent;
	DcacheEntry *next;      // for dcache
	U32 ref_count;
	char name[PATH_MAX];
};

typedef struct {
	int pid;
	ProcState state;
	Vaddr sp;         // stack pointer
	Vaddr heap_start;
	Vaddr heap_end;
	DcacheEntry *working_directory;
	U32 *page_table;  // pointer to 1st level page table
	U8 stack[8192]; 
	File *descriptor_table[SYS_OPEN_FILES_MAX];
	U32 num_fds;
} Process;

typedef struct LRU_Node LRU_Node;
struct LRU_Node {
	void *data;
	LRU_Node *next;
	LRU_Node *prev;
};

typedef struct {
	LRU_Node *head;
	LRU_Node *tail;
	U32 len;
	U32 cap; 
} LRU;


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

static File open_files[SYS_OPEN_FILES_MAX];
static U32 num_open_files;

static Superblock superblock;
static Inode inodes[FILES_MAX];

static int errno;

Paddr alloc_pages(U32 n);
char *path_next_component(char path[PATH_MAX], char comp[PATH_MAX]);
