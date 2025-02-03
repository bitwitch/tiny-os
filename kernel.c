#define PROCS_MAX 8

#define va_list    __builtin_va_list
#define va_start   __builtin_va_start
#define va_end     __builtin_va_end
#define va_arg     __builtin_va_arg
#define align_up   __builtin_align_up
#define is_aligned __builtin_is_aligned
#define offsetof   __builtin_offsetof

#define true  1
#define false 0
#define NULL  ((void *) 0)

// SATP register (supervisor address translation and protection)
// |  31  |     30 - 22   |                 21 - 0                      |
// | Mode | addr space id | phyiscal page number where page table lives |
#define SATP_SV32 (1u << 31)

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


#define KILOBYTES(n)   (n * 1024)
#define PAGE_SIZE      KILOBYTES(4)

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

typedef int bool;
typedef unsigned char U8;
typedef unsigned short U16;
typedef unsigned int U32;
typedef unsigned long long U64;
typedef U32 Paddr;                 // physical address
typedef U32 Vaddr;                 // virtual address

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
} ProcState;

typedef struct {
	int pid;
	ProcState state;
	Vaddr sp;
	U32 *page_table; // pointer to 1st level page table
	U8 stack[8192]; 
} Process;

// Linker symbols defined in kernel.ld
extern U8 __bss[], __bss_end[], __stack_top[], __free_ram[], __free_ram_end[], __kernel_base[];

static Paddr free_ram_cursor = (Paddr)__free_ram;

static Process procs[PROCS_MAX]; 
static Process *current_proc;
static Process idle_proc;

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

void printf(char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	char *c = fmt;
	while (*c != 0) {
		if (*c == '%') {
			++c;
			switch (*c) {
			case 'd': {
				int val = va_arg(args, int);

				if (val < 0) {
					putchar('-');
					val *= -1;
				}

				int divisor = 1;
				while (val / (divisor*10)) divisor *= 10;
				
				while (divisor > 0) {
					int digit = val / divisor;
					putchar(digit + '0');
					val %= divisor;
					divisor /= 10;
				}

				break;
			}
			case 'x': {
				U32 val = va_arg(args, U32);

				U32 divisor = 1;
				while (divisor < 0x10000000 && val / (divisor*16)) {
					divisor *= 16;
				}
				
				putchar('0');
				putchar('x');
				while (divisor > 0) {
					char c = "0123456789abcdef"[val / divisor];
					putchar(c);
					val %= divisor;
					divisor /= 16;
				}
				break;
			}
			case 's': {
				for (char *s = va_arg(args, char*); *s; ++s) {
					putchar(*s);
				}
				break;
			}
			case '%':
				putchar('%');
				break;
			default: 
				break;
			}
		} else {
			putchar(*c);
		}
		++c;
	}

	va_end(args);
}

void *memset(void *buf, U8 val, U32 count) {
	U8 *p = (U8*)buf;
	for (U32 i=0; i<count; ++i) {
		p[i] = val;
	}
	return buf;
}

Paddr alloc_pages(U32 n) {
	U32 size = n * PAGE_SIZE;
	if (free_ram_cursor + size > (U32)__free_ram_end) {
		PANIC("out of memory, requested %d pages", n);
	}
	Paddr result = free_ram_cursor;
	free_ram_cursor += size;
	return result;
}

void map_page2(U32 *table1, Vaddr vaddr, Paddr paddr, U32 flags) {
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

void map_page(U32 *table1, U32 vaddr, Paddr paddr, U32 flags) {
    if (!is_aligned(vaddr, PAGE_SIZE))
        PANIC("unaligned vaddr %x", vaddr);

    if (!is_aligned(paddr, PAGE_SIZE))
        PANIC("unaligned paddr %x", paddr);

    U32 vpn1 = (vaddr >> 22) & 0x3ff;
    if ((table1[vpn1] & PAGE_V) == 0) {
        // Create the non-existent 2nd level page table.
        U32 pt_paddr = alloc_pages(1);
        table1[vpn1] = ((pt_paddr / PAGE_SIZE) << 10) | PAGE_V;
    }

    // Set the 2nd level page table entry to map the physical page.
    U32 vpn0 = (vaddr >> 12) & 0x3ff;
    U32 *table0 = (U32 *) ((table1[vpn1] >> 10) * PAGE_SIZE);
    table0[vpn0] = ((paddr / PAGE_SIZE) << 10) | flags | PAGE_V;
}

Process *create_process(Paddr proc_start) {
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
	*--sp = 0;              // s11
	*--sp = 0;              // s10
	*--sp = 0;              // s9
	*--sp = 0;              // s8
	*--sp = 0;              // s7
	*--sp = 0;              // s6
	*--sp = 0;              // s5
	*--sp = 0;              // s4
	*--sp = 0;              // s3
	*--sp = 0;              // s2
	*--sp = 0;              // s1
	*--sp = 0;              // s0
	*--sp = proc_start;     // ra

	U32 *page_table = (U32*)alloc_pages(1);
	for (Paddr paddr = (Paddr)__kernel_base; paddr < (Paddr)__free_ram_end; paddr += PAGE_SIZE) {
		// Vaddr vaddr = paddr - (Paddr)__kernel_base;
		// map_page(page_table, vaddr, paddr, PAGE_R|PAGE_W|PAGE_X);
		map_page(page_table, paddr, paddr, PAGE_R|PAGE_W|PAGE_X);
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

void handle_trap(TrapFrame *f) {
	(void)f;
    U32 scause  = READ_CSR(scause);
    U32 stval   = READ_CSR(stval);
    U32 user_pc = READ_CSR(sepc);
    PANIC("unexpected trap scause=%x, stval=%x, sepc=%x", scause, stval, user_pc);
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
		Process *prev = current_proc;
		current_proc = next;
		switch_context(&prev->sp, &next->sp);
	}
}

void proc_a_entry(void) {
	printf("starting process A\n");
	while (1) {
		putchar('A');
		yield();
		delay(30000000);
		// __asm__ __volatile__(
			// "li sp, 0xdeadbeef\n"  // set an invalid address to sp
			// "unimp"                // trigger an exception
		// );
	}
}

void proc_b_entry(void) {
	printf("starting process B\n");
	while (1) {
		putchar('B');
		yield();
		delay(30000000);
	}
}

void kernel_main(void) {
	memset(__bss, 0, (U32)__bss_end - (U32)__bss);
	WRITE_CSR(stvec, (U32)kernel_entry);

	printf("\n\n");

	idle_proc.pid = -1;
	current_proc = &idle_proc;

	create_process((Paddr)proc_a_entry);
	create_process((Paddr)proc_b_entry);

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
