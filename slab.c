typedef struct SlabPool SlabPool;
typedef struct Slab Slab;
typedef struct SlabBuf SlabBuf;

struct SlabBuf {
	SlabBuf *next;
};

struct Slab {
	SlabBuf *free_list;
	Slab *prev;
	Slab *next;
	SlabPool *sp;
}; 

struct SlabPool {
	U32 object_size; // note allocator reserves an extra 32 bits for the next pointer
					 // this is so that linkage will not overwrite constructed objects
	U32 num_allocated_bufs;
	U32 num_free_bufs;
	Slab *slabs;
};

// SlabPools for objects of sizes 2^3 - 2^9
// cannot be used before calling init_slab_allocator
SlabPool slab_pools[] = {
	{ .object_size = 8   },
	{ .object_size = 16  },
	{ .object_size = 32  },
	{ .object_size = 64  },
	{ .object_size = 128 },
	{ .object_size = 256 },
	{ .object_size = 512 },
};
U32 num_slab_pools = ARRAY_LEN(slab_pools);

Slab *slab_pool_new_slab(SlabPool *sp) {
	U8 *mem = (U8*)alloc_pages(1);
	U32 size = sp->object_size;

	// add new slab to slabs list
	Slab *slab = (Slab*)(mem + PAGE_SIZE - sizeof(Slab));
	slab->sp = sp;
	slab->prev = NULL;
	if (sp->slabs) {
		sp->slabs->prev = slab;
	} 
	slab->next = sp->slabs;
	sp->slabs = slab;

	
	// build free list
	U32 buf_size = size + sizeof(U32);
	U32 num_bufs = (PAGE_SIZE - sizeof(Slab)) / buf_size;

	for (U32 i=0; i<num_bufs; ++i) {
		SlabBuf *buf = (SlabBuf*)(mem + (i * buf_size) + size);
		if (i < num_bufs - 1) {
			SlabBuf *next_buf = (SlabBuf*)(mem + ((i+1) * buf_size) + size);
			buf->next = next_buf;
		} else {
			buf->next = NULL;
		}
	}

	// linkage is stored at end of buffer so point slab free list to the end of the first buffer
	slab->free_list = (SlabBuf*)(mem + size);
	slab->sp->num_free_bufs += num_bufs;
	return slab;
}

void *slab_pool_alloc(SlabPool *sp) {
	U8 *buf = NULL;
	// find a slab with a free buffer
	for (Slab *slab = sp->slabs; slab; slab = slab->next) {
		if (slab->free_list) {
			buf = (U8*)slab->free_list - sp->object_size;
			slab->free_list = slab->free_list->next;
			break;
		}
	}
	
	// if no free buffer, allocate a new slab
	if (!buf) {
		Slab *slab = slab_pool_new_slab(sp);
		KERNEL_ASSERT(slab->free_list, "newly allocated slab does not have a free list");
		buf = (U8*)slab->free_list - sp->object_size;
		slab->free_list = slab->free_list->next;
	}

	++sp->num_allocated_bufs;
	--sp->num_free_bufs;
	return buf;
}

void *kmalloc(U32 size) {
	KERNEL_ASSERT(size <= 512, 
		"kmalloc cannot allocated %u bytes, it only supports allocations <= 512 bytes", size);
	// find closest size in slab pools to allocate from
	SlabPool *closest_pool = NULL;
	U32 min = UINT32_MAX;
	for (U32 i=0; i<num_slab_pools; ++i) {
		SlabPool *sp = &slab_pools[i];
		if (sp->object_size >= size) {
			U32 diff = sp->object_size - size;
			if (diff < min) {
				min = diff;
				closest_pool = sp;
			}
		}
	}

	if (closest_pool) {
		return slab_pool_alloc(closest_pool);
	}

	return NULL;
}

void kfree(void *ptr) {
	if (!ptr) return;

	// NOTE: the +1 here is so that if ptr is the first item in a slab, it can
	// still align up to the end of a page to find the slab struct. it can also
	// never be at the very end of a page so this is fine even if its the last
	// allocated item in the slab
	U8 *page_end = (U8*)align_up((U32)ptr+1, PAGE_SIZE); 

	Slab *slab = (Slab*)(page_end - sizeof(Slab));
	SlabBuf *buf = (SlabBuf*)((U8*)ptr + slab->sp->object_size);
	buf->next = slab->free_list;
	slab->free_list = buf;
	--slab->sp->num_allocated_bufs;
	++slab->sp->num_free_bufs;

}

// initalize sp and allocate a slab for it
void slab_pool_init(SlabPool *sp, U32 size) {
	// initialize SlabPool
	memset(sp, 0, sizeof(*sp));
	sp->object_size = size;
	slab_pool_new_slab(sp);
}

void init_slab_allocator(void) {
	for (U32 i=0; i<num_slab_pools; ++i) {
		slab_pool_init(&slab_pools[i], slab_pools[i].object_size);
	}
}
