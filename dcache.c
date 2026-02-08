#define DCACHE_BUCKETS_MAX 256

struct DcacheEntry {
	Inode *inode;
	DcacheEntry *parent;
	DcacheEntry *next;
	U32 ref_count;
	char name[PATH_MAX];
};

typedef struct {
	DcacheEntry *buckets[DCACHE_BUCKETS_MAX];
	U32 count;
} Dcache;

U32 u32_hash(U32 x) {
	x ^= (x * 0x85ebca6bul) >> 16;
	return x;
}

U32 ptr_hash(void *ptr) {
	return u32_hash((U32)ptr);
}

U32 dcache_hash(DcacheEntry *parent, char name[PATH_MAX]) {
	U32 hash = ptr_hash(parent);

	U32 fnv_prime = 0x01000193ul;
	for (char *c = name; *c; ++c) {
		hash ^= *c;
		hash *= fnv_prime;
		hash ^= hash >> 16;
	}

	return hash;
}

DcacheEntry *dcache_create_entry(Inode *inode, DcacheEntry *parent, char name[PATH_MAX]) {
	// TODO: use a slab pool specifically for DcacheEntry to avoid wasting space with kmalloc
	DcacheEntry *entry = kmalloc(sizeof(DcacheEntry));
	if (entry) {
		memset(entry, 0, sizeof(*entry));
		entry->inode = inode;
		entry->parent = parent;
		strcpy(entry->name, name);
	}
	return entry;
}

void dcache_put(Dcache *dcache, DcacheEntry *entry) {
	U32 hash = dcache_hash(entry->parent, entry->name);
	U32 index = (U32)(hash % DCACHE_BUCKETS_MAX);
	DcacheEntry *slot = dcache->buckets[index];
	if (slot) {
		for (; slot->next; slot = slot->next) {
			if (slot->parent == entry->parent && 0 == strcmp(slot->name, entry->name)) {
				// entry already in cache, so do nothing
				// TODO: should ref_count be incremented here?? 
				return;
			}
		}
		slot->next = entry;
	} else {
		dcache->buckets[index] = entry;
	}
	dcache->count += 1;
}


DcacheEntry *dcache_get(Dcache *dcache, DcacheEntry *parent, char name[PATH_MAX]) {
	U32 hash = dcache_hash(parent, name);
	U32 index = (U32)(hash % DCACHE_BUCKETS_MAX);
	for (DcacheEntry *entry = dcache->buckets[index]; entry; entry = entry->next) {
		if (entry->parent == parent && 0 == strcmp(entry->name, name)) {
			entry->ref_count += 1;
			return entry;
		}
	}
	return NULL;
}

DcacheEntry *dcache_lookup(Dcache *dcache, char path[PATH_MAX]) {
	DcacheEntry *parent = dcache_get(dcache, NULL, "/");  // start at root
	if (path[0] == '/' && path[1] == 0) {
		return parent;
	}

	char comp[PATH_MAX];
	while ((path = path_next_component(path, comp)) != 0) {
		parent = dcache_get(dcache, parent, comp);
		if (!parent) return NULL;
	}
	return parent;
}

static Dcache dcache;
