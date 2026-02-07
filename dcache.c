#define DCACHE_BUCKETS_MAX 256

typedef struct {
	DirEntry *buckets[DCACHE_BUCKETS_MAX];
	U32 count;
} Dcache;

U32 u32_hash(U32 x) {
	x ^= (x * 0x85ebca6bul) >> 16;
	return x;
}

U32 ptr_hash(void *ptr) {
	return u32_hash((U32)ptr);
}

U32 dcache_hash(DirEntry *parent, char name[PATH_MAX]) {
	U32 hash = ptr_hash(parent);

	U32 fnv_prime = 0x01000193ul;
	for (char *c = name; *c; ++c) {
		hash ^= *c;
		hash *= fnv_prime;
		hash ^= hash >> 16;
	}

	return hash;
}

void dcache_put(Dcache *dcache, DirEntry *entry) {
	U32 hash = dcache_hash(entry->parent, entry->name);
	U32 index = (U32)(hash % DCACHE_BUCKETS_MAX);
	DirEntry *slot = dcache->buckets[index];
	if (slot) {
		for (; slot->next; slot = slot->next) {
			if (slot->parent == entry->parent && 0 == strcmp(slot->name, entry->name)) {
				// entry already in cache, so do nothing
				return;
			}
		}
		slot->next = entry;
	} else {
		dcache->buckets[index] = entry;
	}
	dcache->count += 1;
}


DirEntry *dcache_get(Dcache *dcache, DirEntry *parent, char name[PATH_MAX]) {
	U32 hash = dcache_hash(parent, name);
	U32 index = (U32)(hash % DCACHE_BUCKETS_MAX);
	for (DirEntry *entry = dcache->buckets[index]; entry; entry = entry->next) {
		if (entry->parent == parent && 0 == strcmp(entry->name, name)) {
			return entry;
		}
	}
	return NULL;
}

DirEntry *dcache_lookup(Dcache *dcache, char path[PATH_MAX]) {
	DirEntry *parent = dcache_get(dcache, NULL, "/");  // start at root
	char comp[PATH_MAX];
	while ((path = path_next_component(path, comp)) != 0) {
		parent = dcache_get(dcache, parent, comp);
		if (!parent) return NULL;
	}
	return parent;
}

static Dcache dcache;
