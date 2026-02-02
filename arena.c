/*
                            First 8 Pages
+-----------------------------------------------------------------+
|                                              |                  |
|                    Data                      |       Arena      |
|                                              |                  |
+-----------------------------------------------------------------+

                           Next 8 Pages
+-----------------------------------------------------------------+
|                                                    |            |
|                    Data                            | ArenaChunk |
|                                                    |            |
+-----------------------------------------------------------------+

<-------------------------- 8 Pages ------------------------------>

*/

#define ARENA_CHUNK_SIZE (PAGE_SIZE * 8)  // size allocated by page allocator when arena must grow

typedef struct ArenaChunk ArenaChunk;
struct ArenaChunk {
	ArenaChunk *next;
};

typedef struct Arena Arena;
struct Arena {
	U32 size;      // does not include possible unused space at end of chunks when allocation doesnt fit in chunk
	U32 capacity;
	U32 num_chunks;
	U8 *cursor; // pointer to next available buffer
	bool used;
	ArenaChunk *chunks;
	Arena *next;
};

Arena *arenas;

Arena *karena_get(void) {
	Arena *arena;
	for (arena = arenas; arena; arena = arena->next) {
		if (!arena->used) {
			break;
		}
	}

	if (!arena) {
		U8 *memory = (U8*)alloc_pages(ARENA_CHUNK_SIZE / PAGE_SIZE);

		arena = (Arena*)(memory + ARENA_CHUNK_SIZE - sizeof(Arena));
		arena->capacity = ARENA_CHUNK_SIZE - sizeof(Arena);
		arena->cursor = memory;
	}

	arena->used = true;
	return arena;
}

void *karena_push(Arena *arena, U32 size) {
	// max suppported allocation size is ARENA_CHUNK_SIZE (minus the next pointer)
	KERNEL_ASSERT(size <= ARENA_CHUNK_SIZE - sizeof(ArenaChunk), 
		"attempting to allocate %u bytes, but max allocation size is currently %u", 
		size, ARENA_CHUNK_SIZE - sizeof(ArenaChunk));

	if (arena->size + size > arena->capacity) {
		U8 *memory = (U8*)alloc_pages(ARENA_CHUNK_SIZE / PAGE_SIZE);
		ArenaChunk *new_chunk = (ArenaChunk*)(memory + ARENA_CHUNK_SIZE - sizeof(ArenaChunk));
		arena->size = arena->capacity;
		arena->capacity += ARENA_CHUNK_SIZE - sizeof(ArenaChunk);
		arena->cursor = memory;
		arena->num_chunks += 1;

		if (arena->chunks) {
			ArenaChunk *c;
			for (c = arena->chunks; c->next; c = c->next);
			c->next = new_chunk;
		} else {
			arena->chunks = new_chunk;
		}

	} else {
		// check if this allocation does not fit in current chunk 
		// (here we know there is a next chunk because of the first if)
		U32 first_buffer_size = ARENA_CHUNK_SIZE - sizeof(Arena);
		U32 regular_buffer_size = ARENA_CHUNK_SIZE - sizeof(ArenaChunk);

		if (arena->size <= first_buffer_size) {
		// in first buffer
			U32 remaining_in_chunk = first_buffer_size - arena->size;
			if (size > remaining_in_chunk) {
				KERNEL_ASSERT(arena->chunks, 
					"no arena chunks list found in arena, but it should be there because it has been confirmed at this point that the arena has capacity for the new size, but the size doesn't fit in the first buffer");
				arena->size += remaining_in_chunk;
				arena->cursor = (U8*)arena->chunks - regular_buffer_size;
			}
		} else {
		// not in first buffer
			U32 c = arena->size - first_buffer_size; // sort of an offset into conceptually continuous memory of regular sized buffers
			U32 chunk_offset = c % regular_buffer_size;
			U32 remaining_in_chunk = regular_buffer_size - chunk_offset;
			if (size > remaining_in_chunk) {
				U32 chunk_index = (c / regular_buffer_size) + 1;
				KERNEL_ASSERT(chunk_index < arena->num_chunks, 
					"the chunk index that was calculated to place the new allocation is outside the number of chunks present in the arena");
				ArenaChunk *chunk = arena->chunks;
				for (U32 i=0; i<chunk_index; ++i) {
					chunk = chunk->next;
				}
				arena->size += remaining_in_chunk;
				arena->cursor = (U8*)chunk - regular_buffer_size;
			}
		}
	}

	void *ptr = (void*)arena->cursor;
	arena->cursor += size;
	arena->size += size;
	return ptr;
}

U32 karena_pos(Arena *arena) {
	return arena->size;
}

void karena_set_pos(Arena *arena, U32 pos) {
	// reset size
	arena->size = pos;

	// reset cursor 
	U32 first_buffer_size = ARENA_CHUNK_SIZE - sizeof(Arena);
	U32 regular_buffer_size = ARENA_CHUNK_SIZE - sizeof(ArenaChunk);

	arena->cursor = (U8*)arena - first_buffer_size + arena->size;
	if (arena->size > first_buffer_size) {
		U32 c = arena->size - first_buffer_size; // sort of an offset into conceptually continuous memory of regular sized buffers
		U32 chunk_offset = c % regular_buffer_size;
		U32 chunk_index = c / regular_buffer_size;
		KERNEL_ASSERT(chunk_index < arena->num_chunks, "the chunk index that was calculated to reset the arena cursor is outside the number of chunks present in the arena");
		ArenaChunk *chunk = arena->chunks;
		for (U32 i=0; i<chunk_index; ++i) {
			chunk = chunk->next;
		}
		arena->cursor = (U8*)chunk - regular_buffer_size + chunk_offset;
	}
}

void karena_release(Arena *arena) {
	karena_set_pos(arena, 0);
	arena->used = false;
}


