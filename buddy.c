#include "buddy.h"
#include <stdint.h>
#define NULL ((void *)0)

// Page size is 4K
#define PAGE_SIZE (4096)

// Maximum rank
#define MAX_RANK (16)

// Block structure for free lists
typedef struct block {
    struct block *next;
    struct block *prev;
} block_t;

// Structure to track allocated blocks
typedef struct alloc_info {
    void *addr;
    int rank;
    struct alloc_info *next;
} alloc_info_t;

// Global variables
static void *base_addr = NULL;
static int total_pages = 0;
static block_t *free_lists[MAX_RANK + 1];  // Index 1-16
static alloc_info_t *alloc_list = NULL;

// Helper function to calculate block size for a given rank
static inline int rank_to_size(int rank) {
    return PAGE_SIZE * (1 << (rank - 1));
}

// Helper function to get buddy address
static inline void *get_buddy(void *addr, int rank) {
    uintptr_t offset = (uintptr_t)addr - (uintptr_t)base_addr;
    uintptr_t size = rank_to_size(rank);
    return (void *)((uintptr_t)base_addr + (offset ^ size));
}

// Helper function to check if address is within valid range
static inline int is_valid_addr(void *p) {
    if (p == NULL) return 0;
    uintptr_t offset = (uintptr_t)p - (uintptr_t)base_addr;
    return offset >= 0 && offset < (uintptr_t)total_pages * PAGE_SIZE;
}

// Add block to free list
static void add_to_free_list(void *addr, int rank) {
    block_t *block = (block_t *)addr;
    block->next = free_lists[rank];
    block->prev = NULL;
    if (free_lists[rank] != NULL) {
        free_lists[rank]->prev = block;
    }
    free_lists[rank] = block;
}

// Remove block from free list
static void remove_from_free_list(void *addr, int rank) {
    block_t *block = (block_t *)addr;
    if (block->prev != NULL) {
        block->prev->next = block->next;
    } else {
        free_lists[rank] = block->next;
    }
    if (block->next != NULL) {
        block->next->prev = block->prev;
    }
}

// Find allocated info by address
static alloc_info_t *find_alloc_info(void *p) {
    alloc_info_t *info = alloc_list;
    while (info != NULL) {
        if (info->addr == p) {
            return info;
        }
        info = info->next;
    }
    return NULL;
}

// Add allocation info
static void add_alloc_info(void *addr, int rank) {
    alloc_info_t *info = (alloc_info_t *)addr;
    info->addr = addr;
    info->rank = rank;
    info->next = alloc_list;
    alloc_list = info;
}

// Remove allocation info
static void remove_alloc_info(void *addr) {
    alloc_info_t **info_ptr = &alloc_list;
    while (*info_ptr != NULL) {
        if ((*info_ptr)->addr == addr) {
            *info_ptr = (*info_ptr)->next;
            return;
        }
        info_ptr = &((*info_ptr)->next);
    }
}

// Initialize pages
int init_page(void *p, int pgcount) {
    if (p == NULL || pgcount <= 0) {
        return -EINVAL;
    }

    base_addr = p;
    total_pages = pgcount;

    // Initialize all free lists to NULL
    for (int i = 1; i <= MAX_RANK; i++) {
        free_lists[i] = NULL;
    }
    alloc_list = NULL;

    // Add the entire memory to the highest possible rank
    int max_rank = 1;
    int pages = pgcount;
    while (pages > 1 && max_rank < MAX_RANK) {
        if (pages % 2 == 0) {
            pages = pages / 2;
            max_rank++;
        } else {
            break;
        }
    }

    // Split memory into blocks of maximum rank and add to free list
    int remaining = pgcount;
    void *addr = base_addr;
    while (remaining > 0) {
        int rank = 1;
        int block_pages = 1;
        // Find largest power of 2 that fits in remaining pages
        while (block_pages * 2 <= remaining && rank < MAX_RANK) {
            block_pages *= 2;
            rank++;
        }
        add_to_free_list(addr, rank);
        addr = (void *)((uintptr_t)addr + rank_to_size(rank));
        remaining -= block_pages;
    }

    return OK;
}

// Allocate pages
void *alloc_pages(int rank) {
    // Validate rank
    if (rank < 1 || rank > MAX_RANK) {
        return ERR_PTR(-EINVAL);
    }

    // Find a free block of the required or larger rank
    int current_rank = rank;
    while (current_rank <= MAX_RANK && free_lists[current_rank] == NULL) {
        current_rank++;
    }

    // No available block
    if (current_rank > MAX_RANK) {
        return ERR_PTR(-ENOSPC);
    }

    // Remove block from free list
    void *addr = free_lists[current_rank];
    remove_from_free_list(addr, current_rank);

    // Split blocks if necessary
    while (current_rank > rank) {
        current_rank--;
        void *buddy = (void *)((uintptr_t)addr + rank_to_size(current_rank));
        add_to_free_list(buddy, current_rank);
    }

    // Track allocation
    add_alloc_info(addr, rank);

    return addr;
}

// Return pages
int return_pages(void *p) {
    // Validate address
    if (!is_valid_addr(p)) {
        return -EINVAL;
    }

    // Find allocation info
    alloc_info_t *info = find_alloc_info(p);
    if (info == NULL) {
        return -EINVAL;
    }

    int rank = info->rank;

    // Remove from allocation list
    remove_alloc_info(p);

    // Try to merge with buddy
    void *current_addr = p;
    int current_rank = rank;

    while (current_rank < MAX_RANK) {
        void *buddy = get_buddy(current_addr, current_rank);

        // Check if buddy is free
        block_t *buddy_block = (block_t *)buddy;
        int buddy_found = 0;
        block_t *block = free_lists[current_rank];
        while (block != NULL) {
            if (block == buddy_block) {
                buddy_found = 1;
                break;
            }
            block = block->next;
        }

        if (!buddy_found) {
            break;
        }

        // Remove buddy from free list
        remove_from_free_list(buddy, current_rank);

        // Merge to larger block
        if ((uintptr_t)current_addr > (uintptr_t)buddy) {
            current_addr = buddy;
        }
        current_rank++;
    }

    // Add merged block to free list
    add_to_free_list(current_addr, current_rank);

    return OK;
}

// Query ranks
int query_ranks(void *p) {
    // Validate address
    if (!is_valid_addr(p)) {
        return -EINVAL;
    }

    // Check if allocated
    alloc_info_t *info = find_alloc_info(p);
    if (info != NULL) {
        return info->rank;
    }

    // For unallocated pages, find the maximum rank
    uintptr_t offset = (uintptr_t)p - (uintptr_t)base_addr;

    // Find the largest rank that this address can represent
    int max_rank = 1;
    while (max_rank < MAX_RANK) {
        uintptr_t size = rank_to_size(max_rank + 1);
        if (offset % size == 0 &&
            offset + size <= (uintptr_t)total_pages * PAGE_SIZE) {
            max_rank++;
        } else {
            break;
        }
    }

    return max_rank;
}

// Query page counts
int query_page_counts(int rank) {
    // Validate rank
    if (rank < 1 || rank > MAX_RANK) {
        return -EINVAL;
    }

    // Count free blocks of this rank
    int count = 0;
    block_t *block = free_lists[rank];
    while (block != NULL) {
        count++;
        block = block->next;
    }

    return count;
}
