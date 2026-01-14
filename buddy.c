#include "buddy.h"
#include <stdint.h>
#include <string.h>
#define NULL ((void *)0)

// Page size is 4K
#define PAGE_SIZE (4096)

// Maximum rank
#define MAX_RANK (16)

// Block structure for free lists
typedef struct block {
    struct block *next;
} block_t;

// Global variables
static void *base_addr = NULL;
static int total_pages = 0;
static block_t *free_lists[MAX_RANK + 1];  // Index 1-16, use singly linked list

// Use a byte array to track allocation status
static unsigned char alloc_map[32768];  // Support up to 32K pages

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

// Helper function to get page index from address
static inline int addr_to_page_idx(void *p) {
    return ((uintptr_t)p - (uintptr_t)base_addr) / PAGE_SIZE;
}

// Helper function to get block index
static inline int get_block_idx(void *addr, int rank) {
    uintptr_t offset = (uintptr_t)addr - (uintptr_t)base_addr;
    return offset / rank_to_size(rank);
}

// Helper function to check if address is within valid range
static inline int is_valid_addr(void *p) {
    if (p == NULL || base_addr == NULL) return 0;
    uintptr_t offset = (uintptr_t)p - (uintptr_t)base_addr;
    if (offset >= (uintptr_t)total_pages * PAGE_SIZE) return 0;
    return (offset % PAGE_SIZE) == 0;
}

// Initialize pages
int init_page(void *p, int pgcount) {
    if (p == NULL || pgcount <= 0) {
        return -EINVAL;
    }

    base_addr = p;
    total_pages = pgcount;

    // Clear allocation map
    memset(alloc_map, 0, sizeof(alloc_map));

    // Initialize all free lists to NULL
    for (int i = 1; i <= MAX_RANK; i++) {
        free_lists[i] = NULL;
    }

    // Split memory into blocks of power-of-2 sizes and add to free list
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
        // Add to free list
        block_t *block = (block_t *)addr;
        block->next = free_lists[rank];
        free_lists[rank] = block;
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
    free_lists[current_rank] = ((block_t *)addr)->next;

    // Split blocks if necessary
    while (current_rank > rank) {
        current_rank--;
        void *buddy = (void *)((uintptr_t)addr + rank_to_size(current_rank));
        block_t *buddy_block = (block_t *)buddy;
        buddy_block->next = free_lists[current_rank];
        free_lists[current_rank] = buddy_block;
    }

    // Mark as allocated
    int page_idx = addr_to_page_idx(addr);
    alloc_map[page_idx] = rank;

    return addr;
}

// Return pages
int return_pages(void *p) {
    // Validate address
    if (!is_valid_addr(p)) {
        return -EINVAL;
    }

    int page_idx = addr_to_page_idx(p);
    int rank = alloc_map[page_idx];

    if (rank == 0) {
        return -EINVAL;  // Not allocated
    }

    // Mark as free
    alloc_map[page_idx] = 0;

    // Try to merge with buddy
    void *current_addr = p;
    int current_rank = rank;

    while (current_rank < MAX_RANK) {
        void *buddy = get_buddy(current_addr, current_rank);

        // Check if buddy is free by checking alloc_map
        int buddy_page_idx = addr_to_page_idx(buddy);
        if (alloc_map[buddy_page_idx] != 0) {
            break;  // Buddy is allocated
        }

        // Check if buddy is actually in the free list at this rank
        // We need to verify it's in the free list by searching
        block_t **block_ptr = &free_lists[current_rank];
        int found = 0;
        while (*block_ptr != NULL) {
            if (*block_ptr == (block_t *)buddy) {
                // Found it, remove from list
                *block_ptr = (*block_ptr)->next;
                found = 1;
                break;
            }
            block_ptr = &((*block_ptr)->next);
        }

        if (!found) {
            break;  // Buddy not in free list
        }

        // Merge to larger block
        if ((uintptr_t)current_addr > (uintptr_t)buddy) {
            current_addr = buddy;
        }
        current_rank++;
    }

    // Add merged block to free list
    block_t *block = (block_t *)current_addr;
    block->next = free_lists[current_rank];
    free_lists[current_rank] = block;

    return OK;
}

// Query ranks
int query_ranks(void *p) {
    // Validate address
    if (!is_valid_addr(p)) {
        return -EINVAL;
    }

    int page_idx = addr_to_page_idx(p);
    int rank = alloc_map[page_idx];

    // If allocated, return the rank
    if (rank > 0) {
        return rank;
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
