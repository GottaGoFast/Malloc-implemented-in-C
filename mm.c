/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *   
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *        
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 *********************************************************/
team_t team = {
    /* Team name */
    "myteam",
    /* First member's full name */
    "Yifu Ma",
    /* First member's email address */
    "yifuma@wustl.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/*Explicit list implementation.
 *
 * LIFO policy -- most recently freed block is set to be the head of free list.
 *
 * Empty blocks contain a header struct: size field, previous block in free list, next block in free list.
 * The size field's last bit is the status bit of the block.
 * The size field's second to last bit is the status bit of the block before it in memory.
 * Empty blocks also has a footer which is size of the block.
 * 
 * Allocated blocks only has a header, previous block, next block and footer is now payload.
 *
 * The head of free list is stored at the header of the heap (mem_heap_lo()).
 * The footer of the heap is just the tag indicating that the block is allocated.
 * */
#define ADD_PTR(p,x) ((char*)(p) + (x))
#define SUB_PTR(p,x) ((char*)(p) - (x))


struct header {
  size_t size;
  struct header* next;
  struct header* prev;
};
typedef struct header header;


#define LIST_HEAD *((header **)mem_heap_lo())

#define WSIZE sizeof(void*)

#define MIN_BLOCK_SIZE (sizeof(header) + WSIZE)

#define ALIGNMENT 8

#define get_size(x) ((x) & ~(ALIGNMENT - 1))

#define ALLOC 1

#define PREV_ALLOC 2


static void * find_fit(size_t size){
        header *p = LIST_HEAD;
        while(p != NULL){
                if(get_size(p->size) >= size){
                        return p;
                }
                p = p->next;
        }
        return NULL;
} 

static void insert_block(header* p){
        header* old_head = LIST_HEAD;
        p->next = old_head;
        if(old_head != NULL){
                old_head->prev = p;
        }
        LIST_HEAD = p;
}
static void remove_block(header* p) {
	header *prev_block, *next_block;
        prev_block = p->prev;
        next_block = p->next;
        if(next_block != NULL){
                next_block->prev = prev_block;
        }
        if(p == LIST_HEAD){
                LIST_HEAD = next_block;
        }
        else{
		if(prev_block != NULL){
                	prev_block->next = next_block;
        	}
	}
}

static void coalesce(header* origin){
        size_t total_size = get_size(origin->size);
        size_t fragment_size;
        header* current_block = origin;
        header* fragment;
        while((current_block->size & PREV_ALLOC) == 0){
                fragment_size = get_size(*((size_t *)SUB_PTR(current_block, WSIZE)));
                fragment = (header *)SUB_PTR(current_block, fragment_size);
                total_size += fragment_size;
                remove_block(fragment);
                current_block = fragment;
        }
        header* new_block = current_block;
        current_block = (header *)(ADD_PTR(origin, get_size(origin->size)));
        while((current_block->size & ALLOC) == 0){
                fragment_size = get_size(current_block->size);
                fragment = current_block;
                total_size += fragment_size;
                remove_block(fragment);
                current_block = (header *)(ADD_PTR(current_block, fragment_size));
        }
        if(total_size != get_size(origin->size)){
                remove_block(origin);
                total_size |= PREV_ALLOC;
                new_block->size = total_size;
                *(size_t *)SUB_PTR(current_block, WSIZE) = total_size;
                insert_block(new_block);
        }
}
static void expand_heap(size_t exp_size){
 	size_t page_size = mem_pagesize();
        size_t num_pages = (exp_size + page_size - 1) / page_size;
        size_t total_size = num_pages * page_size;
        void* request_mem = mem_sbrk(total_size);
        if((size_t)request_mem == -1){
                printf("failed to expand heap");
                exit(0);
        }
        header* new_block = (header *)SUB_PTR(request_mem, WSIZE);
        size_t check_prev = new_block->size & PREV_ALLOC;
        size_t head_field = total_size | check_prev;
        new_block->size =  head_field;
        *((size_t *)ADD_PTR(new_block, total_size - WSIZE)) = head_field;
        *((size_t *)ADD_PTR(new_block, total_size)) = ALLOC;
        insert_block(new_block);
        coalesce(new_block);
}

/* Initialize the allocator. */
int mm_init(void)
{
        void* mem_request = mem_sbrk(MIN_BLOCK_SIZE + WSIZE + WSIZE);
        if((size_t)mem_request == -1){
                printf("Cannnot initialize heap");
                exit(1);
        }
        header* first_block = (header *)(ADD_PTR(mem_heap_lo(), WSIZE));
        size_t head_field = MIN_BLOCK_SIZE | PREV_ALLOC;
        first_block->size = head_field;
        first_block->prev = NULL;
        first_block->next = NULL;
        *((size_t *)ADD_PTR(first_block, MIN_BLOCK_SIZE - WSIZE)) = head_field;
        *((size_t*)SUB_PTR(mem_heap_hi(), WSIZE - 1)) = ALLOC;
        LIST_HEAD = first_block;
        return 0;
}



void *mm_malloc(size_t size)
{
        header * free_block;
        size_t block_size;
        size_t prev_alloc_tag;
	size_t excess_block_size;
        header* next_block = NULL;
        size += WSIZE;
	if(size == WSIZE){
                return NULL;
        }
        if(size <= MIN_BLOCK_SIZE){
                size = MIN_BLOCK_SIZE;
        }else{
                size = ALIGNMENT*((size + ALIGNMENT - 1)/ALIGNMENT);
        }
        free_block = find_fit(size);
        if(free_block == NULL){
                expand_heap(size);
		free_block = find_fit(size);
        }
        remove_block(free_block);
        block_size = get_size(free_block->size);
        if((block_size - size) > MIN_BLOCK_SIZE){
                excess_block_size = block_size - size;
                next_block = (header *)(ADD_PTR(free_block, size));
                prev_alloc_tag = free_block->size & PREV_ALLOC;
                free_block->size = size | ALLOC | prev_alloc_tag;
                size_t tags = excess_block_size | PREV_ALLOC;
                tags &= ~ALLOC;
                next_block->size = tags;
                *((size_t *)ADD_PTR(next_block, get_size(tags) - WSIZE)) = tags;
                insert_block(next_block);
        }
        else{
                free_block->size |= ALLOC;
                next_block = (header *)ADD_PTR(free_block, block_size);
                next_block->size |= PREV_ALLOC;
        }
        return ADD_PTR(free_block, WSIZE);
}

void mm_free (void *ptr) {
	
	header* to_free = (header*)SUB_PTR(ptr,WSIZE);
	if(((to_free->size) & ALLOC) == 0){
                return;
        }
	size_t head_field = ((to_free->size) & (~ALLOC));
	to_free->size = head_field;
	header* next_block = (header *)ADD_PTR(to_free, get_size(head_field));
	*((size_t *)ADD_PTR(to_free, get_size(head_field)-WSIZE)) = head_field;
	next_block->size &= (~PREV_ALLOC);
	insert_block(to_free);
	coalesce(to_free);
}


void* mm_realloc(void* ptr,size_t size)
{
	if(ptr == NULL){
		return mm_malloc(size);
	}
	if(ptr != NULL && size == 0){
		mm_free(ptr);
		return NULL;
	}
	header* current_block = (header *)SUB_PTR(ptr, WSIZE);
	size_t current_size = get_size(current_block->size);
	size_t remnant_size;
	header* remnant_block;
	header* next_block = (header *)ADD_PTR(current_block, current_size);
	size_t check_prev_alloc;
	size += WSIZE;
	if(size <= MIN_BLOCK_SIZE){
                size = MIN_BLOCK_SIZE;
        }else{
                size = ALIGNMENT*((size + ALIGNMENT - 1)/ALIGNMENT);
        }
	if(size < current_size){
		remnant_size = current_size - size;
		if(remnant_size <= MIN_BLOCK_SIZE){
			return ptr;
		}
		else{
			check_prev_alloc = current_block->size & PREV_ALLOC;
			current_block->size = size | check_prev_alloc | ALLOC;
			remnant_block = (header *)ADD_PTR(current_block, size);
			remnant_block->size = remnant_size | PREV_ALLOC;
			remnant_block->size &= ~ALLOC;
			*((size_t *)ADD_PTR(remnant_block, remnant_size - WSIZE)) = remnant_size;
			next_block->size &= (~PREV_ALLOC);
			insert_block(remnant_block);
			coalesce(remnant_block);
			return ptr;
		}
	}
	else{
		if(next_block->size & ALLOC){
			void *dest = mm_malloc(size - WSIZE);
			memcpy(dest, ptr, current_size - WSIZE);
			mm_free(ptr);
			return dest; 
		}		
		else{
			size_t total_size = get_size(next_block->size) + current_size;
			if(total_size < size){
				void *dest = mm_malloc(size - WSIZE);
                        	memcpy(dest, ptr, current_size - WSIZE);
                        	mm_free(ptr);
                        	return dest;
			}
			else{
				remove_block(next_block);
				remnant_size = total_size - size;
				check_prev_alloc = current_block->size & PREV_ALLOC;
				if(remnant_size <= MIN_BLOCK_SIZE){
					current_block->size = total_size | ALLOC | check_prev_alloc;
					*((size_t *)ADD_PTR(next_block, get_size(next_block->size))) |= PREV_ALLOC; 
					return ptr;
				}
				else{
					
					current_block->size = size | check_prev_alloc | ALLOC;
                        		remnant_block = (header *)ADD_PTR(current_block, size);
                        		remnant_block->size = remnant_size | PREV_ALLOC & ~ALLOC;
                        		*((size_t *)ADD_PTR(remnant_block, remnant_size - WSIZE)) = remnant_size;
					insert_block(remnant_block);
                        		coalesce(remnant_block);
                        		return ptr;
				}
			}
		}
	}
}	
