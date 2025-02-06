#define M61_DISABLE 1
#include "dmalloc.hh"
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cinttypes>
#include <cassert>
#include <stdint.h> 

#define CANARY 0xDEADBEEF
#define CANARY_SIZE 200
#define FREED_MARKER ((size_t)-1)
// You may write code here.
// (Helper functions, types, structs, macros, globals, etc.)
typedef struct dmalloc_metadata{
    size_t size; //size allocated
    const char* file; //file where allocation occurred
    long line; //line number
    struct dmalloc_metadata* prev; //previous allocation
    struct dmalloc_metadata* next; //next allocation
}dmalloc_metadata;

static dmalloc_statistics global_stats = {0, 0, 0, 0, 0, 0, 0, 0};
static dmalloc_metadata *head = NULL;

/// dmalloc_malloc(sz, file, line)
///    Return a pointer to `sz` bytes of newly-allocated dynamic memory.
///    The memory is not initialized. If `sz == 0`, then dmalloc_malloc must
///    return a unique, newly-allocated pointer value. The allocation
///    request was at location `file`:`line`.

void* dmalloc_malloc(size_t sz, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (sz > SIZE_MAX - sizeof(dmalloc_metadata) - (2 * CANARY_SIZE)) {
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return NULL;  
    }

    // Your code here.
    size_t total_size = sizeof(dmalloc_metadata) + CANARY_SIZE + sz + CANARY_SIZE;
    dmalloc_metadata* metadata = (dmalloc_metadata*) base_malloc(total_size);
    if(!metadata){
        global_stats.nfail++;
        global_stats.fail_size += sz;
        return NULL;
    } 

    //update metadata
    uint32_t* underflow_canary = (uint32_t*)(metadata + 1);
    for (size_t i = 0; i < (CANARY_SIZE / sizeof(uint32_t)); i++){
        underflow_canary[i] = CANARY;
    }
    // memset(overflow_canary, CANARY, CANARY_SIZE);
    metadata->size = sz;
    metadata->file = file;
    metadata->line = line;
    metadata->prev = NULL;
    metadata->next = head;

    if(head){
        head->prev = metadata;
    }
    head = metadata;

    //update stats
    global_stats.nactive++;
    global_stats.active_size += sz;
    global_stats.ntotal++;
    global_stats.total_size += sz;

    uint32_t* overflow_canary = (uint32_t*)((char*)(metadata + 1) + CANARY_SIZE + sz);
    for(size_t i = 0; i < CANARY_SIZE / sizeof(uint32_t); i++){
            overflow_canary[i] = CANARY;
    }
    //get address
    uintptr_t address = (uintptr_t)((char*)(metadata + 1) + CANARY_SIZE);
    if(global_stats.heap_min == 0 || address < global_stats.heap_min){
        global_stats.heap_min = address;
    }
    if(address + sz > global_stats.heap_max){ //ending of payload??
        global_stats.heap_max = address + sz + CANARY_SIZE; //***/
    }

    //return ptr to usable memory
    return (void*)((char*)(metadata + 1) + CANARY_SIZE);
    // return base_malloc(sz);
}


/// dmalloc_free(ptr, file, line)
///    Free the memory space pointed to by `ptr`, which must have been
///    returned by a previous call to dmalloc_malloc. If `ptr == NULL`,
///    does nothing. The free was called at location `file`:`line`.

void dmalloc_free(void* ptr, const char* file, long line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    if (!ptr) return;
    // Your code here.
    uintptr_t address = (uintptr_t)ptr;
    if(address < global_stats.heap_min || address > global_stats.heap_max){
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not in heap\n", file, line, ptr);
        abort();
    }

    dmalloc_metadata *metadata = (dmalloc_metadata*)((char*)ptr - CANARY_SIZE) - 1;

    if(metadata->size == FREED_MARKER){
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, double free\n", file, line, ptr);
        abort();
    }

    //search for ptr in active list
    dmalloc_metadata* curr = head;
    while(curr){
        if (curr == metadata){
            break;
        }
        curr = curr->next;
    }
    if(!curr){
        //check if defined in another block
        dmalloc_metadata* another_block = head;
        while(another_block){
            uintptr_t begining = (uintptr_t)(another_block + 1) + CANARY_SIZE; //skip metadata
            uintptr_t end = begining + another_block->size;
            if(address < end && address >= begining){
                fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
                fprintf(stderr, "  %s:%ld: %p is %zu bytes inside a %zu byte region allocated here\n", file, another_block->line, ptr, address - begining, another_block->size);
                abort();
            }
            another_block = head->next;
        }
        fprintf(stderr, "MEMORY BUG: %s:%ld: invalid free of pointer %p, not allocated\n", file, line, ptr);
        abort();
    }

    // uint32_t* canary = (uint32_t*)((char*)ptr + metadata->size);
    uint32_t* underflow_canary = (uint32_t*)(metadata + 1);
    uint32_t* overflow_canary = (uint32_t*)((char*)ptr + metadata->size);
    // if (*canary != CANARY) { 
    //     fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
    //     abort();
    // }
    for (size_t i = 0; i < CANARY_SIZE / sizeof(uint32_t); i++) {
        if (underflow_canary[i] != CANARY) {
            fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
            abort();
        }
        if (overflow_canary[i] != CANARY) {
            fprintf(stderr, "MEMORY BUG: %s:%ld: detected wild write during free of pointer %p\n", file, line, ptr);
            abort();
        }
    }


    //freeing
    if(metadata->prev){
        metadata->prev->next = metadata->next;
    }else{
        head = metadata->next;
    }

    if(metadata->next){
        metadata->next->prev = metadata->prev;
    }
    size_t size = metadata->size;
    //clear
    metadata->size = FREED_MARKER;

    global_stats.nactive--;
    global_stats.active_size -= size;

    base_free(metadata);
    // base_free(ptr);
}


/// dmalloc_calloc(nmemb, sz, file, line)
///    Return a pointer to newly-allocated dynamic memory big enough to
///    hold an array of `nmemb` elements of `sz` bytes each. If `sz == 0`,
///    then must return a unique, newly-allocated pointer value. Returned
///    memory should be initialized to zero. The allocation request was at
///    location `file`:`line`.

void* dmalloc_calloc(size_t nmemb, size_t sz, const char* file, long line) {
    // Your code here (to fix test014).
    if(sz > 0 && nmemb > 0 && nmemb > SIZE_MAX/sz){
        global_stats.nfail++;
        global_stats.fail_size += nmemb * sz;
        return NULL;
    }
    void* ptr = dmalloc_malloc(nmemb * sz, file, line);
    if (ptr) {
        memset(ptr, 0, nmemb * sz);
    }
    return ptr;
}


/// dmalloc_get_statistics(stats)
///    Store the current memory statistics in `*stats`.

void dmalloc_get_statistics(dmalloc_statistics* stats) {
    // Stub: set all statistics to enormous numbers
    // memset(stats, 255, sizeof(dmalloc_statistics));
    // Your code here.
    if (stats){
        *stats = global_stats;
    }
}


/// dmalloc_print_statistics()
///    Print the current memory statistics.

void dmalloc_print_statistics() {
    dmalloc_statistics stats;
    dmalloc_get_statistics(&stats);

    printf("alloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("alloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}


/// dmalloc_print_leak_report()
///    Print a report of all currently-active allocated blocks of dynamic
///    memory.

void dmalloc_print_leak_report() {
    // Your code here.
    dmalloc_metadata* curr = head;
    //loop through the linked list and print out the report of unfreed memory
    while(curr){
        printf("LEAK CHECK: %s:%ld: allocated object %p with size %zu\n", curr->file, curr->line, (void*)((char*)(curr + 1) + CANARY_SIZE), curr->size);
        curr = curr->next;
    }
}


/// dmalloc_print_heavy_hitter_report()
///    Print a report of heavily-used allocation locations.

void dmalloc_print_heavy_hitter_report() {
    // Your heavy-hitters code here
}
