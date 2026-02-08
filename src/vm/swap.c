#include "devices/block.h"
#include "threads/synch.h"
#include <bitmap.h>
#include "vm/swap.h"

struct block * swap;
struct bitmap * swap_map; 
struct lock swap_lock;

void swap_init(void){
    swap = block_get_role(BLOCK_SWAP);//如果这个要返回NULL,那早就出错了
    size_t b_size = block_size(swap);
    
    swap_map = bitmap_create(b_size / 8);

    lock_init(&swap_lock);
}

size_t swap_out(void *kpage){
    lock_acquire(&swap_lock);
    
    size_t index = bitmap_scan_and_flip(swap_map, 0, 1, false);
    if (index == BITMAP_ERROR){
        PANIC("swap block is already full");
    }
    size_t sector_index = 8 * index;
    for(int i = 0;i < 8;i++){
        block_write(swap, sector_index + i, (uint8_t*)kpage + (i*BLOCK_SECTOR_SIZE) );
    }

    lock_release(&swap_lock);
    return index;
}

void swap_in(void *kpage,size_t index){
    ASSERT (swap != NULL);
    ASSERT (swap_map != NULL);

    lock_acquire(&swap_lock);
     
    for(int i=0;i<8;i++){
        block_read(swap, (index *8) + i,(uint8_t *)kpage + (i*BLOCK_SECTOR_SIZE));   
    }
    bitmap_set(swap_map, index, false);

    lock_release(&swap_lock);
    return;
}
void swap_free(size_t index){
    ASSERT(index < bitmap_size(swap_map));
    ASSERT(bitmap_test(swap_map, index) == true);
    lock_acquire(&swap_lock);
    bitmap_set(swap_map,index,false);
    lock_release(&swap_lock);
}
