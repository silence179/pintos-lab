#include <hash.h>
#include <list.h>
#include <debug.h>
#include <packed.h>
#include <stdio.h>

#include "lib/kernel/hash.h"
#include "lib/kernel/list.h"

#include "threads/palloc.h"
#include "vm/frame.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/pte.h"

#include "vm/page.h"
#include "vm/swap.h"

//同步锁
struct lock frame_lock;

struct list frame_list;

//hash 来管理申请了的映射
struct hash frame_map;

struct list_elem * clock_ptr;

static unsigned frame_hash_func(const struct hash_elem *hash_elem,void * aux);
static bool frame_hash_less(const struct hash_elem* a,const struct hash_elem* b,void *aux);

struct frame_table_entry* clock_ptr_next(void);
struct frame_table_entry * pick_a_frame_evict(void);

struct frame_table_entry{
    void * kpage;//物理页的地址
    void * upage;//用户的地址,也就是虚拟地址

    struct thread * thread;
    
    struct list_elem list_elem;
    struct hash_elem hash_elem;

    bool pinned; //对于一个未完成的页面的保护

};

void vm_frame_init(void){
    list_init(& frame_list);
    hash_init(& frame_map, frame_hash_func,frame_hash_less,NULL);
    lock_init(& frame_lock);

    clock_ptr = NULL;
}

void * vm_frame_alloc(enum palloc_flags flags,void * upage){
    lock_acquire(&frame_lock);
    void * kpage = palloc_get_page(flags);
    if(kpage == NULL){ //空间不够了,我们需要挑出一个页面来牺牲
        // PANIC("swap haven't been implemented");//暂时直接panic
        struct frame_table_entry * f_evicted = pick_a_frame_evict();
        struct thread * owner = f_evicted->thread;

        struct supt_entry* entry = supt_lookup(&owner->supt->page_map,f_evicted->upage);
        pagedir_clear_page(owner->pagedir, f_evicted->upage);

        bool is_dirty = pagedir_is_dirty(owner->pagedir, f_evicted->upage);

        entry->type = ON_SWAP;
        size_t index = swap_out(entry->kpage);
        entry->kpage = NULL;
        entry->swap_index = index;

        vm_frame_free(f_evicted->kpage,true);
    }

    struct frame_table_entry * frame = malloc(sizeof(struct frame_table_entry));
    if(frame == NULL){
        lock_release(&frame_lock);
        return NULL;
    }

    frame -> kpage = kpage;
    frame -> upage = upage;
    frame -> thread = thread_current();
    frame -> pinned = true; //还不能被替换
    
    list_push_back(&frame_list, &frame->list_elem);
    hash_insert(&frame_map,&frame->hash_elem);

    lock_release(&frame_lock);
    return kpage;

}

void vm_frame_free(void * kpage,bool page_free){
    lock_acquire(&frame_lock);
    struct frame_table_entry tmp_entry;
    tmp_entry.kpage = kpage;

    struct hash_elem* tmp_elem = hash_find(&frame_map, &tmp_entry.hash_elem);
    if(tmp_elem == NULL){
        PANIC("hash is empty,memery leak");
    }

    struct frame_table_entry* f_free = hash_entry(tmp_elem,struct frame_table_entry,hash_elem);

    pagedir_clear_page(f_free->thread->pagedir, f_free->upage);

    hash_delete(&frame_map,&f_free->hash_elem);
    list_remove(&f_free->list_elem);

    if(page_free)
        palloc_free_page(kpage);
    free(f_free);
    lock_release(&frame_lock);
}


struct frame_table_entry * pick_a_frame_evict(void){
    size_t size_n = hash_size(&frame_map);
    if(size_n == 0)
        PANIC("Frame table empty,memery leak");
    size_t it;
    for(it = 0;it<=2*size_n;it++){
        struct frame_table_entry * entry = clock_ptr_next();
        if (entry->pinned)
            continue;
        else if(pagedir_is_accessed(entry->thread->pagedir,entry->upage)){
            pagedir_set_accessed(entry->thread->pagedir, entry->upage, false);
            continue;
        }
        else
            return entry;
    }
    PANIC("out of memery");
}


struct frame_table_entry * clock_ptr_next(void){
    if(list_empty(&frame_list))
        PANIC("frame_list is empty , memery leak");
    if(clock_ptr == NULL || clock_ptr == list_end(&frame_list))
        clock_ptr = list_begin(&frame_list);
    else 
        clock_ptr = list_next(clock_ptr);
    struct frame_table_entry *e = list_entry(clock_ptr, struct frame_table_entry, list_elem);
    return e;
}

void unpin_frame(void *kpage){

    ASSERT(pg_ofs(kpage)==0);
    lock_acquire(&frame_lock);

    struct frame_table_entry tmp_entry;
    tmp_entry.kpage = kpage;

    struct hash_elem* tmp_elem = hash_find(&frame_map, &tmp_entry.hash_elem);
    if(tmp_elem == NULL) 
        PANIC("unpinned a frame which not exist");
    struct frame_table_entry* f_unpin = hash_entry(tmp_elem,struct frame_table_entry,hash_elem);
    f_unpin->pinned = false;

    lock_release(&frame_lock);
}
//hash 的配置函数
static unsigned frame_hash_func(const struct hash_elem* hash_elem,void * aux UNUSED){
    void* kpage = hash_entry(hash_elem,struct frame_table_entry, hash_elem)->kpage;
    return hash_bytes(&kpage, sizeof kpage);
}
static bool frame_hash_less(const struct hash_elem* a,const struct hash_elem* b, void *aux UNUSED){
    void* kpage_a = hash_entry(a,struct frame_table_entry, hash_elem)->kpage;
    void* kpage_b = hash_entry(b,struct frame_table_entry, hash_elem)->kpage;
    return kpage_a < kpage_b;
}
