#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hash.h>
#include "vm/page.h"
#include "filesys/off_t.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "userprog/process.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "threads/malloc.h"

#include "userprog/process.h"
#include "vm/swap.h"
#include "vm/frame.h"
#include "vm/swap.h"


struct supt_entry * supt_lookup(struct supplemental_page_table* supt,void * upage){
    struct supt_entry tmp_entry;
    tmp_entry.upage = upage;
    lock_acquire(&supt->supt_lock);
    struct hash_elem* tmp_elem = hash_find(&supt->page_map, &tmp_entry.hash_elem);
    if (tmp_elem == NULL) {
        lock_release(&supt->supt_lock);
        return NULL;
    }
    lock_release(&supt->supt_lock);
    return hash_entry(tmp_elem, struct supt_entry, hash_elem);
}

bool lazy_load_frame(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable){
    struct supt_entry * entry = malloc(sizeof(struct supt_entry));

    if(entry == NULL)
        // PANIC("run out of kernel memery ");
        return false;
    struct hash *supt = &thread_current()->supt->page_map;

    entry->upage = upage;
    // entry->file = file_reopen(file);
    entry->file = file;
    entry->offset = ofs;
    entry->read_bytes = read_bytes;
    entry->zero_bytes = zero_bytes;
    entry->writable = writable;
    entry->type = FROM_FILE;
    entry->kpage = NULL;

    lock_acquire(&thread_current()->supt->supt_lock);
    struct hash_elem * old = hash_insert(supt, &entry->hash_elem);
    lock_release(&thread_current()->supt->supt_lock);

    if(old != NULL){ //说明重复申请了同一块upage,返回false.
        free (entry);
        PANIC("same upage");
        return false;
    }
    return true;
}

bool handle_mm_default(void *fault_addr,void *esp UNUSED){
    struct thread * thread = thread_current();
    void *upage = pg_round_down(fault_addr);
    struct supt_entry *entry = supt_lookup(thread->supt, upage);

    if(entry == NULL){
        // void * kpage = vm_frame_alloc(PAL_USER | PAL_ZERO,upage);
        return false;
    }
    lock_acquire(&thread->supt->supt_lock);
    if(entry->type == ON_FRAME) {
        PANIC("fdasd");
        lock_release(&thread->supt->supt_lock);
        return true;
    }
    lock_release(&thread->supt->supt_lock);

    if(entry->type == FROM_FILE){
        void * kpage = vm_frame_alloc(PAL_USER,upage);
        if (kpage == NULL)
            return false;

        // file_seek(entry->file, entry->offset);
        // if (file_read(entry->file, kpage,entry->read_bytes) != (int)entry->read_bytes){
        
        acquire_lock_f();
        if(file_read_at(entry->file,kpage,entry->read_bytes,entry->offset) != (int)entry->read_bytes){
            PANIC("here");
            vm_frame_free(kpage,true);
            return false;
        }
        release_lock_f();
        lock_acquire(&thread->supt->supt_lock);
        memset(kpage + entry->read_bytes, 0 , entry->zero_bytes);

        if(!install_page(upage, kpage, entry->writable)){
            vm_frame_free(kpage,true);
            return false;
        }

        entry->kpage =  kpage; 
        entry->type = ON_FRAME;
        lock_release(&thread->supt->supt_lock);

        unpin_frame(kpage);
        return true;
    }
    if(entry->type == ON_SWAP){
        /* 1. 分配一个物理帧 */
        void *kpage = vm_frame_alloc(PAL_USER, upage);
        if (kpage == NULL)
            return false;

        lock_acquire(&thread->supt->supt_lock);

        /* 2. 从 Swap 分区读回数据 */
        swap_in(kpage,entry->swap_index);

        /* 3. 建立映射 */
        if(!install_page(upage, kpage, entry->writable)){
            vm_frame_free(kpage, true);
            return false;
        }
        /* 4. 更新状态 */
        entry->kpage = kpage;
        entry->type = ON_FRAME;
        
        lock_release(&thread->supt->supt_lock);
        // 记得处理 pin 逻辑，如果是补页触发，补完通常可以 unpin
        // printf("Mapped: %p -> %p\n", fault_addr, kpage);

        unpin_frame(kpage); 
        return true;
    }

    return false;
}

/* 哈希表销毁的回调函数，用于释放每一个条目占用的资源 */
void 
supt_destroy_callback (struct hash_elem *e, void *aux UNUSED) 
{
    struct supt_entry *entry = hash_entry (e, struct supt_entry, hash_elem);
    if (entry->type == ON_FRAME) {
        /* 1. 如果在内存中，先解除页表映射，再释放物理帧 */
        if (entry->kpage != NULL) {
            pagedir_clear_page(thread_current()->pagedir, entry->upage);
            vm_frame_free(entry->kpage, true); 
        }
    } 
    else if (entry->type == ON_SWAP) {
        swap_free(entry->swap_index); 
    }
    else if (entry->type == FROM_FILE) {
        /* 3. 如果是文件映射且没有加载，通常不需要额外释放资源 */
        /* 但如果你 file_reopen 了文件，记得在这里 file_close */
    }
}

/* 供 process_exit 调用的清理接口 */
void 
supt_destroy (struct hash *supt) 
{
    /* hash_destroy 会遍历哈希表，对每个元素调用回调函数，最后释放哈希表内部存储桶 */
    hash_destroy (supt, supt_destroy_callback);
}

//哈希的初始化函数
unsigned supt_hash_func (const struct hash_elem *e, void *aux UNUSED){
    void * upage = hash_entry(e, struct supt_entry, hash_elem)->upage;
    return hash_bytes(&upage, sizeof upage);
}
bool supt_less_func (const struct hash_elem *a,const struct hash_elem *b,void *aux UNUSED){
    void * upage_a = hash_entry(a, struct supt_entry, hash_elem)->upage;
    void * upage_b = hash_entry(b, struct supt_entry, hash_elem)->upage;
    return upage_a < upage_b;
}
void init_supt(struct hash * hash){
    hash_init(hash,supt_hash_func,supt_less_func,NULL);
}
struct supplemental_page_table*
vm_supt_create (void)
{
  struct supplemental_page_table *supt =
    (struct supplemental_page_table*) malloc(sizeof(struct supplemental_page_table));

  hash_init (&supt->page_map, supt_hash_func, supt_less_func, NULL);
  lock_init(&supt->supt_lock);
  return supt;
}
