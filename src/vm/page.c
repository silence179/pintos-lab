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



struct supt_entry * supt_lookup(struct hash* supt,void * upage){
    struct supt_entry tmp_entry;
    tmp_entry.upage = upage;
    struct hash_elem* tmp_elem = hash_find(supt,upage);
    return hash_entry(tmp_elem,struct supt_entry, hash_elem);
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


    struct hash_elem * old = hash_insert(supt, &entry->hash_elem);
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
    struct hash * supt = &thread->supt->page_map;

    struct supt_entry tmp_entry;
    tmp_entry.upage = upage;

    struct hash_elem *tmp_elem = hash_find(supt,&tmp_entry.hash_elem);
    if(tmp_elem == NULL){
        // void * kpage = vm_frame_alloc(PAL_USER | PAL_ZERO,upage);
        return false;
    }
    struct supt_entry * entry = hash_entry(tmp_elem, struct supt_entry, hash_elem);
    
    if(entry->type == FROM_FILE){
        void * kpage = vm_frame_alloc(PAL_USER,upage);
        if (kpage == NULL)
            return false;

        file_seek(entry->file, entry->offset);
        if (file_read(entry->file, kpage,entry->read_bytes) != (int)entry->read_bytes){
            vm_frame_free(kpage,true);
            return false;
        }
        memset(kpage + entry->read_bytes, 0 , entry->zero_bytes);

        if(!install_page(upage, kpage, entry->writable)){
            vm_frame_free(kpage,true);
            return false;
        }

        entry->kpage =  kpage; 
        entry->type = ON_FRAME;
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
    if(entry->kpage != NULL){
        ASSERT(entry->type == ON_FRAME);
        vm_frame_free(entry->kpage, false);
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
  return supt;
}
