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
    
    if(lock_held_by_current_thread(&frame_lock)){
        PANIC("find out1");
    }
    lock_acquire(&frame_lock);
    void * kpage = palloc_get_page(flags);
    if (kpage == NULL) {
        // 1. 挑选驱逐帧
        struct frame_table_entry *f_evicted = pick_a_frame_evict();

        ASSERT(f_evicted->pinned != true);
        ASSERT(f_evicted != NULL);
        ASSERT(f_evicted->thread != NULL);

        // 2. 标记为 pinned，防止在我们释放 frame_lock 期间被别人动
        f_evicted->pinned = true;

        // 3. 暂存信息
        struct thread *t = f_evicted->thread;
        void *u = f_evicted->upage;
        void *k = f_evicted->kpage;

        // 4. 【关键】释放全局 frame_lock，允许并发
        lock_release(&frame_lock);

        // 5. 【关键】获取线程的 supt_lock，保护“页表清除”到“状态更新”的原子性
        // 防止 handle_mm_fault 在这两步之间插入执行
        lock_acquire(&t->supt->supt_lock);
        // 6. 手动查找 SUPT 条目 (代替 supt_lookup 以避免死锁)
        struct supt_entry tmp_key;
        tmp_key.upage = u;
        struct hash_elem *elem = hash_find(&t->supt->page_map, &tmp_key.hash_elem);

        if (elem != NULL) {
            struct supt_entry *entry = hash_entry(elem, struct supt_entry, hash_elem);
            
            // --- 性能优化开始 ---
            // 检查页面是否被修改过 (Dirty)
            bool is_dirty = pagedir_is_dirty(t->pagedir, u);
            
            // 7. 清除硬件页表映射 (此时持有 supt_lock，缺页处理程序会阻塞等待)
            pagedir_clear_page(t->pagedir, u);

            // 8. 根据页面类型决定去向
            if (entry->type == FROM_FILE && !is_dirty) {
                // 如果是文件页且没改过，不需要写 Swap，直接变回 FROM_FILE
                // 下次访问时直接从原文件读，省下一次昂贵的磁盘写操作
                entry->kpage = NULL; 
                // entry->type 保持 FROM_FILE 或重置为 FROM_FILE
            } else {
                // 其他情况（堆栈、被修改过的文件页）必须写 Swap
                entry->type = ON_SWAP;
                entry->swap_index = swap_out(k); 
                entry->kpage = NULL;
            }
            // --- 性能优化结束 ---
        } else {
            PANIC("Evicted frame has no SUPT entry (Kernel bug)");
        }

        // 9. 状态更新完毕，释放 supt_lock
        lock_release(&t->supt->supt_lock);

        // 10. 重新获取全局 frame_lock 进行物理内存释放
        lock_acquire(&frame_lock);
        
        // 彻底释放旧的 Frame (vm_frame_do_free 内部会处理 hash/list 移除)
        vm_frame_do_free(k, true);

        // 11. 再次尝试分配
        kpage = palloc_get_page(flags);
        if(kpage == NULL )
            PANIC("kpage is NULL");
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
    
    if(lock_held_by_current_thread(&frame_lock)){
        PANIC("find out");
    }
    lock_acquire(&frame_lock);
    struct frame_table_entry tmp_entry;
    tmp_entry.kpage = kpage;

    struct hash_elem* tmp_elem = hash_find(&frame_map, &tmp_entry.hash_elem);
    if(tmp_elem == NULL){
        PANIC("hash is empty,memery leak");
    }

    struct frame_table_entry* f_free = hash_entry(tmp_elem,struct frame_table_entry,hash_elem);

    if (clock_ptr == &f_free->list_elem) {
            // 如果要删的正是时钟指向的，先把它推到下一个
            clock_ptr = list_next(clock_ptr);
            // 如果推到了末尾，绕回开头
            if (clock_ptr == list_end(&frame_list)) {
                clock_ptr = list_begin(&frame_list);
            }
            // 如果链表空了，设为 NULL
            if (list_empty(&frame_list)) clock_ptr = NULL;
    }
 
    pagedir_clear_page(f_free->thread->pagedir, f_free->upage);

    hash_delete(&frame_map,&f_free->hash_elem);
    list_remove(&f_free->list_elem);

    if(page_free)
        palloc_free_page(kpage);
    free(f_free);
    lock_release(&frame_lock);
}

void vm_frame_do_free(void * kpage,bool page_free){
    struct frame_table_entry tmp_entry;
    tmp_entry.kpage = kpage;

    struct hash_elem* tmp_elem = hash_find(&frame_map, &tmp_entry.hash_elem);
    if(tmp_elem == NULL){
        PANIC("hash is empty,memery leak");
    }

    struct frame_table_entry* f_free = hash_entry(tmp_elem,struct frame_table_entry,hash_elem);
    if (clock_ptr == &f_free->list_elem) {
            // 如果要删的正是时钟指向的，先把它推到下一个
            clock_ptr = list_next(clock_ptr);
            // 如果推到了末尾，绕回开头
            if (clock_ptr == list_end(&frame_list)) {
                clock_ptr = list_begin(&frame_list);
            }
            // 如果链表空了，设为 NULL
            if (list_empty(&frame_list)) clock_ptr = NULL;
    }
    pagedir_clear_page(f_free->thread->pagedir, f_free->upage);

    hash_delete(&frame_map,&f_free->hash_elem);
    list_remove(&f_free->list_elem);

    if(page_free)
        palloc_free_page(kpage);
    free(f_free);
}

struct frame_table_entry * pick_a_frame_evict(void){
    size_t size_n = hash_size(&frame_map);
    if(size_n == 0)
        PANIC("Frame table empty,memery leak");
    size_t it;
    // size_t f = 0;
    for(it = 0;it<=2*size_n;it++){
        struct frame_table_entry * entry = clock_ptr_next();
        if (entry->pinned){
            continue;
        }
        if(entry->thread == NULL || entry->thread->pagedir == NULL){
            PANIC("ooo");
            return entry;
        }
        else if(pagedir_is_accessed(entry->thread->pagedir,entry->upage)){
            pagedir_set_accessed(entry->thread->pagedir, entry->upage, false);
            // f++;
            // printf("%d\n",f);
            continue;
        }
        else
            return entry;
    }
    PANIC("out of memery");
}


struct frame_table_entry * clock_ptr_next(void){
    if(list_empty(&frame_list))
        PANIC("frame_list is empty");

    // 如果是第一次运行或者刚好走到了末尾
    if(clock_ptr == NULL || clock_ptr == list_end(&frame_list))
        clock_ptr = list_begin(&frame_list);
    else {
        clock_ptr = list_next(clock_ptr);
        if(clock_ptr == list_end(&frame_list)){
            clock_ptr = list_begin(&frame_list);
        }
    }
    
    return list_entry(clock_ptr, struct frame_table_entry, list_elem);
}

void unpin_frame(void *kpage){

    if(lock_held_by_current_thread(&frame_lock)){
        PANIC("find out");
    }  
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
void
vm_frame_set_pinned (void *kpage, bool new_value)
{
  if(lock_held_by_current_thread(&frame_lock)){
      PANIC("find out");
  }
  lock_acquire (&frame_lock);
  // hash lookup : a temporary entry
  struct frame_table_entry f_tmp;
  f_tmp.kpage = kpage;
  struct hash_elem *h = hash_find (&frame_map, &(f_tmp.hash_elem));
  if (h == NULL) {
    PANIC ("The frame to be pinned/unpinned does not exist");
  }

  struct frame_table_entry *f;
  f = hash_entry(h, struct frame_table_entry, hash_elem);
  f->pinned = new_value;

  lock_release (&frame_lock);
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
