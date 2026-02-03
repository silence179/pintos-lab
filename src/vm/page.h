#include <stdio.h>
#include <hash.h>
#include "filesys/filesys.h"
#include "filesys/off_t.h"
enum page_type{
    ON_FRAME,
    ON_SWAP,
    FROM_FILE,
    ALL_ZERO,
};

struct supt_entry{
    struct hash_elem hash_elem;

    void * upage; //hash 的key
    void * kpage;
    enum page_type type;
    bool writable;
    
    struct file *file;
    off_t offset;
    uint32_t read_bytes;
    uint32_t zero_bytes;

    size_t swap_index;

};

struct supplemental_page_table
  {
    /* The hash table, page -> spte */
    struct hash page_map;
  };

unsigned supt_hash_func (const struct hash_elem *e, void *aux);
bool supt_less_func (const struct hash_elem *a,
                     const struct hash_elem *b,
                     void *aux);

bool lazy_load_frame(struct file* file,off_t ofs ,uint8_t *upage,
                     uint32_t read_bytes,uint32_t zero_bytes,bool writable);
void init_supt(struct hash * hash);

bool handle_mm_default(void *fault_addr,void *esp);
void supt_destroy_callback (struct hash_elem *e, void *aux UNUSED) ;
void supt_destroy (struct hash *supt) ;

struct supt_entry * supt_lookup(struct hash* supt,void * upage);
struct supplemental_page_table* vm_supt_create (void);

