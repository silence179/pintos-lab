#pragma once

#include <list.h>
#include "threads/palloc.h"

void vm_frame_init(void);
void * vm_frame_alloc(enum palloc_flags flags,void * upage);

void vm_frame_free(void * kpage,bool page_free);
struct frame_table_entry * pick_a_frame_evict(void);
void unpin_frame(void *kpage);
void vm_frame_set_pinned (void *kpage, bool new_value);

