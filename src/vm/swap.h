#include <stdio.h>

void swap_init(void);
size_t swap_out(void *kpage);
void swap_in(void *kpage,size_t index);
void swap_free(size_t index);
