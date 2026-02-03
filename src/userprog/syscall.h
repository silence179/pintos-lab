#include <syscall-nr.h>
#include "threads/thread.h"
#include "filesys/filesys.h"


#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

struct thread_file{
    uint32_t fd;
    struct list_elem file_elem;
    struct file* file;
};
void syscall_init (void);

#endif /* userprog/syscall.h */
