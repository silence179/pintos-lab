#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"

#define max_syscall 20
extern struct recursive_lock lock_f;


static void syscall_handler (struct intr_frame *);
static void (*syscalls[max_syscall])(struct intr_frame *);
static void *checkpointer(const void *vaddr);
static void err_exit(void);
static int get_user(const uint8_t *uaddr);
// static void check_buffer(const void *vaddr, size_t size);
static void check_and_preload_buffer (void *buffer, unsigned size, bool writable);
static void unpin_buffer(void *buffer, unsigned size) ;

struct thread_file * find_file_id (uint32_t file_id);
bool is_valid_pointer (void* esp,uint8_t argc);

void sys_halt(struct intr_frame* f);
void sys_exit(struct intr_frame* f);
void sys_exec(struct intr_frame* f);
void sys_create(struct intr_frame* f);
void sys_remove(struct intr_frame* f);
void sys_open(struct intr_frame* f);
void sys_wait(struct intr_frame* f);
void sys_filesize(struct intr_frame* f);
void sys_read(struct intr_frame* f);
void sys_write(struct intr_frame* f);
void sys_seek(struct intr_frame* f);
void sys_tell(struct intr_frame* f);
void sys_close(struct intr_frame* f);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  syscalls[SYS_EXEC] = &sys_exec;
  syscalls[SYS_HALT] = &sys_halt;
  syscalls[SYS_EXIT] = &sys_exit;
 
  syscalls[SYS_WAIT] = &sys_wait;
  syscalls[SYS_CREATE] = &sys_create;
  syscalls[SYS_REMOVE] = &sys_remove;
  syscalls[SYS_OPEN] = &sys_open;
  syscalls[SYS_WRITE] = &sys_write;
  syscalls[SYS_SEEK] = &sys_seek;
  syscalls[SYS_TELL] = &sys_tell;
  syscalls[SYS_CLOSE] =&sys_close;
  syscalls[SYS_READ] = &sys_read;
  syscalls[SYS_FILESIZE] = &sys_filesize; 
}

static void
syscall_handler (struct intr_frame *f ) 
{
  int * p = f->esp;
  checkpointer(p+1);
  thread_current()->current_esp = f->esp;
  int type = * p;
  if(type < 0 || type >=max_syscall){
      err_exit();
  }

  syscalls[type](f);

}

static void* checkpointer(const void *vaddr){
    // if(vaddr==NULL){
    //    err_exit();
    // }
    if(!is_user_vaddr(vaddr)){
       err_exit();
    }
    void* ptr = pagedir_get_page(thread_current()->pagedir,vaddr);
    // if(ptr == NULL){
    //     err_exit(); 
    // } 
    uint8_t *check_byteptr = (uint8_t *) vaddr;
    for (uint8_t i = 0; i < 4; i++) 
    {
        if (get_user(check_byteptr + i) == -1)
        {
          err_exit();
        }
    }
    return ptr;
}
static void err_exit(void){
    thread_current()->exit_code = -1;
    thread_exit();
}
void sys_halt(struct intr_frame* f UNUSED){
    shutdown_power_off();
}
void sys_exit(struct intr_frame* f){
    uint32_t *ptr = f->esp;
    ptr++;
    thread_current()->exit_code = *ptr;
    thread_exit();
}
void sys_exec(struct intr_frame* f){
    uint32_t *ptr = f->esp;
    checkpointer(ptr + 1);
    checkpointer((const void *)*(ptr+1));
    ptr++;
    f->eax = process_execute((char *)*(ptr));//record the return value
}
void sys_create(struct intr_frame* f){
    uint32_t *user_ptr = f->esp;
    checkpointer(user_ptr + 5);//for tests maybe?
    checkpointer((const void*)*(user_ptr + 4));
    user_ptr++;
    acquire_lock_f();
    f->eax = filesys_create((const char*)*user_ptr,*(user_ptr+1));
    release_lock_f();
}
void sys_remove(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 1);
  checkpointer((const void *)(user_ptr + 1));
  user_ptr++;
  acquire_lock_f();
  f->eax = filesys_remove ((const char *)*user_ptr);
  release_lock_f();
}
void sys_open(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 1);
  checkpointer((const void *)*(user_ptr + 1));
  user_ptr++;
  acquire_lock_f();
  struct file * file_opened = filesys_open((const char *)*user_ptr);
  release_lock_f();
  struct thread * t = thread_current();
  if (file_opened)
  {
    struct thread_file *thread_file_temp = malloc(sizeof(struct thread_file));
    thread_file_temp->fd = t->max_file_fd++;
    thread_file_temp->file = file_opened;
    list_push_back(&(t->files), &(thread_file_temp->file_elem));
    f->eax = thread_file_temp->fd;
  } 
  else// 文件没有打开
  {
    f->eax = -1;
  }
}
void sys_wait(struct intr_frame* f){
    uint32_t* ptr = f->esp;
    checkpointer(ptr+1);
    ptr++;
    f->eax = process_wait(*ptr);
}
void sys_filesize(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 1);
  user_ptr++;
  struct thread_file * thread_file_temp = find_file_id (*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f();
    f->eax = file_length (thread_file_temp->file);//return the size in bytes
    release_lock_f();
  } 
  else
  {
    f->eax = -1;
  }
}

void sys_read(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  user_ptr++;
  int fd = *user_ptr;
  uint8_t * buffer = (uint8_t*)*(user_ptr+1);
  off_t size = *(user_ptr+2);

  // if (!is_valid_pointer (buffer, 1) || !is_valid_pointer (buffer + size,1)){
  //   err_exit();
  // }
  check_and_preload_buffer(buffer,size,true);

  if (fd == 0)//stdin
  {
    for (int i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  }
  else
  {
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f();
      f->eax = file_read (thread_file_temp->file, buffer, size);
      release_lock_f();
    } 
    else
    {
      f->eax = -1;
    }
  }
  unpin_buffer(buffer, size);
}

void sys_write(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 7);//(神秘check)
  checkpointer((void *)*(user_ptr + 6));
  user_ptr++;
  int fd = *user_ptr;
  const char * buffer = (const char *)*(user_ptr+1);
  off_t size = *(user_ptr+2);
  check_and_preload_buffer((void*)buffer, size, true);
  if (fd == 1) {
    putbuf(buffer,size);
    f->eax = size;
  }
  else
  {
    /* Write to Files */
    struct thread_file * thread_file_temp = find_file_id (*user_ptr);
    if (thread_file_temp)
    {
      acquire_lock_f();
      f->eax = file_write (thread_file_temp->file, buffer, size);
      release_lock_f();
    } 
    else
    {
      f->eax = 0;//can't write,return 0
    }
  }
  unpin_buffer((void*)buffer,size);
}

void sys_seek(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 5);
  user_ptr++;//fd
  struct thread_file *file_temp = find_file_id (*user_ptr);
  if (file_temp)
  {
    acquire_lock_f();
    file_seek (file_temp->file, *(user_ptr+1));
    release_lock_f();
  }
}
void sys_tell(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 1);
  user_ptr++;
  struct thread_file *thread_file_temp = find_file_id (*user_ptr);
  if (thread_file_temp)
  {
    acquire_lock_f();
    f->eax = file_tell (thread_file_temp->file);
    release_lock_f();
  }else{
    f->eax = -1;
  }
}
void sys_close(struct intr_frame* f){
  uint32_t *user_ptr = f->esp;
  checkpointer(user_ptr + 1);
  user_ptr++;
  struct thread_file * opened_file = find_file_id (*user_ptr);
  if (opened_file)
  {
    acquire_lock_f();
    file_close (opened_file->file);
    release_lock_f();
    list_remove (&opened_file->file_elem);
    free (opened_file);
  }
}

struct thread_file * find_file_id (uint32_t file_id){
  struct list_elem *e;
  struct thread_file * thread_file_temp = NULL;
  struct list *files = &thread_current ()->files;
  for (e = list_begin (files); e != list_end (files); e = list_next (e)){
    thread_file_temp = list_entry (e, struct thread_file, file_elem);
    if (file_id == thread_file_temp->fd)
       return thread_file_temp;
  }
  return false;
}
bool is_valid_pointer (void* esp,uint8_t argc){
    return  esp != NULL && is_user_vaddr(esp);
  // for (uint8_t i = 0; i < argc; ++i)
  // {
  //   if((!is_user_vaddr (esp)) || (pagedir_get_page (thread_current()->pagedir, esp)==NULL)){
  //     return false;
  //   }
  // }
  // return true; 
}
/* 在 syscall.c 中实现 */
static
void check_and_preload_buffer (void *buffer, unsigned size, bool writable) {

    char *start = pg_round_down(buffer);
    char *end = pg_round_down((char *)buffer + size - 1);
    for (char *p = start; p <= end; p += PGSIZE) {
        if (!is_user_vaddr (p)) err_exit();
        
        /* 1. 触发缺页：确保 handle_mm_default 被调用并将页加载到内存 */
        if (writable) {
            volatile char *vp = (volatile char *)p;
            *vp = *vp;
            // *(char *)p = *(char *)p;
        }
        else { char temp = *(char *)p; (void)temp; }
        
        /* 2. 获取物理地址：只有加载后，pagedir 才有这个映射 */
        void *kpage = pagedir_get_page(thread_current()->pagedir, p);
        
        /* 3. 钉住物理帧：防止在 acquire_lock_f 等待期间被驱逐 */
        if (kpage != NULL) {
            vm_frame_set_pinned(kpage, true);
        }
    }
}

static void unpin_buffer(void *buffer, unsigned size) {
    char *start = pg_round_down(buffer);
    char *end = pg_round_down((char *)buffer + size - 1);
    for (char *p = start; p <= end; p += PGSIZE) {
        void *kpage = pagedir_get_page(thread_current()->pagedir, p);
        if (kpage) vm_frame_set_pinned(kpage, false);
    }
}
static int get_user(const uint8_t *uaddr){
    int result;
    asm ("movl $1f, %0; movzbl %1, %0; 1:" : "=&a" (result) : "m" (*uaddr));
    return result;
}
// static void check_buffer(const void *vaddr, size_t size) {
//     if (vaddr == NULL) err_exit();
//     const char *ptr = (const char *)vaddr;
//     for (size_t i = 0; i < size; i++) {
//         if (!is_user_vaddr(ptr + i) || pagedir_get_page(thread_current()->pagedir, ptr + i) == NULL) {
//             err_exit();
//         }
//     }
// }
