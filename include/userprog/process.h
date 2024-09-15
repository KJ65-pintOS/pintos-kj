#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);


/*********************************************/
/* file descriptor, project 2 */
#ifdef USERPROG

#include "filesys/file.h"
#include <list.h>
#include <string.h>
#include "threads/synch.h"

#define FD_MAX_SIZE 512
#define FD_MIN_SIZE 0
struct fd_table{
   struct file* fd_array[FD_MAX_SIZE];
};


#define init_fd(struct_fd) ( {memset(struct_fd, 0 , sizeof(struct fd_table)); memset(struct_fd, 1 , 16 );})

#define is_occupied(struct_fd, index ) ( struct_fd->fd_array[index] != 0 )

#define is_empty(struct_fd, index) ( struct_fd->fd_array[index] == 0)

#define is_file(struct_fd, index) (strucr_fd->fd_array[index] != 0 && 0) // 수정해야함.

#define is_valid_fd(struct_fd, index)

#define get_user_fd(thread) (thread->fd_table)

#define get_file(struct_fd , index) (struct_fd->fd_array[index])

#define free_fd(struct_fd, index) (struct_fd->fd_array[index] = (void*)0)

// struct_fd, file should be a pointer
#define set_fd(struct_fd, index, file ) ( struct_fd->fd_array[index] = file)

int find_empty_fd(struct fd_table * fd_array);

struct child {
    tid_t tid;
    bool success;
    int exit_code;
    struct thread* thread;
    struct thread* parent;
    struct lock lock;
    struct semaphore sema;
    struct list_elem elem;
};


#endif
/* file descriptor, project 2 */
/*********************************************/





#endif /* userprog/process.h */


