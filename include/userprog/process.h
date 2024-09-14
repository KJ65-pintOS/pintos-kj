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
/*
   이거 사용하고 싶으면 가장 먼저 init_fd 해라 ㅇㅋ?
*/

// struct_fd should be a pointer
#define init_fd(struct_fd) ( {memset(struct_fd, 0 , sizeof(struct fd_table)); memset(struct_fd, 1 , 16 );})
// struct_fd should be a pointer
#define is_occupied(struct_fd, index ) ( struct_fd->fd_array[index] != 0 )

// struct_fd should be a pointer
#define is_empty(struct_fd, index) ( struct_fd->fd_array[index] == 0)

#define is_file(struct_fd, index) (strucr_fd->fd_array[index] != 0 && 0) // 수정해야함.

#define is_valid_fd(struct_fd, index)

#define get_user_fd(thread) (thread->fd_table)

#define get_file(struct_fd , index) (struct_fd->fd_array[index])

#define free_fd(struct_fd, index) (struct_fd->fd_array[index] = (void*)0)

// struct_fd, file should be a pointer
#define set_fd(struct_fd, index, file ) ( struct_fd->fd_array[index] = file)

int find_empty_fd(struct fd_table * fd_array);




/*
    fd_lock init 해라.
    fd_array pml4 만들어라
    threads list init 해라
*/


struct fork_args {
    struct thread *parent;
    struct intr_frame *fork_intr_frame;
    struct semaphore fork_sema;
    // sema
    // reason being killed
};

#endif
/* file descriptor, project 2 */
/*********************************************/





#endif /* userprog/process.h */


