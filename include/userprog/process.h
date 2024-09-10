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

#include "filesys/file.h"
#include <list.h>
#include <string.h>
#include "threads/synch.h"

struct file_descriptor{
   struct file* fd[512];
};
/*
   이거 사용하고 싶으면 가장 먼저 init_fd 해라 ㅇㅋ?
*/

// struct_fd should be a pointer
#define init_fd(struct_fd) ( memset(struct_fd, 0 , sizeof(struct file_descriptor))) // 이거 될지 모르겠음
#define init_fd2(struct_fd) (memset(struct_fd, 1 , 16 ));
// struct_fd should be a pointer
#define is_occupied(struct_fd, index ) ( struct_fd->fd[index] != 0 )

#define get_file(struct_fd , index) (struct_fd->fd[index])
// struct_fd should be a pointer
#define is_empty(struct_fd, index) ( struct_fd->fd[index] == 0)

// struct_fd, file should be a pointer
#define set_fd(struct_fd, index, file ) ( struct_fd->fd[index] = file)

int find_empty_fd(struct file_descriptor * fd);


struct process { // 공유자원 
    char name[16];
    struct list threads;

    struct file_descriptor *fd;
    struct lock fd_lock;

    struct list_elem elem;
};

/*
    fd_lock init 해라.
    fd pml4 만들어라
    threads list init 해라
*/

#define process_entry(list_elem) (list_entry( list_elem, struct process, elem))

/* file descriptor, project 2 */
/*********************************************/


struct fork_args {
    struct thread *parent;
    struct intr_frame *fork_intr_frame;
    struct semaphore fork_sema;
    // sema
    // reason being killed
};


#endif /* userprog/process.h */


