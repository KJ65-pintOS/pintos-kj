#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

#define get_fd_table(thread) (thread->fd_table)
struct file* 
get_file_by_fd(int fd);

#endif /* userprog/syscall.h */
