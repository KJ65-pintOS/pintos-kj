#include <stdbool.h>
#include "threads/vaddr.h"
#include "filesys/file.h"

#define FDSIZE (PGSIZE / 8)

typedef struct file *fd_array[FDSIZE];

int fd_open(const char *, fd_array);
int fd_filesize(int, fd_array);
int fd_read(int, void *, unsigned, fd_array);
int fd_write(int, const void *, unsigned, fd_array);
void fd_seek(int, unsigned, fd_array);
unsigned fd_tell(int, fd_array);
void fd_close(int, fd_array);
int fd_dup2(int, int, fd_array);

void fd_close_all(fd_array);
