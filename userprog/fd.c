#include "filesys/file.h"
#include "userprog/fd.h"
#include <stddef.h>

void fd_close_all(fd_array fd_array) {
    for (int fd = 0; fd < FDSIZE; ++fd) {
        fd_close(fd, fd_array);
    }
}

void fd_close(int fd, fd_array fd_array) {
    struct file *file;
    int ret;

    if (!check_fd(fd))
        return 0;
    
    file = fd_array[fd];

    if (file == stdin || file == stdout) 
        fd_array[fd] = NULL;
    else if (file) {
        file_close(file);
        fd_array[fd] = NULL;
    }
}

static bool check_fd(int fd) {
    if (0 <= fd && fd < FDSIZE)
        return true;
    return false;
}