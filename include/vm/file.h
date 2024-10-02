#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"
#include <string.h>
#include "userprog/syscall.h"

struct page;
enum vm_type;

struct file_args{
    struct file* file;
	int fd;
	size_t page_read_bytes;
	size_t page_zero_bytes;
    off_t ofs;
};

struct file_page {
	struct file_args args;
	struct list_elem elem;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
void *do_mmap(void *addr, size_t length, int writable,
		struct file* file, off_t offset);
void do_munmap (void *va);
#endif
