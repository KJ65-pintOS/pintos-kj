#ifndef VM_FILE_H
#define VM_FILE_H
#include "filesys/file.h"
#include "vm/vm.h"
#include <list.h>

struct page;
enum vm_type;

struct file_page {
	struct page *page;
	struct load_args *load_args;
	struct list_elem elem;
};

void vm_file_init (void);
bool file_backed_initializer (struct page *page, enum vm_type type, void *kva);
bool is_valid_mmap(void *addr, size_t length, bool writable, int fd, off_t offset);
void *do_mmap(void *addr, size_t length, int writable,
		struct file *file, off_t offset);
void do_munmap(void *va);
void implicit_munmap(struct supplemental_page_table* spt);
#endif
