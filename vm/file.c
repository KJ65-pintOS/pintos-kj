/* file.c: Implementation of memory backed file object (mmaped object). */
// file-backed page를 위한 기능을 제공합니다 (vm_type = VM_FILE).
#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include <list.h>
#include "threads/mmu.h"
#include "threads/malloc.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
bool lazy_load_file(struct page *page, void *aux);
void free_resources(struct file_page *fpage);
void write_back(struct file *mm_file, struct file_page *fpage);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

struct lock file_lock;

/* The initializer of file vm 
	파일 지원 페이지 하위 시스템을 초기화합니다. 이 기능에서는 file_backed_page와 관련된 모든 것을 설정할 수 있습니다.
*/
void
vm_file_init (void) {
	lock_init(&file_lock);
}

/* Initialize the file backed page 
	파일 지원 페이지를 초기화합니다. 이 함수는 먼저 page->operations에서 file_backed_page에 대한 핸들러를 설정합니다. 
	메모리를 지원하는 파일과 같은 페이지 구조에 대한 일부 정보를 업데이트할 수 있습니다.
*/
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page->page = page;
	file_page->load_args = NULL;

	return true;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	// any change in the content is reflected in the file
}

/* Destory the file backed page. PAGE will be freed by the caller. 
	관련 파일을 닫아 파일 지원 페이지를 파괴합니다. 
	내용이 dirty인 경우 변경 사항을 파일에 다시 기록해야 합니다. 
	이 함수에서 페이지 구조를 free할 필요는 없습니다. file_backed_destroy의 호출자는 이를 처리해야 합니다.
*/
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
	free(file_page->load_args);
}

bool is_valid_mmap(void *addr, size_t length, bool writable, int fd, off_t offset) {
	void *ofs = pg_ofs(addr);
	if (addr == NULL || pg_ofs(addr) != NULL || addr >= (KERN_BASE - PGSIZE) || length == 0 || fd < 2 || fd > 512 || pg_ofs(offset) != NULL)
		return false;
	struct page *page = spt_find_page(&thread_current()->spt, addr);

	return page == NULL;
}
/* Do the mmap */
/*
	1. load_segment like
		- file에 writable을 set한다
		- file을 PGSIZE 단위로 읽는다
			- 한번에 읽는 byte가 PGSIZE보다 작은 경우를 위한 page_zero_bytes를 설정한다
			- offset을 갱신한다
			- page_fault 시 메모리 매핑할 함수를 만든다 -> mmap_handle_fault
			- 이 때 사용할 args를 set한다
	2. lazy_load like 
*/
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	size_t read_bytes = length;
	void *upage = addr;
	
	while (read_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct load_args *aux = malloc(sizeof(struct load_args));
		if (aux == NULL){
			file_close(file);
			return;
		}
		aux->file = file;
		aux->ofs = offset;
		aux->page_read_bytes = page_read_bytes;
		aux->page_zero_bytes = page_zero_bytes;
		aux->writable = writable;

		if (!vm_alloc_page_with_initializer(VM_FILE, upage, writable, lazy_load_file, aux)) {
			file_close(file);
			return;
		}
		
		/* Advance */
		read_bytes -= page_read_bytes;
		upage += PGSIZE;
		offset += page_read_bytes;
	}
	return;
}

bool lazy_load_file(struct page *page, void *aux) {
	struct load_args *load_args = (struct load_args*)aux;
	uint8_t *kpage = (uint8_t *)page->frame->kva;

	page->file.load_args = load_args;

	file_seek(load_args->file, load_args->ofs);

	size_t page_read_bytes = load_args->page_read_bytes;
	if (file_read(load_args->file, kpage, page_read_bytes) != (int)page_read_bytes) {
		palloc_free_page(kpage);
		free(aux);
		return false;
	}

	memset(kpage + page_read_bytes, 0, load_args->page_zero_bytes);

	list_push_back(&thread_current()->mm_pages, &page->file.elem);
	
	return true;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// any change in the content is reflected in the file
	/*
		- file_page의 mm_pages를 순회한다.
		- if dirty bit이 set 되어 있으면 file_write를 한다
			- dirty bit check은 첫 addr만 확인하면 된다
			- file에 대한 정보도 첫 addr만 있으면 된다
			- page_read_bytes & offset은 file_page 별로 있어야 함
			- 위 정보들은 lazy_load_file에서 넣어준다
		- 아니면 똑같이 memcpy을 해주면 안되나?.
		- frame & page를 free 한다
		pml4에서도 삭제한다
		file을 close한다
		로직을 구체적으로 짜야겠다... 계속 수정이 일어나네
	*/
	struct page *start_file_page = spt_find_page(&thread_current()->spt, addr);
	if (start_file_page == NULL)
		return;
	struct file *mm_file = start_file_page->file.load_args->file;
	struct list *mm_pages = &thread_current()->mm_pages;
	bool is_dirty = pml4_is_dirty(thread_current()->pml4, start_file_page->va);
	list_remove(&start_file_page->file.elem);
	struct list_elem *e;
	while (!list_empty(mm_pages)) {
		e = list_pop_front(mm_pages);
		struct file_page *fpage = list_entry(e, struct file_page, elem);		
        if (is_dirty)
        	write_back(mm_file, fpage);
    	free_resources(fpage);
    }
	if (is_dirty)
		write_back(mm_file, &start_file_page->file);
	file_close(mm_file);
	free_resources(&start_file_page->file);
}

void implicit_munmap(struct supplemental_page_table* spt) {
	struct thread *currunt = thread_current();

	if (list_empty(&currunt->mm_pages))
		return;
	struct list_elem *e;
	while (!list_empty(&currunt->mm_pages)) {
		e = list_pop_front(&currunt->mm_pages);
		struct file_page *fpage = list_entry(e, struct file_page, elem);		
		do_munmap(fpage->page->va);
	}
}

void free_resources(struct file_page *fpage)
{
    struct page *page = fpage->page;
	pml4_clear_page(thread_current()->pml4, page->va);
	spt_remove_page(&thread_current()->spt, page);
}

void write_back(struct file *mm_file, struct file_page *fpage) {
	size_t offset = fpage->load_args->ofs;
	size_t page_read_bytes = fpage->load_args->page_read_bytes;
    lock_acquire(&file_lock);
    file_seek(mm_file, offset);
    if (file_write(mm_file, fpage->page->frame->kva, page_read_bytes) != page_read_bytes){
		lock_release(&file_lock);
		thread_kill();
	}
    lock_release(&file_lock);
}

