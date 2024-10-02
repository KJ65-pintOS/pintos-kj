/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool file_backed_duplicate (struct page *dst_page, struct page *src_page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.duplicate = file_backed_duplicate,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
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
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
//1. 가상주소 공간 예약
//2. 파일, 오프셋, 크기, 권한 등의 매핑 정보 기록하기
//3. 페이지 테이블 엔트리 설정-->해당 가상 주소 범위에 대한 페이지 테이블 엔트리를 생성하지만
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	struct supplemental_page_table *spt = &thread_current()->spt;
	struct page *page = spt_find_page(spt, addr);
	bool success;

	//기존 매핑된 페이지 집합(실행가능 파일이 동작하는 동안 매핑된 스택 또는 페이지를 포함)과 겹칠때

	//mmap-inherit

}

/* Do the munmap */
void
do_munmap (void *addr) {
}


/*********************************/
/*project 3*/
static bool file_backed_duplicate (struct page *dst_page, struct page *src_page) {
	return true;

}
/*********************************/