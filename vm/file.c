/* file.c: Implementation of memory backed file object (mmaped object). */
// file-backed page를 위한 기능을 제공합니다 (vm_type = VM_FILE).
#include "vm/vm.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm 
	파일 지원 페이지 하위 시스템을 초기화합니다. 이 기능에서는 파일 백업 페이지와 관련된 모든 것을 설정할 수 있습니다.
*/
void
vm_file_init (void) {
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
}

bool is_valid_mmap(void *addr, size_t length, bool writable, int fd, off_t offset) {
	void *ofs = pg_ofs(addr);
	if (addr == NULL || pg_ofs(addr) != NULL || addr >= (KERN_BASE - PGSIZE) || length == 0 || fd < 2 || fd > 512 || offset != 0)
		return false;
	struct page *page = spt_find_page(&thread_current()->spt, addr);

	return page == NULL;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {

	struct file *reopened = file_reopen(file);

	if (file_length(reopened) == NULL)
		goto err;
	if (writable)
		file_allow_write(reopened);

err:
	file_close(reopened);
	thread_kill();
}

/* Do the munmap */
void
do_munmap (void *addr) {
	// any change in the content is reflected in the file
}
