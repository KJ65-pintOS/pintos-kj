/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
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

// 링커 오류 해결을 위한 load_info구조체 file.c안에 선언
struct load_info_mmap
{
	struct file *file; // 파일 포인터
	off_t offset;	   // 파일 오프셋
	size_t page_read_bytes; // 파일에서 읽을 바이트 수
	size_t page_zero_bytes; // 0으로 채울 바이트 수
	bool writable;	   // 페이지가 쓰기 가능한지 여부
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

static bool
lazy_load_segment_mmap (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	struct load_info *info = (struct load_info*)aux; 

	// file 오프셋 설정
	file_seek(info->file, info->offset);

	// 피일에서 페이지 데이터 로드
	if(file_read(info->file, page->frame->kva, info->page_read_bytes) != (int) info->page_read_bytes) {
		palloc_free_page(page->frame->kva); // 실패시 페이지 메모리 해제
		return false;
	}
	memset(page->frame->kva + info->page_read_bytes, 0, info->page_zero_bytes);
	
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	// lazy loading 구현 필요
	size_t read_bytes = length; // 매핑할 데이터의 크기 
	size_t zero_bytes = PGSIZE- (length % PGSIZE); // 남은데이터를 0으로 채울 크기
	uint8_t first_addr = addr;

	while(read_bytes > 0 || zero_bytes > 0) {
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		struct load_info_mmap *aux = malloc(sizeof(struct load_info_mmap));
		struct load_info_mmap load_info_mmap = {
			.file = file,
			.offset = offset,
			.page_read_bytes = page_read_bytes,
			.page_zero_bytes = PGSIZE - page_read_bytes
		};

		memcpy(aux, &load_info_mmap, sizeof(struct load_info_mmap));

		if(!vm_alloc_page_with_initializer(VM_ANON, addr,
					writable, lazy_load_segment_mmap, aux)) {
			return NULL;
		}
			

		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		addr += PGSIZE;
		offset += page_read_bytes;
	}
	return first_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}
