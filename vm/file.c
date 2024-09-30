/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool
file_backed_duplicate(struct page* dst, const struct page* src);
static bool 
mmap_lazy_load_segment(struct page* page, void* aux);


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
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
	
	void* tmp_addr =  addr;
	

	off_t file_len = file_length(file);

	uint32_t read_bytes = file_len < length? file_len : length;
	uint32_t zero_bytes = length - read_bytes;

	ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
	ASSERT (pg_ofs (addr) == 0);

	/* vm, project 3 */
	struct load_args* args;
	void *aux;

	while (read_bytes > 0 || zero_bytes > 0) {
		/* Do calculate how to fill this page.
		 * We will read PAGE_READ_BYTES bytes from FILE
		 * and zero the final PAGE_ZERO_BYTES bytes. */
		size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
		size_t page_zero_bytes = PGSIZE - page_read_bytes;

		/* TODO: Set up aux to pass information to the lazy_load_segment. */
		/* vm, project 3 */
		
		aux = NULL;
		args = (struct load_args*)malloc(sizeof(struct load_args));
		args->file = file;
		args->page_read_bytes = page_read_bytes;
		args->page_zero_bytes = page_zero_bytes;
		args->ofs = offset;
		aux = args;

		if (!vm_alloc_page_with_initializer (VM_FILE, tmp_addr,
					writable, mmap_lazy_load_segment, aux))
			return NULL;

		/* Advance. */
		read_bytes -= page_read_bytes;
		zero_bytes -= page_zero_bytes;
		tmp_addr += PGSIZE;
		offset += page_read_bytes;
	}
	return addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
}

static bool
file_backed_duplicate(struct page* dst, const struct page* src){
	memcpy(dst,src,sizeof(struct page));
	dst->frame = NULL;
	do_claim(dst);
	memcpy(dst->frame->kva, src->frame->kva,PGSIZE); 
	return true;
}

static bool 
mmap_lazy_load_segment(struct page* page, void* aux){

	struct load_args* args;
	struct file* file;
	struct frame* f;
	void * kva;
	off_t ofs;

	size_t page_read_bytes;
	size_t page_zero_bytes;
	
	if(aux == NULL)
		return false;

	args = (struct loadargs*)aux;
	file = args->file;
	page_read_bytes = args->page_read_bytes;
	page_zero_bytes = args->page_zero_bytes;
	ofs = args->ofs;
	//struct thread* t = thread_current();
	free(aux);

	file_seek(file,ofs);
	int test = file_read (file, kva, page_read_bytes);
	if ( test != (int) page_read_bytes) {
		//palloc_free_page (kva);
		return false;
	}
	memset (kva + page_read_bytes, 0, page_zero_bytes);
	return true;
}
