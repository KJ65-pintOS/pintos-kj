/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include <stdio.h>

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);
static bool lazy_load_file (struct page *page, void *aux);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;

    struct file_page *file_page = &page->file;

    /* Get the lazy load information */
    struct lazy_load_info *aux = (struct lazy_load_info *)page->uninit.aux;
    file_page->file = aux->file;
    file_page->ofs = aux->ofs;
    file_page->page_read_bytes = aux->page_read_bytes;
    file_page->page_zero_bytes = aux->page_zero_bytes;

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
    struct file_page *file_page = &page->file;

    /* 페이지가 더러운지 확인하고, 파일에 다시 쓰기 */
    if (file_page->file && pml4_is_dirty(thread_current()->pml4, page->va)) {
        /* 파일에 페이지를 다시 씁니다. */
        if (file_write_at(file_page->file, page->va, file_page->page_read_bytes, file_page->ofs) != (int)file_page->page_read_bytes) {
        }

        /* 페이지가 더 이상 더럽지 않다고 표시 */
        pml4_set_dirty(thread_current()->pml4, page->va, false);
    }

    /* 페이지 테이블에서 페이지를 제거 */
	pml4_clear_page(thread_current()->pml4, page->va);
	
}


/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
        struct file *file, off_t offset) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    void *start_addr = addr;
    size_t read_bytes = length;
    size_t zero_bytes = (PGSIZE - (length % PGSIZE)) % PGSIZE;

    // Check if file reopened successfully
    struct file *f = file_reopen(file);
    if (!f) {
        return NULL;
    }

    // Calculate total pages to be mapped
    int total_page_count = (length + PGSIZE - 1) / PGSIZE;

    while (read_bytes > 0 || zero_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct lazy_load_info *aux = malloc(sizeof(struct lazy_load_info));
        if (aux == NULL) {
            file_close(f);
            return NULL;
        }

        aux->file = f;
        aux->ofs = offset;
        aux->page_read_bytes = page_read_bytes;
        aux->page_zero_bytes = page_zero_bytes;

        if (!vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_load_file, aux)) {
            file_close(f);
            free(aux);
            return NULL;
        }

        struct page *p = spt_find_page(&thread_current()->spt, addr);
        if (p == NULL) {
            file_close(f);
            return NULL;
        }
        // Set the mapped page count for each page
        p->mappped_page = total_page_count;

        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        addr += PGSIZE;
        offset += page_read_bytes;
    }
    return start_addr; 
}



static bool
lazy_load_file (struct page *page, void *aux){
    struct lazy_load_info *info = (struct lazy_load_info *) aux;

    file_seek(info->file, info->ofs);
    int read_bytes = file_read(info->file, page->frame->kva, info->page_read_bytes);
    if (read_bytes == -1) {
        return false;
    }

    // 읽은 바이트가 예상보다 적으면 나머지 부분을 0으로 채움
    if (read_bytes < (int)info->page_read_bytes) {
        memset(page->frame->kva + read_bytes, 0, info->page_read_bytes - read_bytes);
    }

    // 페이지의 나머지 0으로 채우기
    memset(page->frame->kva + info->page_read_bytes, 0, info->page_zero_bytes);
    return true;
}



/* Do the munmap */
void do_munmap(void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *p = spt_find_page(spt, addr);

    if (p == NULL) {
        return;
    }

    int count = p->mappped_page;
    for (int i = 0; i < count; i++) {

        if (p) {
            file_backed_destroy(p);
			addr += PGSIZE;
        	p = spt_find_page(spt, addr);
        }

    }
}







