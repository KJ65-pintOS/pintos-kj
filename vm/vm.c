/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "hash.h"
#include <string.h>
#include "vm/uninit.h"
#include <stdio.h>

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	list_init(&frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		/* TODO: Insert the page into the spt. */
		struct page *page = malloc(sizeof(struct page));
		if (page == NULL)
		{
			goto err;
		}
		vm_initializer *initializer = NULL;
		switch (VM_TYPE(type))
		{
		case VM_ANON:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
		default:
			goto err;
		}
		uninit_new(page, upage, init, type, aux, initializer);
		page->writable = writable;

		if (!spt_insert_page(spt, page))
		{
			free(page);
			goto err;
		}
	}
	return true;
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page target_page;
	target_page.va = pg_round_down(va);
	struct hash_elem *elem = hash_find(&spt->spt_hash, &target_page.spt_hash_elem);

	if (elem != NULL)
	{
		return hash_entry(elem, struct page, spt_hash_elem);
	}
	return NULL;	
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	lock_acquire(&spt->spt_lock);
	struct hash_elem *elem = hash_insert(&spt->spt_hash, &page->spt_hash_elem);
	lock_release(&spt->spt_lock);

	if (elem == NULL)
	{
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	void *kva = palloc_get_page(PAL_USER);  // 사용자 풀에서 새 물리 메모리 가져오기
	if (kva == NULL)  // 사용가능한 페이지가 없다면
	{
		PANIC("todo");  //swap 구현
	}
	frame = malloc(sizeof(struct frame));  // 프레임 할당
	frame->kva = kva;  // 성공적으로 물리 페이지를 가져오면 프레임 초기화
	frame->page = NULL;
	list_push_back(&frame_table, &frame->frame_elem);  // 할당한 프레임을 프레임 테이블에 입력
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;  // 할당된 프레임 반환
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (addr == NULL)
	{
		return false;
	}
	if (!is_user_vaddr(addr))
	{
		return false;
	}
	if (not_present)
	{
		page = spt_find_page(spt, addr);
		if (page == NULL)
		{
			return false;
		}
		if (write == 1 && page->writable == 0)
		{
			return false;
		}
	return vm_do_claim_page (page);
	}
	return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);  // spt에서 va에 해당하는 페이지 찾기

	if (page == NULL)  // spt에 페이지가 없으면 false 반환
	{
		return false;
	}

	return vm_do_claim_page (page);  // 물리 메모리 클레임
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();  //프레임 얻어오기

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *current = thread_current();
	pml4_set_page(current->pml4, page->va, frame->kva, page->writable);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->spt_hash, page_hash, page_less, NULL);
	lock_init(&spt->spt_lock);
}

unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED){
	const struct page *p = hash_entry(p_, struct page, spt_hash_elem);
	return hash_bytes(&p->va, sizeof p->va);
}

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
	const struct page *a = hash_entry(a_, struct page, spt_hash_elem);
	const struct page *b = hash_entry(b_, struct page, spt_hash_elem);
	return a->va < b->va;
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	struct hash_iterator i;
	hash_first(&i, &src->spt_hash);
	while (hash_next(&i))
	{
		struct page *src_page = hash_entry(hash_cur(&i), struct page, spt_hash_elem);
		enum vm_type type = src_page->operations->type;
		void *upage = src_page->va;
		bool writable = src_page->writable;
		
		if (type == VM_UNINIT)
		{
			vm_initializer *init = src_page->uninit.init;
			void *aux = src_page->uninit.aux;
			vm_alloc_page_with_initializer(VM_ANON, upage, writable, init, aux);
			continue;
		}
		if (!vm_alloc_page(type, upage, writable))
		{
			return false;
		}
		if (!vm_claim_page(upage))
		{
			return false;
		}
		
		struct page *dst_page = spt_find_page(dst, upage);
		memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->spt_hash, clear_page);
}

void clear_page(struct hash_elem *e, void *aux){
	struct page *page = hash_entry(e, struct page, spt_hash_elem);
	destroy(page);
	free(page);
}