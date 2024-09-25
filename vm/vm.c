/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/*************************************************/


static uint64_t 
page_hash(const struct hash_elem *e_, void *aux);
static bool 
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
static struct page *
page_lookup (struct hash* hash, const void *va);

/*************************************************/

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
	struct page* page;
	vm_initializer* initializer = NULL;
	
	upage = pg_round_down(upage);

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,*/

		if((page = (struct page*)malloc(sizeof(struct page))) == NULL){
			/* malloc에 실패하는 경우 */
			return false;
		}

		switch(type){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:
				goto err;
		}
		if(initializer == NULL){
			/* error 동작 */
			free(page);
			return false;
		}
		
		/* TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		
		uninit_new(page,upage,init,type,aux,initializer);
		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		return spt_insert_page(spt,page);
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	if(hash_empty(&spt->page_hash))
		return NULL;
	return page_lookup(&spt->page_hash,pg_round_down(va));
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	int succ = false;
	
	if(!spt_find_page(spt, page->va)){
		lock_acquire(&spt->lock);
		if(hash_insert(&spt->page_hash, &page->hash_elem)){
			/* hash insert 실패한 경우, 이미 해당 hash가 존재  */
		}
		lock_release(&spt->lock);
		succ = true;
	}
	return succ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	if(spt_find_page(spt, page->va)){
		lock_acquire(&spt->lock);
		if(hash_delete(&spt->page_hash,&page->hash_elem) == NULL){
			/* hash_delete 실패한 경우 */
		}
		lock_release(&spt->lock);
		vm_dealloc_page (page);
	}
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

	if((frame = (struct frame*)calloc(1,sizeof(struct frame))) == NULL){
		/* malloc 실패한 경우 */
		return NULL;
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	if((frame->kva = palloc_get_page(PAL_USER)) == NULL){
		/* page 할당에 실패하는 경우 */
		free(frame);
		return NULL;
		/* TODO: evict the frame */
	}
	/* initialize member */

	return frame;
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

	struct supplemental_page_table *spt;
	struct page *page;
	bool succ;

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	succ = false;
	spt = &thread_current()->spt;

	if((page = spt_find_page(spt,addr)) == NULL){
		/* page가 없는경우, 이상동작, 종료 */
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}

	if(vm_do_claim_page (page))
		succ = true;

	return succ;
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
	/* TODO: Fill this function */
	struct supplemental_page_table *spt;
	struct page *page;
	bool succ;

	va = pg_round_down(va);
	succ = false;
	spt = &thread_current()->spt;

	if((page = spt_find_page(spt, va)) == NULL){
		/* page가 존재하지 않는 경우 , 이상 동작 이므로 종료 */
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}
	if(vm_do_claim_page (page))
		succ = true;

	return succ;
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {

	struct frame *frame;
	uint64_t *pml4;
	bool succ;

	frame = vm_get_frame();
	pml4 = thread_current()->pml4;
	succ = false;

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(!pml4_set_page(pml4, page->va, frame->kva, page->writable ))
		return false;
	if(swap_in (page, frame->kva))
		succ = true;
	return succ;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* init, fork에서 호출되는 함수, fork를 대비해서 memset 0으로 초기화 */
	memset(spt, 0, sizeof(spt));
	hash_init(&spt->page_hash, page_hash, page_less, NULL);
	lock_init(&spt->lock);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	if( src == NULL)
		return false;
	memcpy(dst, src, sizeof(src));
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	//hash_destroy(&spt->page_hash, NULL);
}

/***********************************************************************/
/* hash func */
static uint64_t 
page_hash(const struct hash_elem *e_, void *aux){
  const struct page *e = hash_entry (e_, struct page, hash_elem);
  return hash_bytes (&e->va, sizeof e->va);
}
static bool 
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux){
	const struct page *a = hash_entry (a_, struct page, hash_elem);
	const struct page *b = hash_entry (b_, struct page, hash_elem);
	return a->va < b->va;
}

static struct page *
page_lookup (struct hash* hash, const void *va) {
  struct page p;
  struct hash_elem *e;

  p.va = pg_round_down(va);
  e = hash_find (hash, &p.hash_elem);
  return e != NULL ? hash_entry (e, struct page, hash_elem) : NULL;
}
/***********************************************************************/