/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"


/*************************************************/
#include <string.h>
#include <userprog/process.h>

static uint64_t 
page_hash(const struct hash_elem *e_, void *aux);
static bool 
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);
static struct page *
page_lookup (struct hash* hash, const void *va);

static void
vm_dealloc_frame(struct frame *frame);

static void 
page_duplicate(struct hash_elem *e, void *aux);
static void 
hash_page_dealloc(struct hash_elem *e, void *aux);

static void frame_table_init(void);

static struct frame_table frame_table;

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

	frame_table_init();
}
static void 
frame_table_init(void){
	struct pool* user_pool = get_user_pool();
	frame_table.base = get_user_base();
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

const static struct frame_operations frame_operation = { 
	.do_claim = vm_do_claim_page,
	.dealloc_frame = vm_dealloc_frame,
};

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	struct supplemental_page_table *spt;
	struct page* page;
	vm_initializer* initializer;

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	spt = &thread_current ()->spt;
	page = NULL;
	initializer = NULL;
	upage = pg_round_down(upage);

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,*/

		if((page = (struct page*)malloc(sizeof(struct page))) == NULL)
			/* malloc에 실패하는 경우 */
			goto err;

		/* select the initializer by argument type */
		switch(VM_TYPE(type)){
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:
				goto err;
		}
		
		/* TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		uninit_new(page,upage,init,type,aux,initializer);
		page->writable = writable;
		page->f_operations = &frame_operation;

		/* TODO: Insert the page into the spt. */
		if(!spt_insert_page(spt,page))
			goto err;
		return true;
	}
err:
	if(page)
		free(page);
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	if(hash_empty(&spt->page_hash))
		return NULL;
	struct page* page = NULL;
	page = page_lookup(&spt->page_hash,va);
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
	ASSERT(spt != NULL);
	ASSERT(page != NULL);
	
	if(!spt_find_page(spt, page->va)){
		lock_acquire(&spt->lock);
		if(hash_insert(&spt->page_hash, &page->hash_elem)){
			/* hash insert 실패한 경우, 이미 해당 hash가 존재  */
		}
		lock_release(&spt->lock);
		return true;
	}
	return false;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT(spt != NULL);
	ASSERT(page != NULL);

	/* 효율적인 아키텍처 구성을 위해서는 spt내에 page가 존재함이 보장된 후  이 함수를 호출해야함. */
	ASSERT(spt_find_page(spt,page->va) != NULL);

	lock_acquire(&spt->lock);
	if(hash_delete(&spt->page_hash,&page->hash_elem) == NULL){
		/* hash_delete 실패한 경우 */
	}
	lock_release(&spt->lock);
	pml4_clear_page(thread_current()->pml4,page->va);
	vm_dealloc_page(page);
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

	/* frame 을 0으로 초기화하여 메모리 할당. */
	if((frame = (struct frame*)calloc(1,sizeof(struct frame))) == NULL){
		/* malloc 실패한 경우 */
		return NULL;
	}
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	
	
	if((frame->kva= palloc_get_page(PAL_USER)) == NULL){
		/* page 할당에 실패하는 경우 */
		free(frame);
		return NULL;
		/* TODO: evict the frame */
	}
	/* initialize member */

	/* TODO: frame_table에 추가 */
	alloc_frame_table(frame->kva,frame);
	return frame;
}


/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	struct thread* t;
	void* stack_bottom;
	struct page *page;
	struct pml4* pml4;

	addr = pg_round_down(addr);
	pml4 = &thread_current()->pml4;
	stack_bottom = thread_current()->stack_bottom;
	void* tmp = addr;
	while(tmp < stack_bottom){
		vm_alloc_page(VM_ANON|VM_STACK,tmp,true);
		tmp+=PGSIZE;
	}
	thread_current()->stack_bottom = addr;

	return;
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
	void* rsp;

	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	succ = false;
	spt = &thread_current()->spt;
	
	if((page = spt_find_page(spt,addr)) == NULL){
		/* page가 없는경우 */
		
		/* user_stack 검증 */
		rsp = (void*)f->rsp;
		if(is_user_stack(rsp, addr)){
			vm_stack_growth(addr);
			return true;
		}
		return false;
	}
	/* write 불가한 페이지에 작성하려는 경우 */
	if(write == true && page->writable == false){
		succ = false;
		return succ;
	} 
	/* lazy load */

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
	ASSERT( va != NULL);

	va = pg_round_down(va);
	succ = false;
	spt = &thread_current()->spt;

	if((page = spt_find_page(spt, va)) == NULL){
		/* page가 존재하지 않는 경우 , 이상 동작 이므로 종료 */
		thread_exit_by_error(-1);
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
	
	if(page == NULL)
		ASSERT(page != NULL);
	ASSERT(page->frame == NULL);

	if((frame = vm_get_frame()) == NULL)
		goto err;
	pml4 = thread_current()->pml4;
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(!pml4_set_page(pml4, page->va, frame->kva, page->writable ))
		goto err;
	if(!swap_in (page, frame->kva))
		goto err;
	return true;
	
err:

	return false;
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

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	/* page_duplicate에 넣어줄 aux를 세팅하고 사용이후 NULL로 초기화하여 이상동작 방지 */
	src->page_hash.aux = dst;
	hash_apply(&src->page_hash,page_duplicate);
	src->page_hash.aux = NULL;

	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->page_hash,hash_page_dealloc);
}
static void 
hash_page_dealloc(struct hash_elem *e, void *aux){
	struct page* page = hash_entry(e,struct page, hash_elem);
	pml4_clear_page(thread_current()->pml4,page->va);
	vm_dealloc_page(page);
}


/***********************************************************************/
/* hash func */
static uint64_t 
page_hash(const struct hash_elem *e_, void *aux){
  const struct page *e = hash_entry (e_, struct page, hash_elem);
  return hash_bytes (&e->va, sizeof e->va);
}
static bool 
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED){
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
static void 
page_duplicate(struct hash_elem *e, void *aux){
	struct supplemental_page_table* spt;
	const struct page *src_page;
	struct page* page;

	ASSERT( aux != NULL);

	page = NULL;
	spt = (struct supplemental_page_table*)aux;
	src_page = hash_entry(e, struct page, hash_elem);

	if((page  = malloc(sizeof(struct page))) == NULL)
		goto err;
	if(!duplicate(page,src_page))
		goto err;
	if(!spt_insert_page(spt,page))
		goto err;
	return ;
err:
	if(page)
		vm_dealloc_page(page);
}


static void
vm_dealloc_frame(struct frame *frame){
	ASSERT(frame != NULL);
	uint8_t* kva = frame->kva;
	if(frame->kva)
		free(frame->kva);
	free(frame);


	dealloc_frame_table(kva);
}

/***********************************************************************/