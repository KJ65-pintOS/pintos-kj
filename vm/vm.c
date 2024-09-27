/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "kernel/hash.h"
#include "threads/mmu.h"
#include "threads/synch.h"
#include "lib/string.h"
#include "include/userprog/process.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

/* project3: 추가*/
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_,const struct hash_elem *b_, void *aux UNUSED);
void page_destructor (struct hash_elem *p_, void *aux UNUSED);

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

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		// 페이지 생성
		struct page *page = malloc(sizeof(struct page));

		if (page == NULL) 
			goto err;

		// VM type에 따라 initializer fetch
		vm_initializer *initializer = NULL;
		switch (VM_TYPE(type)) {
			case VM_ANON:
				initializer = anon_initializer;
				break;
			case VM_FILE:
				initializer = file_backed_initializer;
				break;
			default:
				goto err;
		}

		// uninit_new를 호출하여 “uninit” 페이지 구조체를 생성
		uninit_new(page, upage, init, type, aux, initializer);

		// 필드 수정
		page->writable = writable;

		/* TODO: Insert the page into the spt. */
		// 해당 페이지를 spt에 추가
		if(!spt_insert_page(spt, page)) {
			free(page);
			goto err;
		}

		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
/* 찾는 va와 일치하는 page 찾기 */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = (struct page*)malloc(sizeof(struct page));
  	struct hash_elem *e;
  	page->va = pg_round_down(va);
  	e = hash_find (&spt->pages, &page->hash_elem);

	// 페이지 free 해야하는지
	free(page);

  	return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	int succ = false;
	/* TODO: Fill this function. */
	// 페이지가 spt에 이미 있는지 확인
	if(hash_find(&spt->pages, &page->hash_elem)) {
		return succ;
	}
	// spt에 페이지 insert, lock으로 동시성 문제 해결

	lock_acquire(&spt->hash_lock);
	hash_insert(&spt->pages, &page->hash_elem);
	lock_release(&spt->hash_lock);
	succ = true;

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
	struct frame *frame = calloc(1, sizeof(struct frame));
	/* TODO: Fill this function. */
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if(kva == NULL) {
		PANIC("todo");
	}

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	frame->kva = kva;
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
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write , bool not_present) {
	struct supplemental_page_table *spt = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	// 스택 확장해야하는지 확인 추가필요

	page = spt_find_page(spt, addr);

	struct thread *current = thread_current();
	
	if (page == NULL || is_kernel_vaddr(addr)) {
		current->exit_code = -1;
		thread_exit();
		return false;
	}

	/* TODO: Your code goes here */
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
// claim - 물리적 프레임, 페이지를 할당하는 것을 의미
bool
vm_claim_page (void *va) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	// spt에서 va와 일치하는 페이지 찾기
	page = spt_find_page(&thread_current()->spt, va);

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if(!pml4_set_page(thread_current()->pml4, page->va, frame->kva, page->writable)) {
		palloc_free_page(frame->kva);
		return false;
	}

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
/* hash_init() 해시 테이블 hash의 해시 함수를 hash_func로, 비교 함수를 less_func로, 보조 데이터를 aux로 초기화 합니다.
초기화 성공 시 true를, 실패 시 false를 반환합니다. */
// 새로운 보조 페이지 테이블을 초기화, 페이지 테이블은 해시 테이블로 관리
void
supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->pages, page_hash, page_less, NULL); // 해시테이블 초기화
	lock_init(&spt->hash_lock); // lock 초기화
}

/*src부터 dst까지 supplemental page table를 복사하세요. 
이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다.
(예 - fork()). src의 supplemental page table를 반복하면서 
dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요. 
당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 요청할 필요가 있을 것입니다 */
/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	
	// 해시테이블 내의 위치 반복자
	struct hash_iterator i;
	// 첫번째 요소로 초기화
	hash_first (&i, &src->pages);
	while (hash_next(&i)) {
		struct page *origin_page = hash_entry(hash_cur (&i), struct page, hash_elem);
		enum vm_type type = origin_page->operations->type; // 페이지 타입

		// uninit은 alloc까지만 해두고 pagefault가 발생할때 claim되도록
		if(type == VM_UNINIT) {
			struct load_info *copied_aux = malloc(sizeof(struct load_info)); // load_info 넘겨주기
			memcpy(copied_aux, origin_page->uninit.aux, sizeof(struct load_info)); // aux를 memcpy해서 free되는 것을 방지
			if (!vm_alloc_page_with_initializer (origin_page->uninit.type, origin_page->va,
					origin_page->writable, origin_page->uninit.init, copied_aux))
				return false;

			continue;
		}

		// anon, file은 claim까지 진행
		if(!(vm_alloc_page(type, origin_page->va, origin_page->writable) &&
							vm_claim_page(origin_page->va))) {
			return false;
		}

		// copeid page에 origin page memcpy
		struct page *copied_page = spt_find_page(dst, origin_page->va);
		if(copied_page == NULL) {
			return false;
		}

		// spt에 커널 물리 주소
		memcpy(copied_page->frame->kva, origin_page->frame->kva, PGSIZE);
	}
	return true;
}

/* supplemental page table에 의해 유지되던 모든 자원들을 free합니다. 
이 함수는 process가 exit할 때(userprog/process.c의 process_exit()) 호출됩니다.
당신은 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야 합니다.
당신은 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된 메모리)에 대해 걱정할 필요가 없습니다. 
supplemental page table이 정리되어지고 나서, 호출자가 그것들을 정리할 것입니다.*/
/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if(!hash_empty(&spt->pages)) {
		hash_clear(&spt->pages, page_destructor);
	}

}

/* project3: hash_init에 필요한 함수 추가 */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

bool
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->va < b->va;
}

void page_destructor (struct hash_elem *p_, void *aux UNUSED) {
	struct page *page = hash_entry (p_, struct page, hash_elem);
	destroy(page);
	free(page);
}

unsigned
frame_hash (const struct hash_elem *f_, void *aux UNUSED) {
	const struct frame *f = hash_entry(f_, struct frame, hash_elem);
	return hash_bytes(&f->kva, sizeof(f->kva));
}

bool
frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct frame *a = hash_entry(a_, struct frame, hash_elem);
	const struct frame *b = hash_entry(b_, struct frame, hash_elem);
	return a->kva < b->kva;
}