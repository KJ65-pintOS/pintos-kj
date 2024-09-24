/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
/*각 서브시스템의 초기화 코드를 호출하여 가상 메모리 서브시스템을 초기화합니다.*/
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
	
	// Frame Table 생성 및 초기화
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
	// current thread의 supplemental_page_table을 가져옴.
	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	// spt_find_page 를 통해서 va에 해당하는 구조체 페이지를 찾아서 반환한다.
	// 만약 해당하는 페이지가 없다면 새 페이지를 만든다.
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */

		// 1. Create the page
		struct page *page = malloc(sizeof(struct page));
    	if (page == NULL)
        	goto err;

		// 2. fetch the initialier according to the VM type
		vm_initializer *initialier = NULL;
		switch (type)
		{
		case VM_ANON:
			initialier = anon_initializer;
			break;
		case VM_FILE:
			initialier = file_backed_initializer;
			break;
		default:
			goto err;
		}

		// 3. create "uninit" page struct by calling uninit_new
		// init 은 여기서 lazy_load 함수임!
		uninit_new(page, upage, init, type, aux, initialier);

		// 필드 수정
        page->writable = writable;
    
		/* TODO: Insert the page into the spt. */
		// 4. Insert the page into the spt
		if(!spt_insert_page(spt,page))  // 해당 페이지를 spt에 추가한다.
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
	struct page *page = NULL;
	/* TODO: Fill this function. */
	/*
		주어진 보충 페이지 테이블에서 
		va에 해당하는 구조체 페이지를 찾습니다. 실패하면 NULL을 반환합니다.
	*/

	page = page_lookup (va);

	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	/*
		struct page를 주어진 보충 페이지 테이블에 삽입합니다. 
		이 함수는 가상 주소가 지정된 추가 페이지 테이블에 없는지 확인해야 합니다.
	*/
	// 1. 추가할 페이지가 spt에 있는지 확인해야함.
	if(hash_find(&spt->pages_map, &page->hash_elem) != NULL) // NULL 이 아니면 있다는 뜻이므로 false return
		return succ;

	// 2. spt에 page 삽입.
	sema_down(&spt->spt_sema);
	hash_insert(&spt->pages_map, &page->hash_elem);
	sema_up(&spt->spt_sema);
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
	void *kva = palloc_get_page(PAL_USER);
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
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	if(!is_user_vaddr(addr)) {
		return false;
	}
	// 스택 확장 해야하는지 확인
	page = spt_find_page(spt, addr);
	if(!page) {
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
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */

	// va에 해당하는 페이지가 존재하는지 확인
	if(!spt_find_page(&thread_current()->spt, va)) {
		return false;
	}

	// 페이지 구조체 생성
	page = malloc(sizeof(struct page));
	if(page == NULL) {
		return false;
	}
	page->va = va; // 가상주소 설정

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	// claim : 물리적 프레임, 페이지를 할당하는 것을 의미
	// 1. vm_get_frame을 호출 -> 프레임을 얻는다.
	struct frame *frame = vm_get_frame();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	// 2. mmu 설정 ( 가상 주소에서 페이지 테이블의 실제 주소로 매핑을 추가 )
	if(!pml4_set_page(&thread_current()->pml4, page->va, frame->kva, page->writable)) {
		palloc_free_page(frame->kva);
		// page 구조체와 프레임의 할당 해제도 해야하나?
		return false;
	}
	
	// 3. 작업성공 여부를 반환한다.
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/*
		추가 페이지 테이블을 초기화합니다. 
		보충 페이지 테이블에 사용할 데이터 구조를 선택할 수 있습니다. 
		이 함수는 새 프로세스가 시작될 때(userprog/process.c의 initd에서) 프로세스가 분기될 때
		(userprog/process.c의 __do_fork에서) 호출됩니다.
	*/
	hash_init(&spt->pages_map, page_hash, page_less, NULL);
	sema_init(&spt->spt_sema, 1);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {
	
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	
}
