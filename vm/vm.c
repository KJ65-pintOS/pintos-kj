/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"

/*********************************/
/* supplemental page table, project 3*/
#include "hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "lib/string.h"

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

const static struct frame_operations frame_operation = { 
	.do_claim = vm_do_claim_page
};

/*********************************/
/* supplemental page table, project 3*/
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less (const struct hash_elem *a_,const struct hash_elem *b_, void *aux UNUSED);
static void page_duplicate(struct hash_elem *e, void *aux);
/*********************************/

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;
	upage = pg_round_down(upage);

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		/* TODO: Insert the page into the spt. */

		/*********************************/
		/* supplemental page table, project 3*/

		//1.이 함수는 페이지 구조체를 할당하고
		struct page *new_page = (struct page *)malloc(sizeof(struct page));

		//2. type에 따라 초기화 함수 다르게 설정
		bool (*initializer)(struct page *page, enum vm_type type, void *kva);

		switch(VM_TYPE(type)) {
			case VM_ANON:
			initializer=anon_initializer;
			break;
			case VM_FILE:
			initializer=file_backed_initializer;
			break;
		}

		// 3. create "uninit" page struct by calling uninit_new
		// 초기화되지 않은 페이지 구조체를 설정
		uninit_new(new_page,upage,init,type,aux,initializer);
		new_page->writable = writable;
		new_page->f_operations = &frame_operation;

		//4. Insert the page into the spt.
		return spt_insert_page(spt,new_page);

		/*********************************/
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */

	/*********************************/
	/* supplemental page table, project 3*/
	struct page dummy_page;
	struct hash_elem *e;

	dummy_page.va = pg_round_down(va);
	e = hash_find(&spt->hash_spt, &dummy_page.hash_elem);

	if (e==NULL) {
		return NULL;
	}

	page = hash_entry (e,struct page, hash_elem);
	/*********************************/
	return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	// int succ = false;
	// /* TODO: Fill this function. */

	/*********************************/
	// /* supplemental page table, project 3*/

	// struct hash_elem *result;
	// // 1.주어진 페이지가, 보조 페이지 테이블에 존재하는지 확인하기
	// struct page *p = spt_find_page(&spt, &p->va);
	// if (p != NULL) {
	// 	return succ; //false 반환
	// }
	// // 2.없다면, spt에 해당 페이지 넣기
	// hash_insert(spt->hash_spt, &page->hash_elem);
	// succ = true;

	// return succ; //true 

	return hash_insert(&spt->hash_spt, &page->hash_elem) == NULL ? true : false;
	/*********************************/
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	ASSERT(spt != NULL);
	ASSERT(page != NULL);
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
/*위의 함수는 palloc_get_page 함수를 호출함으로써 당신의 메모리 풀에서 새로운 물리메모리 페이지를 가져옵니다. 유저 메모리 풀에서 페이지를 성공적으로 가져오면, 프레임을 할당하고 프레임 구조체의 멤버들을 초기화한 후 해당 프레임을 반환합니다. 
당신이 frame *vm_get_frame  함수를 구현한 후에는 모든 유저 공간 페이지들을 이 함수를 통해 할당해야 합니다.
지금으로서는 페이지 할당이 실패했을 경우의 swap out을 할 필요가 없습니다. 일단 지금은 PANIC ("todo")으로 해당 케이스들을 표시해 두십시오.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */

	/*********************************/
	/* supplemental page table, project 3*/
	void *kva = palloc_get_page(PAL_USER);
	if(kva == NULL) {
		PANIC("todo");
	}
	//성공 시
	frame = malloc(sizeof(struct frame));
	frame->kva = kva;
	frame->page = NULL;
	/*********************************/
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

// /* Growing the stack. */
// static void
// vm_stack_growth (void *addr UNUSED) {
// 	// 하나 이상의 anonymous 페이지를 할당하여 스택 크기를 늘림 이로써 addr은 page fault에서 유효한 주소가 됩니다.
// 	// 페이지를 할당할때 pgsize 기준으로 내림하세요
// 	// 현재 rsp와 주소를 비교해서, stack_bottom
// 	//stack bottom을 stack에 매핑함, 해당 페이지가 stack이라는 것을 mark하기

// 	void *addr_round_down= pg_round_down(addr);
// 	void *stack_bottom = thread_current()->stack_bottom;
// 	bool success;
// 	void *tmp = addr_round_down; //tmp(새로 page 할당할 주소)->초깃값:addr_round_down
// 	while(addr_round_down < stack_bottom) {
// 		vm_alloc_page(VM_ANON,tmp,1);//추가: addr_round_down을 tmp로 변경
// 		//success = vm_claim_page(stack_bottom);
// 		stack_bottom = addr_round_down;
// 		tmp+=PGSIZE; //추가: tmp 갱신
// 	}
	
// }

/* Growing the stack. */
static void
vm_stack_growth (void *addr) {
	struct thread* t;
	void* stack_bottom;
	struct page *page;

	addr = pg_round_down(addr);
	ASSERT(addr > USER_STACK - USER_STACK_MAX_SIZE)

	stack_bottom = thread_current()->stack_bottom;
	void* tmp = addr;
	while(tmp < stack_bottom){
		vm_alloc_page(VM_ANON,tmp,true);
		tmp+=PGSIZE;
	}
	thread_current()->stack_bottom = addr;

	return;
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

// /* Return true on success */
// bool
// vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
// 		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {

// 	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
// 	struct page *page = NULL;

// 	/* TODO: Validate the fault */
// 	/* TODO: Your code goes here */
// 	void *rsp = (void *)f->rsp;

// 	if (addr == NULL)
//         goto error;

//     if (is_kernel_vaddr(addr))
// 		goto error;
// 	///////////////////////////////////////////////
// 	page = spt_find_page(spt, addr);
// 	if (page == NULL)
// 		//스택에 접근하는 경우인데, 가상메모리가 아직 할당되어 있지 않은 경우
// 		if (is_stack_access(rsp,addr)) {
// 			vm_stack_growth(addr);
// 			return true;
// 		}
// 		return false;
// 	///////////////////////////////////////////////
// 	if (write == true && page->writable == false) // write 불가능한 페이지에 write 요청한 경우
//         return vm_handle_wp;

//     if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
//     {
//         /* TODO: Validate the fault */
//         if(vm_do_claim_page(page)) {
// 			return true;
// 		}
//     }


// 	error:
// 		return false;
   



// 	// 스택 포인터 아래 8바이트에 대해서 PAGE FAULT를 발생시킬 수 있다.
// 	// intr_frame rsp에서 얻을 수 있다.
// 	// 잘못된 메모리 접근을 감지하기 위해 PAGE FAULT에 의존하는 경우 커널에서 PAGE FAULT 가 발생하는 경우도 처리해야함
// 	// 프로세스가 스택 포인터를 저장하는 것은 예외로 인해 유저 모드에서 커널 모드로 전환될 때 뿐이므로 page_fault()로 전달된 struct intr_frame 에서 rsp를 읽으면 유저 스택 포인터가 아닌 정의되지 않은 값을 얻을 수 있습니다. 유저 모드에서 커널 모드로 전환 시 rsp를 struct thread에 저장하는 것과 같은 다른 방법을 준비해야 합니다.

// 	// 스택 증가를 확인, 확인 후 vm_stack_growth를 호출하여 스택을 증가시켜야함
// 	// page fault가 스택을 증가시켜야하는 경우에 해당하는지 아닌지를 확인해야함
// 	// 스택 증가로 page fault 예외를 처리할 수 있는지 확인한 경우 page fualt가 발생한 주소로 vm_stack_growth를 호출해야함

// }

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
	/* page가 없는경우 */
	if((page = spt_find_page(spt,addr)) == NULL){
		/* user_stack 검증 */
		rsp = (void*)f->rsp;
		if(is_stack_access(rsp,addr)){
			vm_stack_growth(addr);
			return true;
		}
		return false;
	}
	/* write 불가한 페이지에 작성하려는 경우 */
	if(write == true && page->writable == false){
		if(vm_handle_wp(page)) {
			succ = true;
		}
		
	} 
	/* lazy load */
	if(not_present) {
		if(vm_do_claim_page (page))
		succ = true;
	}
	

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
	struct page *page = NULL;
	/* TODO: Fill this function */
	
	/*********************************/
	/*project 3*/
	ASSERT(is_user_vaddr(va));
	struct supplemental_page_table *spt = &thread_current()->spt;
	page = spt_find_page(spt,va);
	if (page==NULL) {
		return false;
	}

	/*********************************/
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

	/*********************************/
	/*project 3*/
	struct thread *curr_thread= thread_current();
	pml4_set_page(curr_thread->pml4,page->va,frame->kva,page->writable);
	/*********************************/

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init (&spt->hash_spt, page_hash, page_less, NULL);
}

//src부터 dst까지 supplemental page table를 복사하세요. 이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다.(예 - fork()). src의 supplemental page table를 반복하면서 dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요. 당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 요청할 필요가 있을 것입니다.

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,struct supplemental_page_table *src UNUSED) {

	ASSERT(dst != NULL);
	ASSERT(src != NULL);

	src->hash_spt.aux = dst;
	hash_apply(&src->hash_spt, page_duplicate);
	src->hash_spt.aux = NULL;
	return true;

}

/* Free the resource hold by the supplemental page table */

//supplemental page table에 의해 유지되던 모든 자원들을 free합니다. 이 함수는 process가 exit할 때(userprog/process.c의 process_exit()) 호출됩니다. 당신은 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야 합니다. 당신은 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된 메모리)에 대해 걱정할 필요가 없습니다. supplemental page table이 정리되어지고 나서, 호출자가 그것들을 정리할 것입니다.
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->hash_spt,page_destroy);

}

/*********************************/


/* supplemental page table, project 3*/

/* Returns a hash value for page p. */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}


void page_destroy(struct hash_elem *e, void *aux) {
	struct page *page = hash_entry(e, struct page, hash_elem);
	vm_dealloc_page(page);
}

/*********************************/
/*project 3*/
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


/*********************************/