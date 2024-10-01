/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/uninit.h"
#include "vm/file.h"
#include "vm/inspect.h"
#include "threads/mmu.h"
#include "userprog/process.h"
#include <stdio.h>

static struct frame_table frame_table;
void frame_table_init();

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
bool is_stack_addr(void*, bool, struct thread *);

bool frame_table_insert (struct frame *frame);
void frame_table_remove(struct frame *frame);

/* page hash functions */
unsigned page_hash (const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);
void page_free (struct hash_elem *p_, void *aux UNUSED);

unsigned frame_hash (const struct hash_elem *f_, void *aux UNUSED);
bool frame_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED);


/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {
// 페이지 구조체를 할당하고 페이지 타입에 맞는 적절한 초기화 함수를 세팅함으로써 새로운 페이지를  초기화하는 함수
	ASSERT (VM_TYPE(type) != VM_UNINIT);

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = malloc(sizeof(struct page));
		if (page == NULL) 
			goto err;
		vm_initializer* page_initializer = NULL;
		switch (VM_TYPE(type)) {
			case VM_ANON:
				page_initializer = anon_initializer;
				break;
			case VM_FILE:
				page_initializer = file_backed_initializer;
				break;
			default:
				goto err;
		}


		uninit_new(page, upage, init, type, aux, page_initializer);

		page->writable = writable;
		page->plm4 = thread_current()->pml4;

		/* TODO: Insert the page into the spt. VM_TYPE 매크로를 사용 */
		if (!spt_insert_page(spt, page)) {
			free(page);
			goto err;
		}

		return true;
	}
err:
	NOT_REACHED();
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
   struct page *page = NULL;
   /* TODO: Fill this function. */
   page = (struct page*)malloc(sizeof(struct page));
   struct hash_elem *e;

   page->va = pg_round_down(va);
   e = hash_find(&(spt->pages), &(page->hash_elem));

   free(page);

   return e != NULL ? hash_entry(e, struct page, hash_elem) : NULL;
}
/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	bool succ = false;
	/* TODO: Fill this function. */
	// 이 함수에서 주어진 보충 테이블에서 가상 주소가 존재하지 않는지 검사해야 합니다.
	if (spt_find_page(spt, &page->va) == NULL) {		
		lock_acquire(&spt->hash_lock);
		hash_insert(&spt->pages, &page->hash_elem);
		lock_release(&spt->hash_lock);
		succ = true;
	}
	return succ;
}

bool
frame_table_insert (struct frame *frame) {
	lock_acquire(&frame_table.hash_lock);
	hash_insert(&frame_table.frames, &frame->hash_elem);
	list_push_front(&thread_current()->child_frames, &frame->list_elem);
	lock_release(&frame_table.hash_lock);
	return true;
}

void frame_table_remove(struct frame *frame) {
	lock_acquire(&frame_table.hash_lock);
	hash_delete(&frame_table.frames, &frame->hash_elem);
	lock_release(&frame_table.hash_lock);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	lock_acquire(&spt->hash_lock);
	hash_delete(&spt->pages, &page->hash_elem);
	lock_release(&spt->hash_lock);
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. 
	 	- LRU algorithm & Clock algorithm의 기능을 구현해야 함
		- 같은 프레임을 참조하는 두 개 (또는 그 이상)의 페이지들인 aliases 를 조심해야 합니다. 
			aliased 프레임이 accessed 될 때, accessed와 dirty 비트는 하나의 페이지 테이블 엔트리에서만 업데이트됩니다 (access에 쓰인 페이지에서만). 
			다른 alias들에 대한  accessed와 dirty 비트는 업데이트 되지 않습니다.
		- Pintos에서 모든 유저 가상 페이지는 커널 가상 페이지에 alias 되어 있습니다. 당신은 반드시 이 alias들을 관리해야 합니다. 
			예를 들면, 당신의 코드는 양쪽 주소 모두를 위한 accessed와 dirty 비트를 확인하고 업데이트 할 수 있어야 합니다. 
			또는, 오직 유저 가상 주소를 통해서만 유저 데이터에 접근하게 함으로써 커널이 이 문제를 피하게 할 수 있습니다.
	 */
	/* Clock algorithm 사용 */
	/*
		- page 순회
		- accessed 확인
			if accessed == 0 -> gottcha!
			if accessed == 1 -> set 0
		- 끝까지 못찾으면 iter 한번 더
	*/
	while (victim == NULL) {
		struct hash_iterator i;
		hash_first(&i, &frame_table);
		while (hash_next(&i)) {
			struct frame *f = hash_entry(hash_cur(&i), struct frame, hash_elem);
			void *upage = f->page->va;
			uint64_t *pml4 = f->page->plm4;
			ASSERT(!is_kernel_vaddr(f->page->va));
			if (pml4_is_accessed(pml4, upage))
				pml4_set_accessed(pml4, upage, false);
			else {
				victim = f;
				break;
			}
		}
	}
	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
/*
1. 당신의 페이지 재배치 알고리즘을 이용하여, 쫓아낼 프레임을 고릅니다. 아래에서 설명할 “accessed”, “dirty” 비트들(페이지 테이블에 있는)이 유용할 것입니다.
2. 해당 프레임을 참조하는 모든 페이지 테이블에서 참조를 제거합니다. 공유를 구현하지 않았을 경우, 해당 프레임을 참조하는 페이지는 항상 한 개만 존재해야 합니다.
3. 필요하다면, 페이지를 파일 시스템이나 스왑에 write 합니다. 쫓아내어진(evicted) 프레임은 이제 다른 페이지를 저장하는 데에 사용할 수 있습니다.
*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	victim->page = NULL;

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* 위의 함수는 palloc_get_page 함수를 호출함으로써 당신의 메모리 풀에서 새로운 물리메모리 페이지를 가져옵니다. 
 * 유저 메모리 풀에서 페이지를 성공적으로 가져오면, 프레임을 할당하고 프레임 구조체의 멤버들을 초기화한 후 해당 프레임을 반환합니다. 
 * 당신이 frame *vm_get_frame  함수를 구현한 후에는 모든 User Space Pages들을 이 함수를 통해 할당해야 합니다.
 * 지금으로서는 페이지 할당이 실패했을 경우의 swap out을 할 필요가 없습니다. 
 * 일단 지금은 PANIC ("todo")으로 해당 케이스들을 표시해 두십시오.*/
static struct frame *
vm_get_frame (void) {
	void *kva = palloc_get_page(PAL_USER | PAL_ZERO);
	if (kva == NULL) 
		return vm_evict_frame();
	
	struct frame *frame = malloc(sizeof(struct frame));
	if (frame == NULL) {
		PANIC("-- swapping needed --");
	}

	frame->kva = kva;
	frame->page = NULL;

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);

	frame_table_insert(frame);
	return frame;
}

/* Growing the stack. 
	하나 이상의 anonymous 페이지를 할당하여 스택 크기를 늘립니다. 
	이로써 addr은 faulted 주소(폴트가 발생하는 주소) 에서 유효한 주소가 됩니다.  
	페이지를 할당할 때는 주소를 PGSIZE 기준으로 내림하세요.
	max size of stack is 1MB
*/
static void
vm_stack_growth (void *addr) {
	void *new_stack_bottom = pg_round_down(addr);
	struct thread *current = thread_current();
	bool success = false;
	while (new_stack_bottom < current->stack_bottom) {
		if (!(vm_alloc_page(VM_ANON | VM_MARKER_0, new_stack_bottom, true) &&
					vm_claim_page(new_stack_bottom))){
			current->exit_code = -1;
			thread_exit();
		}
		new_stack_bottom += PGSIZE;
	}
	thread_current()->stack_bottom = pg_round_down(addr);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
/* 
1. 보조 페이지 테이블에서 폴트가 발생한 페이지를 찾습니다. 
	만일 메모리 참조가 유효하다면, 보조 페이지 엔트리를 사용해서 데이터가 들어갈 페이지를 찾으세요. 
	그 페이지는 파일 시스템에 있거나, 스왑 슬롯에 있거나, 또는 단순히 0으로만 이루어져야 할 수도 있습니다. 
	당신이 만약 Copy-on-Write와 같은 Sharing을 구현한다면, 
	페이지의 데이터는 이미 페이지 테이블에 없고 페이지 프레임에 들어가 있을 것입니다. 
	만약 보조 페이지 테이블이 다음과 같은 정보를 보여주고 있다면 
		- 유저 프로세스가 접근하려던 주소에서 데이터를 얻을 수 없거나, 페이지가 커널 가상 메모리 영역에 존재하거나, 
		읽기 전용 페이지에 대해 쓰기를 시도하는 상황 - 
	그건 유효하지 않은 접근이란 뜻입니다. 유효하지 않은 접근은 프로세스를 종료시키고 프로세스의 모든 자원을 해제합니다.
2. 페이지를 저장하기 위해 프레임을 획득합니다. 만일 당신이 Sharing을 구현한다면, 필요한 데이터는 이미 프레임 안에 있을 겁니다. 
	이 경우 해당 프레임을 찾을 수 있어야 합니다.
3. 데이터를 파일 시스템이나 스왑에서 읽어오거나, 0으로 초기화하는 등의 방식으로 만들어서 프레임으로 가져옵니다. 
	Sharing을 구현한다면, 필요한 페이지가 이미 프레임 안에 있기 때문에 지금 단계에서는 별다른 조치가 필요하지 않습니다.
4. 폴트가 발생한 가상주소에 대한 페이지 테이블 엔트리가 물리 페이지를 가리키도록 지정합니다. `threads/mmu.c` 에 있는 함수를 사용할 수 있습니다.
최종적으로 spt_find_page 를 거쳐 보조 페이지 테이블을 참고하여 fault된 주소에 대응하는 페이지 구조체를 해결하기 위한 함수 vm_try_handle_fault를 수정하세요.
*/
/* bogus page fault란?
	- 물리 메모리와 매핑은 되어 있지만, 컨텐츠가 load되어 있지 않은 경우를 의미
	- 컨텐츠를 load해주면 됨
*/
bool
vm_try_handle_fault (struct intr_frame *f, void *addr,
		bool user, bool write, bool not_present) {
	if (is_kernel_vaddr(addr)) 
		return false;
	
	struct thread *current = thread_current();
	struct supplemental_page_table *spt = &current->spt;
	struct page *page = spt_find_page(spt, addr);
	/* TODO: Validate the fault.
		- 유저 프로세스가 접근하려던 주소에서 데이터를 얻을 수 없거나
		- 페이지가 커널 가상 메모리 영역에 존재하거나, 
		- 읽기 전용 페이지에 대해 쓰기를 시도하는 상황
	*/
	if (is_stack_addr(addr, write, current)) {
		vm_stack_growth(addr);
		return true;
	}
	
	if (page == NULL || (write && !page->writable))
		return false;

	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

void
vm_dealloc_frame(struct frame *frame) {
	free(frame);
}

/* Claim이란, physical frame에 page를 할당하는 것을 의미한다 */
/* Claim the page that allocate on VA. */ 
/* 위 함수는 인자로 주어진 va에 페이지를 할당하고, 해당 페이지에 프레임을 할당합니다. 
 * 당신은 우선 한 페이지를 얻어야 하고 그 이후에 해당 페이지를 인자로 갖는 vm_do_claim_page라는 함수를 호출해야 합니다.*/
bool
vm_claim_page (void *va) {
	struct page *page = spt_find_page(&thread_current()->spt, va);
	/* TODO: Fill this function */	
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
/* 위 함수는 인자로 주어진 page에 물리 메모리 프레임을 할당합니다. 
 * 당신은 먼저 vm_get_frame 함수를 호출함으로써 프레임 하나를 얻습니다(이 부분은 스켈레톤 코드에 구현되어 있습니다). 
 * 그 이후 당신은 MMU를 세팅해야 하는데, 이는 가상 주소와 물리 주소를 매핑한 정보를 페이지 테이블에 추가해야 한다는 것을 의미합니다.
 * 위의 함수는 앞에서 말한 연산이 성공적으로 수행되었을 경우에 true를 반환하고 그렇지 않을 경우에 false를 반환합니다. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	struct thread *t = thread_current();
	if (!(pml4_get_page (t->pml4, page->va) == NULL
			&& pml4_set_page (t->pml4, page->va, frame->kva, page->writable))) {		
		vm_dealloc_frame(frame);
		vm_dealloc_page(page);
		NOT_REACHED();
		return false;
	}

	// uninit page 시: swap_in -> uninit_initialize -> page_initialize -> init
	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init (struct supplemental_page_table *spt) {
	hash_init(&spt->pages, page_hash, page_less, NULL);
	lock_init(&spt->hash_lock);
}

void frame_table_init() {
	hash_init(&frame_table, frame_hash, frame_less, NULL);
	lock_init(&frame_table.hash_lock);
}

/* Copy supplemental page table from src to dst */
/*
	src부터 dst까지 supplemental page table를 복사하세요. 
	이것은 자식이 부모의 실행 context를 상속할 필요가 있을 때 사용됩니다. (예 - fork()). 
	src의 supplemental page table를 반복하면서 
	dst의 supplemental page table의 엔트리의 정확한 복사본을 만드세요. 
	당신은 초기화되지않은(uninit) 페이지를 할당하고 그것들을 바로 claim할 필요가 있을 것입니다.
*/
bool
supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src) {
	struct hash_iterator itr;
	hash_first(&itr, &src->pages);
	while (hash_next(&itr)) {
		struct page *origin = hash_entry(hash_cur(&itr), struct page, hash_elem);
		enum vm_type page_type = origin->operations->type;

		if (page_type == VM_UNINIT) {
			struct load_args *cpy_aux = malloc(sizeof(struct load_args));
			memcpy(cpy_aux, origin->uninit.aux, sizeof(struct load_args));
			if (!vm_alloc_page_with_initializer(origin->uninit.type, origin->va, origin->writable, origin->uninit.init, cpy_aux))
				return false;
			continue;
		}

		/* VM_ANON & VM_FILE */
		if (!(vm_alloc_page(page_type, origin->va, origin->writable) &&
					vm_claim_page(origin->va)))
			return false;

		struct page *copy = spt_find_page(dst, origin->va);
		if (copy == NULL) 
			return false;
		memcpy(copy->frame->kva, origin->frame->kva, PGSIZE);
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
/*
	supplemental page table에 의해 유지되던 모든 자원들을 free합니다. 
	이 함수는 process가 exit할 때(userprog/process.c의 process_exit()) 호출됩니다. 
	당신은 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야 합니다. 
	당신은 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된 메모리)에 대해 걱정할 필요가 없습니다. 
	supplemental page table이 정리되어지고 나서, 호출자가 그것들을 정리할 것입니다.
*/
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	struct list_elem *e;
	struct list *child_frames = &thread_current()->child_frames;
	while (!list_empty(child_frames)) {
		e = list_pop_front(child_frames);
		struct frame *frame = list_entry(e, struct frame, list_elem);
		frame_table_remove(frame);
	}
	if (!hash_empty(&spt->pages))
		hash_clear(&spt->pages, page_free);
	// writeback all the modified contents to the storage!! - mmap 시?
}

bool is_stack_addr(void* addr, bool write, struct thread *current) {
	return addr < current->stack_bottom && addr >= MAX_USER_STACK_BOTTOM && write;
}

/* Returns a hash value for page p */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
  return hash_bytes (&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b */
bool
page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED) {
	const struct page *a = hash_entry(a_, struct page, hash_elem);
	const struct page *b = hash_entry(b_, struct page, hash_elem);
	return a->va < b->va;
}

void page_free (struct hash_elem *p_, void *aux UNUSED) {
	const struct page *p = hash_entry (p_, struct page, hash_elem);
	free(p->frame);
	vm_dealloc_page(p);
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