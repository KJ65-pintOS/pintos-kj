/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/inspect.h"
#include "vm/vm.h"

/*********************************/
/* supplemental page table, project 3*/
#include "hash.h"
#include "lib/string.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
  vm_anon_init();
  vm_file_init();
#ifdef EFILESYS /* For project 4 */
  pagecache_init();
#endif
  register_inspect_intr();
  /* DO NOT MODIFY UPPER LINES. */
  /* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
  int ty = VM_TYPE(page->operations->type);
  switch (ty) {
  case VM_UNINIT:
    return VM_TYPE(page->uninit.type);
  default:
    return ty;
  }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);

/*********************************/
/* supplemental page table, project 3*/
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED);
/*********************************/

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage,
                                    bool writable, vm_initializer *init,
                                    void *aux) {

  ASSERT(VM_TYPE(type) != VM_UNINIT)

  struct supplemental_page_table *spt = &thread_current()->spt;

  /* Check wheter the upage is already occupied or not. */
  if (spt_find_page(spt, upage) == NULL) {
    /* TODO: Create the page, fetch the initialier according to the VM type,
     * TODO: and then create "uninit" page struct by calling uninit_new. You
     * TODO: should modify the field after calling the uninit_new. */
    /* TODO: Insert the page into the spt. */

    /*********************************/
    /* supplemental page table, project 3*/

    // 1.이 함수는 페이지 구조체를 할당하고
    struct page *new_page = (struct page *)malloc(sizeof(struct page));

    // 2. type에 따라 초기화 함수 다르게 설정
    bool (*initializer)(struct page * page, enum vm_type type, void *kva);

    switch (VM_TYPE(type)) {
    case VM_ANON:
      initializer = anon_initializer;
      break;
    case VM_FILE:
      initializer = file_backed_initializer;
      break;
    }

    // 3. create "uninit" page struct by calling uninit_new
    // 초기화되지 않은 페이지 구조체를 설정
    uninit_new(new_page, upage, init, type, aux, initializer);
    new_page->writable = writable;

    // 4. Insert the page into the spt.
    return spt_insert_page(spt, new_page);

    /*********************************/
  }
err:
  return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED,
                           void *va UNUSED) {
  struct page *page = NULL;
  /* TODO: Fill this function. */

  /*********************************/
  /* supplemental page table, project 3*/
  struct page dummy_page;
  struct hash_elem *e;

  dummy_page.va = pg_round_down(va);
  e = hash_find(&spt->hash_spt, &dummy_page.hash_elem);

  if (e == NULL) {
    return NULL;
  }

  page = hash_entry(e, struct page, hash_elem);
  /*********************************/
  return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED,
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

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
  ASSERT(spt != NULL);
  ASSERT(page != NULL);
  vm_dealloc_page(page);
  return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
  struct frame *victim = NULL;
  /* TODO: The policy for eviction is up to you. */

  return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
  struct frame *victim UNUSED = vm_get_victim();
  /* TODO: swap out the victim and return the evicted frame. */

  return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/*위의 함수는 palloc_get_page 함수를 호출함으로써 당신의 메모리 풀에서 새로운
물리메모리 페이지를 가져옵니다. 유저 메모리 풀에서 페이지를 성공적으로 가져오면,
프레임을 할당하고 프레임 구조체의 멤버들을 초기화한 후 해당 프레임을 반환합니다.
당신이 frame *vm_get_frame  함수를 구현한 후에는 모든 유저 공간 페이지들을 이
함수를 통해 할당해야 합니다. 지금으로서는 페이지 할당이 실패했을 경우의 swap
out을 할 필요가 없습니다. 일단 지금은 PANIC ("todo")으로 해당 케이스들을 표시해
두십시오.*/
static struct frame *vm_get_frame(void) {
  struct frame *frame = NULL;
  /* TODO: Fill this function. */

  /*********************************/
  /* supplemental page table, project 3*/
  void *kva = palloc_get_page(PAL_USER);
  if (kva == NULL) {
    PANIC("todo");
  }
  //성공 시
  frame = malloc(sizeof(struct frame));
  frame->kva = kva;
  frame->page = NULL;
  /*********************************/
  ASSERT(frame != NULL);
  ASSERT(frame->page == NULL);
  return frame;
}

/* Growing the stack. */
static bool vm_stack_growth(void *addr UNUSED) {
  // todo: 스택 크기를 증가시키기 위해 anon page를 하나 이상 할당하여 주어진
  // 주소(addr)가 더 이상 예외 주소(faulted address)가 되지 않도록 합니다. todo:
  // 할당할 때 addr을 PGSIZE로 내림하여 처리
  return vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {}

#define STACK_MAX (1 << 20) // 1MB

/* Return true on success */
#include <stdio.h>

bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user,
                         bool write, bool not_present) {
  struct supplemental_page_table *spt = &thread_current()->spt;
  struct page *page = NULL;

  // 1. 기본 검증
  if (user && is_kernel_vaddr(addr))
    return false;

  // 2. 페이지 찾기
  page = spt_find_page(spt, addr);

  // 3. 쓰기 권한 확인
  if (write && page && page->writable == false) {
    return false;
  }

  // 4. 페이지가 존재하지 않는 경우 처리
  if (not_present) {
    if (page)
      return vm_do_claim_page(page);

    // 5. 스택 성장 처리
    void *rsp = user ? f->rsp : thread_current()->rsp;

    if (USER_STACK - STACK_MAX <= (uint8_t *)rsp - 8 &&
        (uint8_t *)rsp - 8 <= (uint8_t *)addr &&
        (uint8_t *)addr <= (uint8_t *)USER_STACK) {
      return vm_stack_growth(addr);
    }

    return false;
  }

  // 6. 예상치 못한 상황
  return true;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
  destroy(page);
  free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
  struct page *page = NULL;
  /* TODO: Fill this function */

  /*********************************/
  /*project 3*/
  ASSERT(is_user_vaddr(va));
  struct supplemental_page_table *spt = &thread_current()->spt;
  page = spt_find_page(spt, va);
  if (page == NULL) {
    return false;
  }

  /*********************************/
  return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
  struct frame *frame = vm_get_frame();

  /* Set links */
  frame->page = page;
  page->frame = frame;

  /* TODO: Insert page table entry to map page's VA to frame's PA. */

  /*********************************/
  /*project 3*/
  struct thread *curr_thread = thread_current();
  pml4_set_page(curr_thread->pml4, page->va, frame->kva, page->writable);
  /*********************************/

  return swap_in(page, frame->kva);
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
  hash_init(&spt->hash_spt, page_hash, page_less, NULL);
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
  // 해시 테이블을 순회하기 위한 이터레이터 선언
  struct hash_iterator iterator;

  // 소스 SPT의 해시 테이블 순회 시작
  // hash_first 함수로 이터레이터를 초기화하고 첫 번째 요소를 가리키도록 함
  hash_first(&iterator, &src->hash_spt);

  // 해시 테이블의 모든 요소를 순회
  while (hash_next(&iterator)) {
    // 현재 해시 요소에서 페이지 구조체 추출
    // hash_entry 매크로를 사용하여 현재 해시 요소를 struct page 포인터로 변환
    struct page *parent_page =
        hash_entry(hash_cur(&iterator), struct page, hash_elem);

    // 부모 페이지의 타입, 쓰기 가능 여부, 가상 주소 추출
    // operations 구조체를 통해 페이지 타입 접근
    enum vm_type parent_page_type = parent_page->operations->type;
    bool parent_page_writable = parent_page->writable;
    void *parent_page_address = parent_page->va;

    if (parent_page_type == VM_UNINIT) {
      // 초기화 함수와 보조 데이터 추출
      vm_initializer *init = parent_page->uninit.init;
      void *aux = parent_page->uninit.aux;

      // 수정: parent_page->uninit.type을 사용하여 원래 의도된 타입으로 페이지
      // 할당
      if (!vm_alloc_page_with_initializer(parent_page->uninit.type,
                                          parent_page_address,
                                          parent_page_writable, init, aux))
        return false;
    } else {
      // 이미 초기화된 페이지 처리
      if (!vm_alloc_page(parent_page_type, parent_page_address,
                         parent_page_writable))
        return false;
      // 물리 메모리 요청 및 페이지 테이블 매핑
      if (!vm_claim_page(parent_page_address))
        return false;

      // 대상 SPT에서 새로 할당된 페이지 찾기
      struct page *dst_page = spt_find_page(dst, parent_page_address);
      // 페이지 내용 복사
      memcpy(dst_page->frame->kva, parent_page->frame->kva, PGSIZE);
    }
  }

  // 모든 페이지 복사가 성공적으로 완료됨
  return true;
}

/* Free the resource hold by the supplemental page table */

// supplemental page table에 의해 유지되던 모든 자원들을 free합니다. 이 함수는
// process가 exit할 때(userprog/process.c의 process_exit()) 호출됩니다. 당신은
// 페이지 엔트리를 반복하면서 테이블의 페이지에 destroy(page)를 호출하여야
// 합니다. 당신은 이 함수에서 실제 페이지 테이블(pml4)와 물리 주소(palloc된
// 메모리)에 대해 걱정할 필요가 없습니다. supplemental page table이 정리되어지고
// 나서, 호출자가 그것들을 정리할 것입니다.
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
  /* TODO: Destroy all the supplemental_page_table hold by thread and
   * TODO: writeback all the modified contents to the storage. */
  hash_clear(&spt->hash_spt, page_destroy);
}

/*********************************/

/* supplemental page table, project 3*/

/* Returns a hash value for page p. */
unsigned page_hash(const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry(p_, struct page, hash_elem);
  return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_,
               void *aux UNUSED) {
  const struct page *a = hash_entry(a_, struct page, hash_elem);
  const struct page *b = hash_entry(b_, struct page, hash_elem);

  return a->va < b->va;
}

void page_destroy(struct hash_elem *e, void *aux) {
  struct page *page = hash_entry(e, struct page, hash_elem);
  // vm_dealloc_page(page);
  destroy(page);
  free(page);
}

/*********************************/