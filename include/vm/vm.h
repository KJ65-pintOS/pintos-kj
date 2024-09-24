#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>
#include "threads/palloc.h"
#include <hash.h>
#include "threads/synch.h"

enum vm_type {
	/* page not initialized */
	VM_UNINIT = 0,
	/* page not related to the file, aka anonymous page */
	VM_ANON = 1,
	/* page that realated to the file */
	VM_FILE = 2,
	/* page that hold the page cache, for project 4 */
	VM_PAGE_CACHE = 3,

	/* Bit flags to store state */

	/* Auxillary bit flag marker for store information. You can add more
	 * markers, until the value is fit in the int. */
	VM_MARKER_0 = (1 << 3),
	VM_MARKER_1 = (1 << 4),

	/* DO NOT EXCEED THIS VALUE. */
	VM_MARKER_END = (1 << 31),
};

#include "vm/uninit.h"
#include "vm/anon.h"
#include "vm/file.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page { // vm_entry의 역할
	const struct page_operations *operations;
	void *va;              /* Address in terms of user space */
	struct frame *frame;   /* Back reference for frame */

	/* Your implementation */
	struct hash_elem hash_elem;
	bool writable;
	bool is_user_stack; // get_victim에서 고려해야 하나?
	int fault_cnt;
	// location in swqp area
	// reference to the file object and offset(memory mapped file)

	/* Per-type data are binded into the union.
	 * Each function automatically detects the current union */
	// page마다 아래 중 하나의 page 종류만 사용 가능함
	union {
		struct uninit_page uninit;
		struct anon_page anon;
		struct file_page file;
#ifdef EFILESYS
		struct page_cache page_cache;
#endif
	};
};

/* The representation of "frame" */
/* - 물리 메모리 상의 연속적인 영역입니다. 페이지와 동일하게, 프레임은 PAGE_SIZE여야 하고 페이지 크기에 정렬되어 있어야 합니다 
   - 프레임 테이블에는 각 프레임의 엔트리 정보가 담겨 있습니다. 
   - 프레임 테이블의 각 엔트리에는 현재 해당 엔트리를 차지하고 있는 페이지에 대한 포인터(있는 경우라면), 그리고 당신의 선택에 따라 넣을 수 있는 기타 데이터들이 담겨 있습니다. 
   - 프레임 테이블은 비어있는 프레임이 없을 때 쫓아낼 페이지를 골라줌으로써, Pintos가 효율적으로 eviction policy를 구현할 수 있도록 해줍니다.
	palloc.c의 user_pool 봐야 함. user_pool.bitmap.cnt = 생성 가능 총 page 갯수. base = 시작 kva. 이걸로 frame table의 key로 구성해야
	extern keyword로 잘 받아올 것.
*/
struct frame {
	void *kva;
	struct page *page;
	struct hash_elem hash_elem;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations {
	bool (*swap_in) (struct page *, void *);
	bool (*swap_out) (struct page *);
	void (*destroy) (struct page *);
	enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in ((page), v)
#define swap_out(page) (page)->operations->swap_out (page)
#define destroy(page) \
	if ((page)->operations->destroy) (page)->operations->destroy (page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table {
	struct hash pages;
	struct lock hash_lock; // hash table을 수정하는 함수(insert, delete etc)는 사용할 때 동시성을 조율해야 함
};

struct frame_table {
	struct hash frames;
	struct lock hash_lock;
	int usable_page_cnt;
};

#include "threads/thread.h"
void supplemental_page_table_init (struct supplemental_page_table *spt);
bool supplemental_page_table_copy (struct supplemental_page_table *dst,
		struct supplemental_page_table *src);
void supplemental_page_table_kill (struct supplemental_page_table *spt);
struct page *spt_find_page (struct supplemental_page_table *spt,
		void *va);
bool spt_insert_page (struct supplemental_page_table *spt, struct page *page);
void spt_remove_page (struct supplemental_page_table *spt, struct page *page);

void vm_init (void);
bool vm_try_handle_fault (struct intr_frame *f, void *addr, bool user,
		bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
	vm_alloc_page_with_initializer ((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer (enum vm_type type, void *upage,
		bool writable, vm_initializer *init, void *aux);
void vm_dealloc_page (struct page *page);
bool vm_claim_page (void *va);
enum vm_type page_get_type (struct page *page);
#endif  /* VM_VM_H */
