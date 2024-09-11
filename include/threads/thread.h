#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#ifdef VM
#include "vm/vm.h"
#endif
#ifdef USERPROG
#include "synch.h"
#endif

/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */

struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */

	/* custom */
	/**********************************/
	/* alarm clock, project 1 */

	int64_t sleep_time;

	/* alarm clock, project 1*/
	/**********************************/
	/* priority scheduling, project 1 */

	int donated_priority;
	

	uint8_t padding_1;
	uint8_t cflag;
	uint8_t padding_2;
	
	struct list locks; 
	struct lock* wanted_lock;

	/* priority scheduling, project 1 */
	/**********************************/
	/* mlfqs scheduling, project 1*/

	uint8_t padding_3;

	int32_t nice; 
	int32_t recent_cpu;

	uint8_t padding_4;

	/* mlfqs scheduling, project 1*/
	/**********************************/
	/* custom */

	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */

	

#ifdef USERPROG
	/* Owned by userprog/process.c. */

	uint64_t *pml4;                     /* Page map level 4 */


	/* process include 안했는데 왜 됨? */
	struct process *process;
	struct list_elem p_elem;
	
	struct semaphore p_wait_sema;
	struct list process_children;
	struct list_elem p_child_elem;
	bool is_process;
	int exit_code;
	// 자식 process는 부모 process가 wait할 때까지 자식은 자원을 반환(destroyed)하면 안됨. 이를 위한 sema 중요
	struct semaphore kill_sema;

#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */

extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

/* custom */
/***************************************************/
/* alarm clock , project 1 */

void thread_sleep(int64_t ticks);

void thread_wakeup(int64_t ticks);

/* alarm clock , project 1 */
/***************************************************/
/* priority scheduling , project 1*/

#define CFLAG_PRT_DONATED 0x1
#define CFLAG_WAIT_LOCK 0x2

#define is_prt_donated(t) (t->cflag & CFLAG_PRT_DONATED)
#define set_donated_prt(t,p) ({t->cflag |= CFLAG_PRT_DONATED; t->donated_priority = p;})
#define free_donated_prt(t) (t->cflag &= ~CFLAG_PRT_DONATED)

#define is_wait_lock(t) (t->cflag & CFLAG_WAIT_LOCK)
#define set_wait_lock(t,lock) ({t->cflag |= CFLAG_WAIT_LOCK; t->wanted_lock = lock;})
#define set_wait_sema(t) (t->cflag |= CFLAG_WAIT_LOCK)
#define free_wait_lock(t) (t->cflag &= ~CFLAG_WAIT_LOCK)

bool // thread t에게 현재 스레드의 prt 기부를 시도함.
thread_try_donate_prt(int given_prt, struct thread* to);

void 
thread_event(void);

int
thread_get_priority_any(const struct thread* t);

/* priority scheduling , project 1 */
/***************************************************/
/* mlfqs scheduling, project 1 */

typedef int ffloat;

#define fbase (1<<14)

#define convert_if(n) ((n) * fbase)
#define convert_fi(x) ((x) / fbase)
#define convert_fi_near(x) ( (x)>0 ? ((x) + fbase / 2) / fbase : ((x) - fbase / 2) / fbase )

#define add_ff(x,y) ((x) + (y)) //둘다 실수 
#define add_fi(x,y) ((x) + (y) * fbase)

#define sub_ff(x,y) ((x) - (y))
#define sub_fi(x,n) ((x) - (n) * fbase) // x는 실수 , y는 정수 


#define mul_fi(x,n) ((x) * (n))
#define mul_ff(x,y) (((int64_t)(x)) * (y) / fbase)


#define div_fi(x,n) ((x) / (n))
#define div_ff(x,y) (((int64_t)(x)) * fbase / (y))

/* mlfqs scheduling, project 1 */
/***************************************************/
/* user program, project 2 */
#ifdef USERPROG

#define KILLED 999999
void init_process_wait_info();
struct thread *get_child_by_id(tid_t child_tid);


#endif

/* user program, project 2 */
/***************************************************/

#endif /* threads/thread.h */
