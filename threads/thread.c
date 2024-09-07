#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "intrinsic.h"
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* Random value for basic thread
   Do not modify this value. */
#define THREAD_BASIC 0xd42df210

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Thread destruction requests */
static struct list destruction_req;

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* custom define */
/**********************************************/
/* alarm clock, project 1 */

static struct list waiting_list;
static bool
sort_by_sleeptime_asc (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED);

/* alarm clock, project 1 */
/**********************************************/
/* priority scheduling, project 1 */

static bool
sort_by_prt_desc (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) ;
static bool 
is_priority_less_than_next(int64_t p);
#define thread_entry(list_elem) (list_entry(list_elem, struct thread, elem))
#define insert_ready(elem) (list_insert_ordered(&ready_list, &(elem), sort_by_prt_desc,NULL))

/* priority scheduling, project 1 */
/**********************************************/
/* advanced scheduling, project 1 */
typedef void calculation(struct thread* t);

static ffloat load_avg; 		
static struct list mlfqs_all_thread;

static void mlfqs_reset_prt(void);
static void mlfqs_task(void);
// static void mlfqs_recalibrate(struct list * l);

static void linear_traversal(struct list* l, calculation* func);
static void mlfqs_set_load_avg(void);
static void mlfqs_set_priority(struct thread* t);
static void mlfqs_set_recent_cpu(struct thread* t);

/* advanced scheduling, project 1 */
/**********************************************/

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);


/* Returns true if T appears to point to a valid thread. */
#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC)
/* Returns the running thread.
 * Read the CPU's stack pointer `rsp', and then round that
 * down to the start of a page.  Since `struct thread' is
 * always at the beginning of a page and the stack pointer is
 * somewhere in the middle, this locates the curent thread. */
#define running_thread() ((struct thread *) (pg_round_down (rrsp ())))


// Global descriptor table for the thread_start.
// Because the gdt will be setup after the thread_init, we should
// setup temporal gdt first.
static uint64_t gdt[3] = { 0, 0x00af9a000000ffff, 0x00cf92000000ffff };

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) {
	ASSERT (intr_get_level () == INTR_OFF);

	/* Reload the temporal gdt for the kernel
	 * This gdt does not include the user context.
	 * The kernel will rebuild the gdt with user context, in gdt_init (). */
	struct desc_ptr gdt_ds = {
		.size = sizeof (gdt) - 1,
		.address = (uint64_t) gdt
	};
	lgdt (&gdt_ds);

	/* Init the globla thread context */
	lock_init (&tid_lock);
	list_init (&ready_list);
	list_init (&destruction_req);
	
	/* custum init part  */
	list_init(&waiting_list);
	
	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();


	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();

	if(thread_mlfqs)
	{
		// mlfqs
		initial_thread->nice = 0;
		initial_thread->recent_cpu = 0;
		load_avg = 0;
		list_init(&mlfqs_all_thread);
	}
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) {
	/* Create the idle thread. */
	struct semaphore idle_started;
	sema_init (&idle_started, 0);
	thread_create ("idle", PRI_MIN, idle, &idle_started);

	/* Start preemptive thread scheduling. */
	intr_enable ();

	/* Wait for the idle thread to initialize idle_thread. */
	sema_down (&idle_started);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) {
	struct thread *t = thread_current ();

	/* Update statistics. */
	if (t == idle_thread)
		idle_ticks++;
#ifdef USERPROG
	else if (t->pml4 != NULL)
		user_ticks++;
#endif
	else{
		kernel_ticks++;
		if(thread_mlfqs)
			t->recent_cpu = add_fi(t->recent_cpu,1);
			
	}
	if(thread_mlfqs && ((idle_ticks+kernel_ticks) % 100 == 0))
		mlfqs_task();
	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE){
		if( thread_mlfqs )
			mlfqs_reset_prt();
		intr_yield_on_return();
	}
}

/* Prints thread statistics. */
void
thread_print_stats (void) {
	printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
			idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
		thread_func *function, void *aux) {
	struct thread *t;
	tid_t tid;

	ASSERT (function != NULL);

	/* Allocate thread. */
	t = palloc_get_page (PAL_ZERO);
	if (t == NULL)
		return TID_ERROR;

	/* Initialize thread. */
	init_thread (t, name, priority);
	tid = t->tid = allocate_tid ();

;	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	if(thread_mlfqs){
		t->nice = thread_get_nice(); // 상속
		t->recent_cpu = thread_current()->recent_cpu;
	}

	/* Add to run queue. */
	thread_unblock (t);
	if(is_priority_less_than_next(thread_get_priority())) 
		thread_yield();
	return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) {
	ASSERT (!intr_context ());
	ASSERT (intr_get_level () == INTR_OFF);
	thread_current ()->status = THREAD_BLOCKED;
	schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) {
	enum intr_level old_level;

	ASSERT (is_thread (t));

	old_level = intr_disable ();
	ASSERT (t->status == THREAD_BLOCKED);
	insert_ready(t->elem);
	t->status = THREAD_READY;
	intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) {
	return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) {
	struct thread *t = running_thread ();

	/* Make sure T is really a thread.
	   If either of these assertions fire, then your thread may
	   have overflowed its stack.  Each thread has less than 4 kB
	   of stack, so a few big automatic arrays or moderate
	   recursion can cause stack overflow. */
	ASSERT (is_thread (t));
	ASSERT (t->status == THREAD_RUNNING);

	return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) {
	return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) {
	ASSERT (!intr_context ());

#ifdef USERPROG
	process_exit ();
#endif

	/* Just set our status to dying and schedule another process.
	   We will be destroyed during the call to schedule_tail(). */
	intr_disable ();
	do_schedule (THREAD_DYING);
	NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) {
	struct thread *curr = thread_current ();
	enum intr_level old_level;

	ASSERT (!intr_context ());

	old_level = intr_disable ();
	if (curr != idle_thread)
		insert_ready(curr->elem);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}


/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) { //donated Flag에서 적절한 작동 보장 해야함
	thread_current ()->priority = new_priority;
	if(is_priority_less_than_next(new_priority))
		thread_yield();
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) {
	struct thread* t = thread_current();
	return ( is_prt_donated(t)? t->donated_priority : t->priority);
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice UNUSED) {
	/* TODO: Your implementation goes here */
	thread_current()->nice = nice;
	// mlfqs_reset_prt();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return convert_fi(mul_fi(load_avg,100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	
	return convert_fi_near(mul_fi(thread_current()->recent_cpu, 100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) {
	struct semaphore *idle_started = idle_started_;

	idle_thread = thread_current ();
	sema_up (idle_started);

	for (;;) {
		/* Let someone else run. */
		intr_disable ();
		thread_block ();

		/* Re-enable interrupts and wait for the next one.

		   The `sti' instruction disables interrupts until the
		   completion of the next instruction, so these two
		   instructions are executed atomically.  This atomicity is
		   important; otherwise, an interrupt could be handled
		   between re-enabling interrupts and waiting for the next
		   one to occur, wasting as much as one clock tick worth of
		   time.

		   See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
		   7.11.1 "HLT Instruction". */
		asm volatile ("sti; hlt" : : : "memory");
	}
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) {
	ASSERT (function != NULL);

	intr_enable ();       /* The scheduler runs with interrupts off. */
	function (aux);       /* Execute the thread function. */
	thread_exit ();       /* If function() returns, kill the thread. */
}


/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority) {
	ASSERT (t != NULL);
	ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
	ASSERT (name != NULL);
#ifdef USERPROG
	char *space_p = strchr(name, ' ');
	if (space_p != NULL)
		*space_p = '\0';
#endif
	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;
	t->magic = THREAD_MAGIC;

	/*custom valuable*/
	t->donated_priority = 0;
	t->sleep_time = 0;
	t->cflag = 0;
	t->wanted_lock = (void*)0;

	list_init(&t->locks);
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) {
	if (list_empty (&ready_list))
		return idle_thread;
	else
		return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Use iretq to launch the thread */
void
do_iret (struct intr_frame *tf) {
	__asm __volatile(
			"movq %0, %%rsp\n"
			"movq 0(%%rsp),%%r15\n"
			"movq 8(%%rsp),%%r14\n"
			"movq 16(%%rsp),%%r13\n"
			"movq 24(%%rsp),%%r12\n"
			"movq 32(%%rsp),%%r11\n"
			"movq 40(%%rsp),%%r10\n"
			"movq 48(%%rsp),%%r9\n"
			"movq 56(%%rsp),%%r8\n"
			"movq 64(%%rsp),%%rsi\n"
			"movq 72(%%rsp),%%rdi\n"
			"movq 80(%%rsp),%%rbp\n"
			"movq 88(%%rsp),%%rdx\n"
			"movq 96(%%rsp),%%rcx\n"
			"movq 104(%%rsp),%%rbx\n"
			"movq 112(%%rsp),%%rax\n"
			"addq $120,%%rsp\n"
			"movw 8(%%rsp),%%ds\n"
			"movw (%%rsp),%%es\n"
			"addq $32, %%rsp\n"
			"iretq"
			: : "g" ((uint64_t) tf) : "memory");
}

/* Switching the thread by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function. */
static void
thread_launch (struct thread *th) {
	uint64_t tf_cur = (uint64_t) &running_thread ()->tf;
	uint64_t tf = (uint64_t) &th->tf;
	ASSERT (intr_get_level () == INTR_OFF);

	/* The main switching logic.
	 * We first restore the whole execution context into the intr_frame
	 * and then switching to the next thread by calling do_iret.
	 * Note that, we SHOULD NOT use any stack from here
	 * until switching is done. */
	__asm __volatile (
			/* Store registers that will be used. */
			"push %%rax\n"
			"push %%rbx\n"
			"push %%rcx\n"
			/* Fetch input once */
			"movq %0, %%rax\n"
			"movq %1, %%rcx\n"
			"movq %%r15, 0(%%rax)\n"
			"movq %%r14, 8(%%rax)\n"
			"movq %%r13, 16(%%rax)\n"
			"movq %%r12, 24(%%rax)\n"
			"movq %%r11, 32(%%rax)\n"
			"movq %%r10, 40(%%rax)\n"
			"movq %%r9, 48(%%rax)\n"
			"movq %%r8, 56(%%rax)\n"
			"movq %%rsi, 64(%%rax)\n"
			"movq %%rdi, 72(%%rax)\n"
			"movq %%rbp, 80(%%rax)\n"
			"movq %%rdx, 88(%%rax)\n"
			"pop %%rbx\n"              // Saved rcx
			"movq %%rbx, 96(%%rax)\n"
			"pop %%rbx\n"              // Saved rbx
			"movq %%rbx, 104(%%rax)\n"
			"pop %%rbx\n"              // Saved rax
			"movq %%rbx, 112(%%rax)\n"
			"addq $120, %%rax\n"
			"movw %%es, (%%rax)\n"
			"movw %%ds, 8(%%rax)\n"
			"addq $32, %%rax\n"
			"call __next\n"         // read the current rip.
			"__next:\n"
			"pop %%rbx\n"
			"addq $(out_iret -  __next), %%rbx\n"
			"movq %%rbx, 0(%%rax)\n" // rip
			"movw %%cs, 8(%%rax)\n"  // cs
			"pushfq\n"
			"popq %%rbx\n"
			"mov %%rbx, 16(%%rax)\n" // eflags
			"mov %%rsp, 24(%%rax)\n" // rsp
			"movw %%ss, 32(%%rax)\n"
			"mov %%rcx, %%rdi\n"
			"call do_iret\n"
			"out_iret:\n"
			: : "g"(tf_cur), "g" (tf) : "memory"
			);
}

/* Schedules a new process. At entry, interrupts must be off.
 * This function modify current thread's status to status and then
 * finds another thread to run and switches to it.
 * It's not safe to call printf() in the schedule(). */
static void
do_schedule(int status) {
	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (thread_current()->status == THREAD_RUNNING);
	while (!list_empty (&destruction_req)) {
		struct thread *victim =
			list_entry (list_pop_front (&destruction_req), struct thread, elem);
		palloc_free_page(victim);
	}
	thread_current ()->status = status;
	schedule ();
}


static void
schedule (void) {
	struct thread *curr = running_thread ();
	struct thread *next = next_thread_to_run ();

	ASSERT (intr_get_level () == INTR_OFF);
	ASSERT (curr->status != THREAD_RUNNING);
	ASSERT (is_thread (next));
	/* Mark us as running. */
	next->status = THREAD_RUNNING;

	/* Start new time slice. */
	thread_ticks = 0;

#ifdef USERPROG
	/* Activate the new address space. */
	process_activate (next);
#endif

	if (curr != next) {
		/* If the thread we switched from is dying, destroy its struct
		   thread. This must happen late so that thread_exit() doesn't
		   pull out the rug under itself.
		   We just queuing the page free reqeust here because the page is
		   currently used by the stack.
		   The real destruction logic will be called at the beginning of the
		   schedule(). */
		if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
			ASSERT (curr != next);
			list_push_back(&destruction_req,&curr->elem);
		}

		/* Before switching the thread, we first save the information
		 * of current running. */
		
		thread_launch (next);
	}
}


/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) {
	static tid_t next_tid = 1;
	tid_t tid;

	lock_acquire (&tid_lock);
	tid = next_tid++;
	lock_release (&tid_lock);

	return tid;
}


/* custom  function */
/***************************************************************/
/* alarm clock, project 1 */

void 
thread_sleep(int64_t ticks)
{
	struct thread *curr = thread_current();
	enum intr_level old_level;
	
	ASSERT(ticks != 0);
	ASSERT(intr_get_level() == INTR_ON);
	ASSERT(!intr_context ());  // internel interrupt만 받음

	old_level = intr_disable ();
	curr->sleep_time = ticks;
	list_insert_ordered(&waiting_list,&(curr->elem),sort_by_sleeptime_asc,NULL);
	thread_block();
	intr_set_level (old_level);
}


void 
thread_wakeup(int64_t ticks)
{
	while(!list_empty(&waiting_list) && (list_entry(list_front(&waiting_list), struct thread, elem))->sleep_time <= ticks )
		thread_unblock(list_entry(list_pop_front(&waiting_list),struct thread, elem));
	
}

static bool
sort_by_sleeptime_asc(const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) 
{
  const struct thread *a = list_entry (a_, struct thread, elem);
  const struct thread *b = list_entry (b_, struct thread, elem);
  return a->sleep_time < b-> sleep_time;
}


/* alarm clock, project 1 */
/***************************************************************/
/* priority scheduling, project 1 */


bool // thread t에게 현재 스레드의 prt 기부를 시도함.
thread_try_donate_prt(int given_prt, struct thread* to)
{
	ASSERT(is_thread(to));

	if(is_prt_donated(to))
	{
		if(to->donated_priority > given_prt)
			return false;
		set_donated_prt(to,given_prt);
	}
	else
	{
		if(to->priority > given_prt)
			return false;
		set_donated_prt(to,given_prt);
	}
	return true;
}


void 
thread_event(void)
{
	if(is_priority_less_than_next(thread_get_priority())) {
		if (intr_context())
			intr_yield_on_return();
		else
			thread_yield();
	}
}


int
thread_get_priority_any(const struct thread* t)
{	
	uint8_t test = is_prt_donated(t);
	return (test ? t->donated_priority : t->priority);
}


/* Compare 'p'(p should be priority of some thread) 
   with ready_list thread. */
static bool 
is_priority_less_than_next(int64_t p)
{
	if(list_empty(&ready_list))
		return false;
	struct thread *front = thread_entry(list_front(&ready_list));
	return (p <= thread_get_priority_any(front));
}


// Todo 이후에 bit mask 추가해서 insert_by_prt 와 통합
static bool
sort_by_prt_desc (const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) 
{
  const struct thread *a = list_entry (a_, struct thread, elem);
  const struct thread *b = list_entry (b_, struct thread, elem);
  return thread_get_priority_any(a) > thread_get_priority_any(b);
}


/* priority scheduling, project 1 */
/***************************************************************/
/* advanced scheduling, project 1 */



static void 
mlfqs_reset_prt(void)
{	
	mlfqs_set_priority(thread_current());
	linear_traversal(&ready_list, mlfqs_set_priority);
	linear_traversal(&waiting_list, mlfqs_set_priority);
	list_sort(&ready_list, sort_by_prt_desc, NULL);
}



static void 
mlfqs_task(void)
{	
	mlfqs_set_load_avg();
	mlfqs_set_recent_cpu(thread_current());
	linear_traversal(&ready_list, mlfqs_set_recent_cpu);
	linear_traversal(&waiting_list, mlfqs_set_recent_cpu);
}


static void 
linear_traversal(struct list* l, calculation* func)
{	
	struct thread * t;
	if(!list_empty(l)){
		t = list_entry(list_front(l), struct thread, elem);
		while(is_thread(t))
		{	
			func(t);
			t = list_entry(list_next(&t->elem),struct thread, elem);
		}
	}
}


static void 
mlfqs_set_load_avg(void)
{
	ffloat f1, f59, f60;
	int size;

	ASSERT(intr_get_level() == INTR_OFF);

	f1 = convert_if(1);
	f59 = convert_if(59);
	f60 = convert_if(60);

	size = (idle_thread == thread_current()) ? list_size(&ready_list) : list_size(&ready_list)+1;

	/* load_avg = (59/60) * load_avg + (1/60) * ready_threads */
	load_avg = add_ff(mul_ff( div_ff(f59,f60), load_avg ),mul_fi( div_ff(f1,f60), size));
}


static void 
mlfqs_set_recent_cpu(struct thread* t)
{
	ASSERT(intr_get_level() == INTR_OFF);

	/* recent_cpu = (2 * load_avg) / (2 * load_avg + 1) * recent_cpu + nice */
	t->recent_cpu = add_fi(mul_ff( div_ff(mul_fi(load_avg,2), add_fi(mul_fi(load_avg,2),1)), t->recent_cpu), t->nice);
}


static void 
mlfqs_set_priority(struct thread* t)
{	
	ASSERT(intr_get_level() == INTR_OFF);

	/* priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
	t->priority = PRI_MAX - convert_fi(add_ff(div_fi(t->recent_cpu, 4),convert_if(t->nice * 2)));  
	if(t->priority < PRI_MIN )
		t->priority = PRI_MIN;
	else if(t->priority > PRI_MAX)
		t->priority = PRI_MAX;
}


/* advanced scheduling, project 1 */
/*****************************************************************/