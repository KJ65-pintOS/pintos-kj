/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"


/***************************************/
/* priority scheduling, project 1 */

static void
lock_checkup(struct thread* t, struct lock* l);

static bool
sort_by_prt_desc_semaelem (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED);
static bool
sort_by_prt_desc_thread (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED);
static bool
sort_by_prt_desc_lock (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED) ;

#define lock_peeker(list) (list_entry(list_max(list,sort_by_prt_desc_lock,NULL),struct lock, elem))
#define thread_peeker(list) (list_entry(list_max(list,sort_by_prt_desc_thread,NULL),struct thread, elem))

/* priority scheduling, project 1 */
/***************************************/



/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}


/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
      list_push_back(&sema->waiters, &(thread_current()->elem));
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
   sema->value++;
	if (!list_empty (&sema->waiters)){
      
      struct thread* next_t = thread_peeker(&sema->waiters);
      list_remove(&next_t->elem);
		thread_unblock (next_t);
      thread_event();
   }
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);
   lock->max_prt = PRI_MIN;
	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
lock_acquire (struct lock *lock) {
   struct thread* curr;
   enum intr_level old_level;

	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));
   
   curr = thread_current();
   old_level = intr_disable();
   if(!sema_try_down(&lock->semaphore)){
      set_wait_lock(curr,lock);
      lock_checkup(curr,lock); // O(D) 의 작업시간 소요됨
      sema_down (&lock->semaphore);
      lock->max_prt = thread_get_priority_any(
         thread_peeker(&lock->semaphore.waiters)); // O(N)의 작업시간 소요됨
      free_wait_lock(curr);
   } 

   intr_set_level(old_level);
   list_push_back(&curr->locks, &lock->elem);
	lock->holder = curr;
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL); 
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
   struct thread * curr;
   struct lock *peeked_lock;
   enum intr_level old_level;

	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));

   old_level = intr_disable(); 
   free_donated_prt(lock->holder); //현재 donated 값을 제거
   list_remove(&(lock->elem)); //현재 스레드에서 lock을 제거 
   curr = thread_current();
   if(!list_empty(&curr->locks))
   {
      peeked_lock = lock_peeker(&curr->locks); //맨 앞 스레드의 값을 가져오고있음. 하지만 Lock이랑 맨 첫번째 값이랑 비교후 
      thread_try_donate_prt(peeked_lock->max_prt, curr); // 이 시점에서 lock의 prt가 바뀌면 안됨.
   }
   intr_set_level(old_level);
   
	lock->holder = NULL;
	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}



/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

   waiter.max_prt = thread_get_priority_any(lock->holder);
	sema_init (&waiter.semaphore, 0);
	list_push_back (&cond->waiters, &waiter.elem);
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock UNUSED) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));
   
   struct semaphore_elem* cond_t;
	if (!list_empty (&cond->waiters)){
      cond_t = list_entry (list_max(&cond->waiters, sort_by_prt_desc_semaelem, NULL),
					struct semaphore_elem, elem);
      list_remove(&cond_t->elem);
		sema_up (&cond_t->semaphore);
   }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}




/***************************************************************************/
/* priority scheduling, project 1 */

static void
lock_checkup(struct thread* t, struct lock* l)
{
   struct thread* holder;
   int prt;

   ASSERT(intr_get_level() == INTR_OFF);

   holder = l->holder;
   prt = thread_get_priority_any(t);
   if( prt >= l->max_prt ){ // lazy insert가 해결되면 ==로 교체해도 작동해야한다. 
      l->max_prt = prt;
      if(thread_try_donate_prt(prt,holder)
         &&is_wait_lock(holder) )
         lock_checkup(holder,holder->wanted_lock);
   }
}


static bool
sort_by_prt_desc_thread (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED) 
{
  const struct thread *a = list_entry (a_, struct thread, elem);
  const struct thread *b = list_entry (b_, struct thread, elem);
  return thread_get_priority_any(a) < thread_get_priority_any(b);
}


static bool
sort_by_prt_desc_lock (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED) 
{
  const struct lock *a = list_entry (a_, struct lock, elem);
  const struct lock *b = list_entry (b_, struct lock, elem);
  return a->max_prt < b->max_prt;
}


static bool
sort_by_prt_desc_semaelem (const struct list_elem *a_, const struct list_elem *b_,
            void *aux UNUSED)
{
  const struct semaphore_elem *a = list_entry (a_, struct semaphore_elem, elem);
  const struct semaphore_elem *b = list_entry (b_, struct semaphore_elem, elem);
  return a->max_prt < b->max_prt;
}


/* priority scheduling, project 1 */
/***************************************************************************/
