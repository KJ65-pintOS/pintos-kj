#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* handlers */
static void exit_handler(struct intr_frame *f);
static void write_handler(struct intr_frame *f);
static void fork_handler(struct intr_frame *f);
static void wait_handler(struct intr_frame *f);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	/*
		시스템 콜 핸들러는 시스템 콜 번호를 받아오고, 시스템 콜 인자들을 받아오고, 그에 알맞은 액션을 취해야 합니다.
	*/
	switch (f->R.rax) {
		case SYS_EXIT:
			exit_handler(f);
			break;
		case SYS_WRITE:
			write_handler(f);
			break;
		case SYS_FORK:
			fork_handler(f);
			break;
		case SYS_WAIT:
			wait_handler(f);
			break;
		default:
			thread_exit();
			break;
	}
	
}

static void exit_handler(struct intr_frame *f) {
	struct thread *current = thread_current();
	int exit_code = f->R.rdi;
	current->exit_code = exit_code;
	current->tf.R.rax = exit_code;
	thread_exit();
}

static void write_handler(struct intr_frame *f) {
	/*
		rdi = fd
		rsi = buffer
		rdx = size
	*/
	uint64_t fd = f->R.rdi;
	char* buffer = (char *)f->R.rsi;
	size_t size = (size_t)f->R.rdx;
	if (fd == STDOUT_FILENO)
		putbuf(buffer, size);
	f->R.rax = size; // return size
}

void fork_handler(struct intr_frame *f) {
	char *thread_name = (char *)f->R.rdi;
	init_process_wait_info();
	int pid = process_fork(thread_name, f);

	f->R.rax = pid;  // set fork() syscall return value as pid of child
	// is_process = false 해주는거 고려
}

void wait_handler(struct intr_frame *f) {
	int pid = (int)f->R.rdi;
	int exit_code = process_wait(pid);

	f->R.rax = exit_code;
}
