#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

//#include "init.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/************************************************************************/
/* syscall, project 2  */
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "string.h"
#include "threads/malloc.h"

typedef void 
syscall_handler_func(struct intr_frame *);

static syscall_handler_func 
*syscall_handlers[25]; // 25는 총 syscall 갯수;


static void
halt_handler(struct intr_frame *f);

static void 
exit_handler(struct intr_frame* f);

static void 
fork_handler(struct intr_frame* f);

static void
exec_handler(struct intr_frame* f);

static void 
wait_handler(struct intr_frame* f);

static void
create_handler(struct intr_frame* f);

static void
remove_hander(struct intr_frame* f);

static void
read_handler(struct intr_frame* f);

static void 
open_handler(struct intr_frame *f);

static void 
filesize_handler(struct intr_frame* f);

static void  
write_handler(struct intr_frame* f);

static void
seek_handler(struct intr_frame* f);

static void
tell_handler(struct intr_frame* f);

static void
close_handler(struct intr_frame* f);



/* syscall, project 2 */
/************************************************************************/

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
	
	/***********************************************/
	/* syscall, project 2 */

	// memset(fd_list, 0, sizeof(fd_list)); // fd 초기화
	

	memset(syscall_handlers, 0 , sizeof(syscall_handlers)); // sycall 함수배열 초기화

	syscall_handlers[SYS_HALT] = halt_handler;
	syscall_handlers[SYS_EXIT] = exit_handler;
	syscall_handlers[SYS_FORK] = fork_handler;
	syscall_handlers[SYS_EXEC] =exec_handler;
	syscall_handlers[SYS_WAIT] = wait_handler;
	syscall_handlers[SYS_CREATE] = create_handler;
	syscall_handlers[SYS_REMOVE] = remove_hander;
	syscall_handlers[SYS_READ] = read_handler;
	syscall_handlers[SYS_OPEN] = open_handler;
	syscall_handlers[SYS_FILESIZE] = filesize_handler;
	syscall_handlers[SYS_WRITE] = write_handler; 
	syscall_handlers[SYS_SEEK] = seek_handler;
	syscall_handlers[SYS_TELL] = tell_handler;
	syscall_handlers[SYS_CLOSE] = close_handler;


	//syscall_hadnlers[SYS_FILESIZE] = 
	/***********************************************/
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	/****************************************/
	/* syscall, project 2 */

	syscall_handler_func *handler;
	int sys_num;

	
	sys_num = f->R.rax;
	handler = syscall_handlers[sys_num];
	handler(f);

	/* syscall, project 2 */
	/****************************************/
}



/*******************************************/







static void
halt_handler(struct intr_frame *f){

}

static void 
exit_handler(struct intr_frame* f){
	int status;
	status = f->R.rdi;
	f->R.rax = status;
	thread_exit();
}

static void 
fork_handler(struct intr_frame* f){

}

static void
exec_handler(struct intr_frame* f)
{

}

static void 
wait_handler(struct intr_frame* f)
{

}

static void
create_handler(struct intr_frame* f)
{

}

static void
remove_hander(struct intr_frame* f)
{

}

static void
read_handler(struct intr_frame* f)
{

}

static void 
open_handler(struct intr_frame *f)
{
	char* file_name = &f->R.rdi;
	struct file *file = NULL;

	
	/* Open executable file. */
	file = filesys_open (file_name);
	if (file == NULL) {
		printf ("load: %s: open failed\n", file_name);
		f->R.rax = -1;
		return;
	}
}

static void 
filesize_handler(struct intr_frame* f)
{

}

static void  
write_handler(struct intr_frame* f) // 핸들러를 실행하는 주체는 kernel 모드로 전환한 user prog이다.
{
	int fd;
	void* buffer;
	unsigned size;
	struct thread* t = thread_current();
	fd = f->R.rdi;
	buffer = f->R.rsi;
	size = f->R.rdx;

	if(fd == STDOUT_FILENO)	
		putbuf(buffer,size);
}

static void
seek_handler(struct intr_frame* f)
{

}

static void
tell_handler(struct intr_frame* f)
{

}

static void
close_handler(struct intr_frame* f)
{

}
