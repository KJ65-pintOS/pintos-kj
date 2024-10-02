
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

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/************************************************************************/
/* syscall, project 2  */
#ifdef USERPROG

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "string.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"

/************************************************************************/
/* project 3  */
#include "vm/vm.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
/************************************************************************/

typedef void
syscall_handler_func(struct intr_frame *);

static syscall_handler_func
	*syscall_handlers[25]; // 25는 총 syscall 갯수;

#define get_fd_table(thread) (thread->fd_table)

static struct file *
get_file_by_fd(int fd);

static bool
is_vaddr_valid(void *vaddr);
/* project 3 */
/****************************************************************/
static bool
is_writable_vaddr(void* vaddr);
/****************************************************************/

static void
halt_handler(struct intr_frame *f);
static void
exit_handler(struct intr_frame *f);
static void
fork_handler(struct intr_frame *f);
static void
exec_handler(struct intr_frame *f);
static void
wait_handler(struct intr_frame *f);
static void
create_handler(struct intr_frame *f);
static void
remove_hander(struct intr_frame *f);
static void
read_handler(struct intr_frame *f);
static void
open_handler(struct intr_frame *f);
static void
filesize_handler(struct intr_frame *f);
static void
write_handler(struct intr_frame *f);
static void
seek_handler(struct intr_frame *f);
static void
tell_handler(struct intr_frame *f);
static void
close_handler(struct intr_frame *f);
/* project 3 */
/****************************************************************/
static void
mmap_handler(struct intr_frame *f);
/****************************************************************/

#endif
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

#define MSR_STAR 0xc0000081			/* Segment selector msr */
#define MSR_LSTAR 0xc0000082		/* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void)
{
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 |
							((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			  FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

#ifdef USERPROG /* syscall, project 2 */

	// /* 자 지금부터 열려있는 모든 파일은 커널이 관리합니다. */
	memset(syscall_handlers, 0, sizeof(syscall_handlers)); // sycall 함수배열 초기화

	syscall_handlers[SYS_HALT] = halt_handler;
	syscall_handlers[SYS_EXIT] = exit_handler;
	syscall_handlers[SYS_FORK] = fork_handler;
	syscall_handlers[SYS_EXEC] = exec_handler;
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
/* project 3 */
/****************************************************************/
	syscall_handlers[SYS_MMAP] = mmap_handler;
/****************************************************************/

#endif /* syscall, project 2 */
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f UNUSED)
{

#ifdef USERPROG /* syscall, project 2 */

	syscall_handler_func *handler;
	int sys_num;

	sys_num = f->R.rax;
	handler = syscall_handlers[sys_num];
	if (handler == NULL)
		return;
	handler(f);

#endif /* syscall, project 2 */
}

/******************************************************/
/* userprogram, project 2 */
#ifdef USERPROG

static void
halt_handler(struct intr_frame *f)
{
	// power_off();
}

static void
exit_handler(struct intr_frame *f)
{
	struct thread *current;
	int exit_code;

	current = thread_current();
	exit_code = f->R.rdi;
	current->exit_code = exit_code;
	current->tf.R.rax = exit_code;
	thread_exit();
}

static void
fork_handler(struct intr_frame *f)
{
	char *thread_name;
	int pid;

	thread_name = (char *)f->R.rdi;
	pid = process_fork(thread_name, f);
	f->R.rax = pid;
}

static void
exec_handler(struct intr_frame *f)
{
	int fd;
	const char *fn_copy;
	const char *file_name;

	fn_copy = NULL;
	file_name = (char *)f->R.rdi;

	if (!(is_vaddr_valid(file_name) && *file_name != NULL))
		goto err;
	if ((fn_copy = palloc_get_page(PAL_USER)) == NULL)
		goto err;
	if (!strlcpy(fn_copy, file_name, strlen(file_name) + 1))
		goto err;

	/* exec에 실패할 경우에만 return value가 존재함. */
	f->R.rax = process_exec(fn_copy);
	thread_exit_by_error(-1);
err:
	if (fn_copy)
		free(fn_copy);
	f->R.rax = -1;
	return;
}

static void
wait_handler(struct intr_frame *f)
{
	int pid;
	int exit_code;

	pid = (int)f->R.rdi;
	exit_code = process_wait(pid);
	f->R.rax = exit_code;
}

static void
create_handler(struct intr_frame *f)
{
	char *file_name;
	unsigned initial_size;

	file_name = (char *)f->R.rdi;
	initial_size = (unsigned)f->R.rsi;

	if (!is_vaddr_valid(file_name) || *file_name == NULL)
	{
		thread_exit_by_error(-1);
	}

	f->R.rax = filesys_create(file_name, initial_size);
}

static void
remove_hander(struct intr_frame *f)
{
	char *file_name;

	file_name = f->R.rdi;
	f->R.rax = filesys_remove(file_name);
}

static void
read_handler(struct intr_frame *f)
{
	struct file *file;
	int fd;
	void *buffer;
	unsigned size;

	fd = f->R.rdi;
	buffer = f->R.rsi;
	size = f->R.rdx;

	if (!is_vaddr_valid(buffer) || fd == STDOUT_FILENO)
	{
		thread_exit_by_error(-1);
	}
	if(!is_writable_vaddr(buffer))
		thread_exit_by_error(-1);
	struct thread *t = thread_current();
	if ((file = get_file_by_fd(fd)) == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_read(file, buffer, size);
}

static void
open_handler(struct intr_frame *f)
{
	struct fd_table *fd_table;
	struct file *file;
	char *file_name;
	int fd;

	/* Open executable file. */
	file_name = f->R.rdi;
	if (!is_vaddr_valid(file_name) || file_name == NULL)
	{
		thread_exit_by_error(-1);
	}

	file = filesys_open(file_name);
	if (file == NULL)
	{
		f->R.rax = -1;
		return;
	}

	fd_table = get_fd_table(thread_current());
	if ((fd = find_empty_fd(fd_table)) == -1)
	{
		file_close(file);
		f->R.rax = -1;
		return;
	}
	set_fd(fd_table, fd, file);
	f->R.rax = fd;
}

static void
filesize_handler(struct intr_frame *f)
{
	struct file *file;
	int fd;

	fd = f->R.rdi;

	if ((file = get_file_by_fd(fd)) == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_length(file);
}

static void
write_handler(struct intr_frame *f)
{
	struct file *file;
	int fd;
	void *buffer;
	unsigned size;

	fd = f->R.rdi;
	buffer = f->R.rsi;
	size = f->R.rdx;

	/* 표준 출력에 작성 */
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		return;
	}

	if (!is_vaddr_valid(buffer) || fd == STDIN_FILENO)
	{
		thread_exit_by_error(-1);
	}

	if ((file = get_file_by_fd(fd)) == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_write(file, buffer, size);
}

static void
seek_handler(struct intr_frame *f)
{
	struct file *file;
	int fd;
	unsigned position;

	fd = f->R.rdi;
	position = f->R.rsi;

	if ((file = get_file_by_fd(fd)) == NULL)
	{
		f->R.rax = -1;
		return;
	}
	file_seek(file, position);
}

static void
tell_handler(struct intr_frame *f)
{
	struct file *file;
	int fd;

	fd = f->R.rdi;
	if ((file = get_file_by_fd(fd)) == NULL)
	{
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_tell(file);
}

static void
close_handler(struct intr_frame *f)
{
	struct thread *current;
	struct file *file;
	int fd;

	current = thread_current();
	fd = (int)f->R.rdi;

	if ((file = get_file_by_fd(fd)) == NULL)
	{
		thread_exit_by_error(-1);
	}
	free_fd(get_fd_table(current), fd);
	file_close(file);
}

//fd로 열린 파일의 오프셋(offset) 바이트부터 length 바이트 만큼을 프로세스의 가상주소공간의 주소 addr 에 매핑 합니다.

//전체 파일은 addr에서 시작하는 연속 가상 페이지에 매핑됩니다. 파일 길이(length)가 PGSIZE의 배수가 아닌 경우 최종 매핑된 페이지의 일부 바이트가 파일 끝을 넘어 "stick out"됩니다. page_fault가 발생하면 이 바이트를 0으로 설정하고 페이지를 디스크에 다시 쓸 때 버립니다. 

//성공하면 이 함수는 파일이 매핑된 가상 주소를 반환합니다. 실패하면 파일을 매핑하는 데 유효한 주소가 아닌 NULL을 반환해야 합니다.

//fd로 열린 파일의 길이가 0바이트인 경우 mmap에 대한 호출이 실패할 수 있습니다. addr이 page-aligned되지 않았거나, 기존 매핑된 페이지 집합(실행가능 파일이 동작하는 동안 매핑된 스택 또는 페이지를 포함)과 겹치는 경우 실패해야 합니다.

//Linux에서 addr이 NULL이면 커널은 매핑을 생성할 적절한 주소를 찾습니다. 단순화를 위해 주어진 addr에서 mmap을 시도할 수 있습니다. 
//따라서 addr이 0이면 일부 Pintos 코드는 가상 페이지 0이 매핑되지 않는다고 가정하기 때문에 실패해야 합니다. length가 0일때도 mmap은 실패해야 합니다. 마지막으로 콘솔 입력 및 출력을 나타내는 파일 설명자는 매핑할 수 없습니다.
//메모리 매핑된 페이지도 익명 페이지처럼 lazy load로 할당되어야 합니다. vm_alloc_page_with_initializer 또는 vm_alloc_page를 사용하여 페이지 개체를 만들 수 있습니다.

static void
mmap_handler(struct intr_frame *f) {
	void *addr;
	size_t length;
	int writable;
	int fd;
	off_t offset;
	struct file *file;

	addr = f->R.rdi;
	length = f->R.rsi;
	writable = f->R.rdx;
	fd = f->R.r10;
	offset = f->R.r8;

	//-----------------------------------------
	//addr 관련 예외처리
	//addr이 NULL이거나, 4바이트로 정렬되어 있지 않으면 실패
	if (pg_ofs (addr) != 0 || addr == NULL) {
		f->R.rax = NULL;
    	return;
	}
	//z커널 영역에 매핑할 때
	if (is_kernel_vaddr(addr)) {
		f->R.rax = NULL;
		return;
	}
		
	//length 관련 예외처리
	//length가 0일 때
	if(length == 0) {
		f->R.rax = NULL;
		return;
	}

	//fd관련 예외처리
	//fd값이 입출력 전용 file descriptor면 실패
	if(fd==0 || fd==1)
		f->R.rax = NULL;
    	return;
	//fd에해당하는 파일이 없거나, file길이가 0인 경우 실패
	if ((file = get_file_by_fd(fd))==NULL||file_length(file)==0)
		f->R.rax = NULL;
    	return;

	//offset관련 예외처리
	//offset이 4의 배수가 아니거나, 파일크기를 초과할 때
	if(pg_ofs (offset) != 0 || offset > file_length(file))
		f->R.rax = NULL;
		return;

	//do_mmap에서, NULL 반환한 경우 실패
	if(do_mmap(addr,length,writable,file,offset)==NULL)
		goto error;
	f->R.rax = do_mmap(addr,length,writable,file,offset);


	error:
		thread_exit_by_error(-1);
}

/***********************************************************/
/* static functions */

static struct file *
get_file_by_fd(int fd)
{
	struct fd_table *fd_table = get_fd_table(thread_current());
	if (fd < FD_MIN_SIZE || fd > FD_MAX_SIZE)
		return NULL;
	if (is_empty(fd_table, fd))
		return NULL;
	// todo 유효한 파일인지 검사, 이미 닫혔는지 아닌지, 가르키는 주소가 파일이 맞는지.
	return get_file(fd_table, fd);
}

static bool
is_vaddr_valid(void *vaddr)
{
#ifndef VM
	return is_user_vaddr(vaddr) && pml4_get_page(thread_current()->pml4, vaddr);
#else
	return is_user_vaddr(vaddr) && spt_find_page(&thread_current()->spt, vaddr);
#endif
}

static bool
is_writable_vaddr(void* vaddr){
	struct page* page = spt_find_page(&thread_current()->spt, vaddr);
	if(page == NULL)
		return false;
	return page->writable;
}

/***********************************************************/

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user(const uint8_t *uaddr)
{
	int64_t result;
	__asm __volatile(
		"movabsq $done_get, %0\n"
		"movzbq %1, %0\n"
		"done_get:\n"
		: "=&a"(result) : "m"(*uaddr));
	return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user(uint8_t *udst, uint8_t byte)
{
	int64_t error_code;
	__asm __volatile(
		"movabsq $done_put, %0\n"
		"movb %b2, %1\n"
		"done_put:\n"
		: "=&a"(error_code), "=m"(*udst) : "q"(byte));
	return error_code != -1;
}
#endif
/* userprogram, project 2 */
/******************************************************/
