
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


/************************************************************************/
/* syscall, project 2  */
#ifdef USERPROG 

#include "filesys/filesys.h"
#include "filesys/file.h"
#include "string.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "vm/vm.h"

typedef void 
syscall_handler_func(struct intr_frame *);

static syscall_handler_func 
*syscall_handlers[25]; // 25는 총 syscall 갯수;

#define get_fd_table(thread) (thread->fd_table)

static struct file* 
get_file_by_fd(int fd);

bool is_vaddr_valid(void*);
bool is_vaddr_valid_with_write(void*, bool);

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
static void
mmap_handler(struct intr_frame* f);
static void
munmap_handler(struct intr_frame* f);

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
	
	
#ifdef USERPROG /* syscall, project 2 */

	// /* 자 지금부터 열려있는 모든 파일은 커널이 관리합니다. */
	memset(syscall_handlers, 0 , sizeof(syscall_handlers)); // sycall 함수배열 초기화

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
	syscall_handlers[SYS_MMAP] = mmap_handler;
	syscall_handlers[SYS_MUNMAP] = munmap_handler;

#endif /* syscall, project 2 */
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

#ifdef USERPROG /* syscall, project 2 */

	syscall_handler_func *handler;
	int sys_num;
	
	sys_num = f->R.rax;
	handler = syscall_handlers[sys_num];
	if(handler == NULL)
		return;
	handler(f);

#endif /* syscall, project 2 */
}


/******************************************************/
/* userprogram, project 2 */
#ifdef USERPROG

static void
halt_handler(struct intr_frame *f){
	// power_off();
}

static void 
exit_handler(struct intr_frame* f){
	struct thread *current;
	int exit_code;

	current = thread_current();
	exit_code = f->R.rdi;
	current->exit_code = exit_code;
	current->tf.R.rax = exit_code;
	thread_exit();
}

static void 
fork_handler(struct intr_frame* f){
 	char *thread_name;
	int pid;

	thread_name = (char *)f->R.rdi;
	pid = process_fork(thread_name, f);
	f->R.rax = pid;
}

static void
exec_handler(struct intr_frame* f)
{ 	
	int fd;
	const char *fn_copy;
	const char* file_name; 
	
	file_name = (char*)f->R.rdi;
	if((fn_copy =  palloc_get_page(PAL_USER)) == NULL){
		thread_current()->exit_code = -1;
		thread_exit();
	}

	if(!is_vaddr_valid(file_name) || *file_name == NULL){
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}
	strlcpy(fn_copy, file_name, strlen(file_name) + 1);

	/* exec에 실패할 경우에만 return value가 존재함. */
	f->R.rax = process_exec(fn_copy);
}

static void 
wait_handler(struct intr_frame* f)
{	
	int pid;
	int exit_code;

 	pid = (int)f->R.rdi;
	exit_code = process_wait(pid);
	f->R.rax = exit_code;
}

static void
create_handler(struct intr_frame* f)
{
	char* file_name = (char*)f->R.rdi;
	unsigned initial_size = (unsigned)f->R.rsi;


	if(!is_vaddr_valid(file_name) || *file_name == NULL){
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}

	f->R.rax = filesys_create(file_name, initial_size);
}

static void
remove_hander(struct intr_frame* f)
{
	char *file_name;

	file_name = f->R.rdi;
	f->R.rax = filesys_remove(file_name);
}

static void
read_handler(struct intr_frame* f)
{
	struct file* file;
	int fd; 
	void *buffer;
	unsigned size;
	
	fd = f->R.rdi;
	buffer = f->R.rsi;
	size = f->R.rdx;

	if(!is_vaddr_valid_with_write(buffer, true) ||  fd == STDOUT_FILENO){
		thread_current()->exit_code = -1;
		thread_exit(); 
		NOT_REACHED();
	}
	struct thread* t = thread_current();
	if((file = get_file_by_fd(fd))== NULL){
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_read(file, buffer, size);
}

static void 
open_handler(struct intr_frame *f)
{
	struct fd_table* fd_table;
	struct file *file;
	char* file_name;
	int fd; 

	/* Open executable file. */
	file_name = f->R.rdi;
	if(!is_vaddr_valid(file_name) || file_name == NULL){
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}

	file = filesys_open (file_name);
	if (file == NULL) {
		f->R.rax = -1;
		return;
	}

	fd_table = get_fd_table(thread_current());
	if( (fd = find_empty_fd(fd_table)) == -1 ){
		file_close(file);
		f->R.rax = -1;
		return;
	}
	set_fd(fd_table,fd,file);
	f->R.rax = fd;
}

static void 
filesize_handler(struct intr_frame* f)
{	
	struct file *file;
	int fd;

	fd = f->R.rdi;

	if((file = get_file_by_fd(fd)) == NULL){
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_length(file);
}

static void  
write_handler(struct intr_frame* f)
{	
	struct file *file;
	int fd;
	void* buffer;
	unsigned size;
	
	fd = f->R.rdi;
	buffer = f->R.rsi;
	size = f->R.rdx;
	
	/* 표준 출력에 작성 */
	if(fd == STDOUT_FILENO)	{
		putbuf(buffer,size);
		return;
	}

	if( !is_vaddr_valid_with_write(buffer, true) || fd == STDIN_FILENO) {
		thread_current()->exit_code = -1;
		thread_exit();
		NOT_REACHED();
	}

	if((file = get_file_by_fd(fd)) == NULL){
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_write(file,buffer,size);
}

static void
seek_handler(struct intr_frame* f)
{
	struct file *file;
	int fd; 
	unsigned position;

	fd = f->R.rdi;
	position = f->R.rsi;

	if((file = get_file_by_fd(fd)) == NULL){
		f->R.rax = -1;
		return;
	}
	file_seek(file,position);
}

static void
tell_handler(struct intr_frame* f)
{
	struct file *file;
	int fd;

	fd = f->R.rdi;
	if((file = get_file_by_fd(fd)) == NULL){
		f->R.rax = -1;
		return;
	}
	f->R.rax = file_tell(file);
}

static void
close_handler(struct intr_frame* f)
{
	struct thread* current;
	struct file *file;
	int fd;

	current = thread_current();
	fd = (int)f->R.rdi;

	if((file = get_file_by_fd(fd)) == NULL){
		current->exit_code = -1;
		thread_exit();
	}
	free_fd(get_fd_table(current),fd);
	file_close(file);
}

/***********************************************************/
/* static functions */

static struct file* 
get_file_by_fd(int fd)
{
	struct fd_table *fd_table = get_fd_table(thread_current());
	if(fd < FD_MIN_SIZE || fd > FD_MAX_SIZE)
		return NULL;
	if(is_empty(fd_table,fd))
		return NULL;
	//todo 유효한 파일인지 검사, 이미 닫혔는지 아닌지, 가르키는 주소가 파일이 맞는지.
	return get_file(fd_table,fd);
}

bool is_vaddr_valid(void *vaddr) {
		return !(is_kernel_vaddr(vaddr) 
		|| spt_find_page(&thread_current()->spt, vaddr) == NULL
		|| vaddr == NULL);
}

bool is_vaddr_valid_with_write(void* vaddr, bool write)
{
	if (vaddr == NULL || is_kernel_vaddr(vaddr))
		return false;

	struct page *page = spt_find_page(&thread_current()->spt, vaddr);

	if (page == NULL || page->writable != write)
		return false;
	return true;
}

/***********************************************************/

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t
get_user (const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile (
    "movabsq $done_get, %0\n"
    "movzbq %1, %0\n"
    "done_get:\n"
    : "=&a" (result) : "m" (*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile (
    "movabsq $done_put, %0\n"
    "movb %b2, %1\n"
    "done_put:\n"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
    return error_code != -1;
}
#endif
/* userprogram, project 2 */
/******************************************************/

/******************************************************/
/* vm, project 3 */
/*
	fd로 열린 파일의 오프셋(offset) 바이트부터 length 바이트 만큼을 프로세스의 가상주소공간의 주소 addr 에 매핑 합니다.
	전체 파일은 addr에서 시작하는 연속 가상 페이지에 매핑됩니다. 
	파일 길이(length)가 PGSIZE의 배수가 아닌 경우 -> 최종 매핑된 페이지의 일부 바이트가 파일 끝을 넘어 "stick out"됩니다. 
		page_fault가 발생하면 이 바이트(stick out된)를 0으로 설정하고 페이지를 디스크에 다시 쓸 때 버립니다. 
			성공하면 이 함수는 파일이 매핑된 가상 주소를 반환합니다. 
			실패하면 파일을 매핑하는 데 유효한 주소가 아닌 NULL을 반환해야 합니다.

	실패해야 하는 경우
		- fd로 열린 파일의 길이가 0바이트인 경우
		- addr이 page-aligned되지 않았거나
		- 기존 매핑된 페이지 집합(실행가능 파일이 동작하는 동안 매핑된 스택 또는 페이지를 포함)과 겹치는 경우 
		- addr == NULL || length == 0
		- fd == (stdin || stdout)

	메모리 매핑된 페이지도 익명 페이지처럼 lazy load로 할당되어야 합니다. 
	vm_alloc_page_with_initializer 또는 vm_alloc_page를 사용하여 페이지 개체를 만들 수 있습니다.

	둘 이상의 프로세스가 동일한 파일을 매핑하는 경우 일관된 데이터를 볼 필요가 없습니다. 
	Unix는 두 매핑이 동일한 물리적 페이지를 공유하도록 합니다. 
	그리고 mmap system call에는 클라이언트가 페이지를 share, private(즉, copy-on-write) 여부를 결정할 수 있도록 하는 인수도 있습니다.
*/
static void
mmap_handler(struct intr_frame* f) {
	void* addr = (void *)f->R.rdi;
	size_t length = (size_t)f->R.rsi;
	bool writable = (bool)f->R.rdx;
	int fd = (int)f->R.r10;
	off_t offset = (off_t)f->R.r8;
	if (!is_valid_mmap(addr, length, writable, fd, offset)) {
		f->R.rax = (void *)NULL;
		return;
	}
	
	struct file *file =get_file_by_fd(fd);
	size_t actual_length = file_length(file);
	length = length > actual_length ? actual_length : length;
	if (actual_length == NULL)
		thread_kill();
	
	struct file *reopened = file_reopen(file);
		
	if (writable) 
		file_allow_write(reopened);

	do_mmap(addr, length, writable, reopened, offset);

	f->R.rax = addr;
}
/*
	지정된 주소 범위 addr에 대한 매핑을 해제합니다.
	지정된 주소는 => 아직 매핑 해제되지 않은 동일한 프로세서의 mmap에 대한 이전 호출에서 반환된 가상 주소여야 합니다.

	종료를 통하거나 다른 방법을 통해 프로세스가 exit되면 모든 매핑이 암시적으로 매핑 해제됩니다. 
	암시적이든 명시적이든 매핑이 매핑 해제되면 프로세스에서 쓴 모든 페이지는 파일에 다시 기록되며 기록되지 않은 페이지는 기록되지 않아야 합니다. 
	그런 다음 해당 페이지는 프로세스의 가상 페이지 목록에서 제거됩니다.

	파일을 닫거나 제거해도 해당 매핑이 매핑 해제되지 않습니다. 
	생성된 매핑은 Unix 규칙에 따라 munmap이 호출되거나 프로세스가 종료될 때까지 유효합니다. 
	자세한 내용은  Removing an Open File를 참조하세요. 
	각 매핑에 대해 파일에 대한 개별적이고 독립적인 참조를 얻으려면 file_reopen 함수를 사용해야 합니다.

	둘 이상의 프로세스가 동일한 파일을 매핑하는 경우 일관된 데이터를 볼 필요가 없습니다. 
	Unix는 두 매핑이 동일한 물리적 페이지를 공유하도록 합니다. 
	그리고 mmap system call에는 클라이언트가 페이지를 share, private(즉, copy-on-write) 여부를 결정할 수 있도록 하는 인수도 있습니다.
*/
static void
munmap_handler(struct intr_frame* f) {
	void* addr = (void *)f->R.rdi;
}

/* vm, project 3 */
/******************************************************/