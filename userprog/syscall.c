#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* $feat/syscall_handler */
static void halt_handler(void);
static void exit_handler(int status);
static tid_t fork_handler(struct intr_frame *f);
static int exec_handler(const char *file);
static int wait_handler(tid_t pid);
static bool create_handler(const char *file, unsigned initial_size);
static bool remove_handler(const char *file);
static int open_handler(const char *file);
static int filesize_handler(int fd);
static int read_handler(int fd, void *buffer, unsigned size);
static int write_handler(int fd, const void *buffer, unsigned size);
static void seek_handler(int fd, unsigned position);
static unsigned tell_handler(int fd);
static void close_handler(int fd);
/* feat/syscall_handler */

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

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kerneål
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
    // TODO: Your implementation goes here.
    int syscall_num = f->R.rax;
	
	switch (syscall_num) {
        case SYS_HALT: // syscall_num 0 
	        halt_handler();
	        break;
	    case SYS_EXIT: // syscall_num 1
		    exit_handler(f->R.rdi);
		    break;
		case SYS_FORK: // syscall_num 2 
		    f->R.rax = fork_handler(f);
    	    break;
		case SYS_EXEC: // syscall_num 3 
			f->R.rax = exec_handler(f->R.rdi);
		    break;
		case SYS_WAIT: // syscall_num 4 
			f->R.rax = wait_handler(f->R.rdi);
		    break;
		case SYS_CREATE: // syscall_num 5 
			f->R.rax = create_handler(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE: // syscall_num 6 
			f->R.rax = remove_handler(f->R.rdi);
		    break;
		case SYS_OPEN: // syscall_num 7
            f->R.rax = open_handler(f->R.rdi);
            break;
        case SYS_FILESIZE: // syscall_num 8
            f->R.rax = filesize_handler(f->R.rdi);
            break;
        case SYS_READ: // syscall_num 9
	        f->R.rax = read_handler(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE: // syscall_num 10 
            f->R.rax = write_handler(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK: // syscall_num 11 
            seek_handler(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL: // syscall_num 12
            f->R.rax = tell_handler(f->R.rdi);
            break;
        case SYS_CLOSE: // syscall_num 13 
            close_handler(f->R.rdi); 
            break;
		    
        default:
            printf("system call!\n");
            printf("undefined system call number: %d\n", syscall_num);
            thread_exit();
	}
}

static
void halt_handler(void) {
    power_off();
}

/* 현재 프로세스를 종료 */
static
void exit_handler(int status) {
    // 현재 쓰레드 종료 + exit status 저장
    struct thread *cur = thread_current();
    cur->status = status;
    printf("%s: exit(%d)\n", cur->name, status);
    thread_exit();
}

/* 현재 프로세스를 복사하여 새 프로세스 생성 */
static
tid_t fork_handler(struct intr_frame *f) {
    // 부모의 메모리와 상태를 복사해 자식 생성
    return -1; // TODO: 구현 필요
}

/* 사용자 프로그램 실행 */
static
int exec_handler(const char *file) {
    // 유저 주소 확인 -> 문자열 복사 -> process_exec 호출
    return -1; // TODO: 구현 필요
}

/* 자식 프로세스가 종료될 때까지 대기 */
static
int wait_handler(tid_t pid) {
    return -1; // TODO: 구현 필요
}

/* 파일 생성 */
static
bool create_handler(const char *file, unsigned initial_size) {
    return false; // TODO: filesys_create 호출
}

/* 파일 삭제 */
static
bool remove_handler(const char *file) {
    return false; // TODO: filesys_remove 호출
}

/* 파일 열기 */
static
int open_handler(const char *file) {
    return -1; // TODO: file 객체 반환 -> fd_table에 저장
}

/* 파일 크기 반환 */
static
int filesize_handler(int fd) {
    return 0; // TODO: fd로 file 찾아서 길이 반환
}

/* 파일 또는 STDIN에서 읽기 */
static
int read_handler(int fd, void *buffer, unsigned size) {
    return -1; // TODO: 유저 주소 검증 -> file_read
}

/* 파일 또는 STDOUT으로 쓰기 */
static
int write_handler(int fd, const void *buffer, unsigned size) {
    return -1; // TODO: 유저 주소 검증 -> file_write 또는 putbuf
}

/* 파일 커서 위치 이동 */
static
void seek_handler(int fd, unsigned position) {
    // TODO: file_seek 호출
}

/* 파일 커서 위치 반환 */
static
unsigned tell_handler(int fd) {
    return 0; // TODO: file_tell 호출
}

/* 파일 닫기 */
static
void close_handler(int fd) {
    // TODO: file_close -> fd_table에서 제거
}