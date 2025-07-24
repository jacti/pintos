#include "userprog/syscall.h"

#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>

#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "user/syscall.h"
#include "userprog/check_perm.h"
#include "userprog/file_abstract.h"
#include "userprog/gdt.h"
#include "userprog/process.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* $feat/syscall_handler */
static void halt_handler(void);
static void exit_handler(int status);
static pid_t fork_handler(const char *thread_name, struct intr_frame *f);
static int exec_handler(const char *file);
static int wait_handler(pid_t pid);
static bool create_handler(const char *file, unsigned initial_size);
static bool remove_handler(const char *file);
static int open_handler(const char *file_name);
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
        case SYS_HALT:  // syscall_num 0
            halt_handler();
            break;
        case SYS_EXIT:  // syscall_num 1
            exit_handler(f->R.rdi);
            break;
        case SYS_FORK:  // syscall_num 2
            f->R.rax = fork_handler(f->R.rdi, f);
            break;
        case SYS_EXEC:  // syscall_num 3
            f->R.rax = exec_handler(f->R.rdi);
            break;
        case SYS_WAIT:  // syscall_num 4
            f->R.rax = wait_handler(f->R.rdi);
            break;
        case SYS_CREATE:  // syscall_num 5
            f->R.rax = create_handler(f->R.rdi, f->R.rsi);
            break;
        case SYS_REMOVE:  // syscall_num 6
            f->R.rax = remove_handler(f->R.rdi);
            break;
        case SYS_OPEN:  // syscall_num 7
            f->R.rax = open_handler(f->R.rdi);
            break;
        case SYS_FILESIZE:  // syscall_num 8
            f->R.rax = filesize_handler(f->R.rdi);
            break;
        case SYS_READ:  // syscall_num 9
            f->R.rax = read_handler(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_WRITE:  // syscall_num 10
            f->R.rax = write_handler(f->R.rdi, f->R.rsi, f->R.rdx);
            break;
        case SYS_SEEK:  // syscall_num 11
            seek_handler(f->R.rdi, f->R.rsi);
            break;
        case SYS_TELL:  // syscall_num 12
            f->R.rax = tell_handler(f->R.rdi);
            break;
        case SYS_CLOSE:  // syscall_num 13
            close_handler(f->R.rdi);
            break;

        default:
            printf("system call!\n");
            printf("undefined system call number: %d\n", syscall_num);
            thread_exit();
    }
}

/**
 * @iizxcv
 * @brief fd-no로 현재 쓰레드에 매핑된 file-table에서 file 주소 가져오기
 *
 * @branch ADD/write_handler
 * @see
 * https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c
 */
static struct File *get_file_from_fd(int fd) {
    if (get_user((thread_current()->fdt + fd)) == (int64_t)-1) {
        return NULL;
    }
    return thread_current()->fdt[fd];
}

static void halt_handler(void) {
    power_off();
}

/* 현재 프로세스를 종료 */
static void exit_handler(int status) {
    struct thread *cur = thread_current();
    cur->exit_status = status;
    // process_exit();
    thread_exit();
}

/**
 * @brief 현재 프로세스를 복사하여 새 프로세스를 생성합니다.
 *
 * @branch feat/fork_handler
 * @param thread_name 새 프로세스의 이름
 * @param f 현재 프로세스의 인터럽트 프레임
 * @return 성공 시 자식 프로세스의 PID, 실패 시 TID_ERROR
 * 이 함수는 현재 실행 중인 프로세스의 메모리와 상태를 복사하여
 * 새로운 자식 프로세스를 생성합니다. 부모 프로세스는 자식 프로세스의
 * 생성이 완료될 때까지 대기하며, 자식 프로세스는 부모와 동일한
 * 메모리 공간을 가지게 됩니다.
 * @see process_fork()
 */
static pid_t fork_handler(const char *thread_name, struct intr_frame *f) {
    if (is_user_accesable(thread_name, 0, P_USER | IS_STR)) {
        return process_fork(thread_name, f);
    } else {
        exit_handler(-1);
    }
}

/* 사용자 프로그램 실행 */
static int exec_handler(const char *file) {
    if (is_user_accesable(file, 0, P_USER)) {
        char *fn_copy = palloc_get_page(0);
        if (fn_copy) {
            strlcpy(fn_copy, file, PGSIZE);
            return process_exec(fn_copy);
        }
    }
    exit_handler(-1);
}

/* 자식 프로세스가 종료될 때까지 대기 */
static int wait_handler(pid_t pid) {
    return process_wait(pid);
}

/* 파일 생성 */
static bool create_handler(const char *file, unsigned initial_size) {
    if (is_user_accesable(file, 0, P_USER | IS_STR)) {
        return filesys_create(file, initial_size);
    }
    exit_handler(-1);
    NOT_REACHED();
    return false;
}

/* 파일 삭제 */
static bool remove_handler(const char *file) {
    if (is_user_accesable(file, 0, P_USER | IS_STR)) {
        return filesys_remove(file);
    }
    exit_handler(-1);
    NOT_REACHED();
    return false;
}

/* 파일 열기 */
static int open_handler(const char *file_name) {
    if (file_name && is_user_accesable(file_name, 0, P_USER | IS_STR)) {
        struct File *file = open_file(file_name);
        if (file == NULL) {
            return -1;
        }
        return set_fd(file);
    }
    exit_handler(-1);
}

/* 파일 크기 반환 */
static int filesize_handler(int fd) {
    int result = -1;
    struct File *get_file = get_file_from_fd(fd);
    if (get_file) {
        result = get_file_size(get_file);
    }
    if (result == -1) {
        exit_handler(-1);
    }
    return result;
}

/* 파일 또는 STDIN에서 읽기 */
static int read_handler(int fd, void *buffer, unsigned size) {
    struct File *get_file = get_file_from_fd(fd);
    int result = -1;
    if (get_file != NULL && is_user_accesable(buffer, size, P_USER | P_WRITE)) {
        result = read_file(get_file, buffer, size);
    }
    if (result == -1) {
        exit_handler(-1);
    }
    return result;
}

/* 파일 또는 STDOUT으로 쓰기 */
/**
 * @brief 사용자 파일 디스크립터에 버퍼 내용을 씁니다.
 *
 * @branch ADD/write_handler
 *
 * @iizxcv
 * @jacti
 * @param fd    파일 디스크립터 (0: stdin, 1: stdout, >1: 파일)
 * @param buffer   쓰기할 데이터가 있는 사용자 버퍼의 시작 주소
 * @param size  쓰기할 데이터 크기(바이트 단위)
 * @return 작성한 바이트 수(size) 또는 접근 오류 시 -1
 * @see
 * https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c
 *
 * is_user_accesable을 통해 사용자 버퍼 접근을 검증한 후,
 * fd가 stdin인 경우 경고 메시지를 출력합니다.
 * fd가 stdout인 경우 putbuf를 이용해 화면에 출력하며,
 * 그 외(fd > stdout)의 경우 파일 객체를 fd로부터 가져와 file_write를 호출합니다.
 */
static int write_handler(int fd, const void *buffer,
                         unsigned size) {  // write의 목적은 buf를 fd에 쓰기해주는 함수

    struct File *get_file = get_file_from_fd(fd);
    int result = -1;
    if (get_file != NULL && is_user_accesable(buffer, size, P_USER)) {
        result = write_file(get_file, buffer, size);
    }
    if (result == -1) {
        exit_handler(-1);
    }
    return result;
}

/* 파일 커서 위치 이동 */
static void seek_handler(int fd, unsigned position) {
    struct File *get_file = get_file_from_fd(fd);
    if (get_file == NULL || seek_file(get_file, position) == -1) {
        exit_handler(-1);
    }
}

/* 파일 커서 위치 반환 */
static unsigned tell_handler(int fd) {
    struct File *get_file = get_file_from_fd(fd);
    int64_t result;
    if (get_file == NULL || (result = tell_handler(get_file)) == -1) {
        exit_handler(-1);
    }
    return (unsigned)result;
}

/* 파일 닫기 */
static void close_handler(int fd) {
    struct File *get_file = get_file_from_fd(fd);
    if (get_file == NULL || remove_fd(fd) == -1) {
        exit_handler(-1);
        NOT_REACHED();
    }
}
