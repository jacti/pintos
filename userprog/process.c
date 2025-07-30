#include "userprog/process.h"

#include <debug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "threads/flags.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "userprog/file_descriptor.h"
#include "userprog/process_impl.h"
#include "userprog/tss.h"
#ifdef VM
#include "vm/vm.h"
#endif

// static 함수 선정의
static void initd(void *f_name);
static void __do_fork(void *);

/**
 * @brief fork 작업에 필요한 데이터를 전달하기 위한 구조체
 * @branch feat/fork_handler
 * @details 부모 프로세스의 정보와 인터럽트 프레임을 자식 프로세스 생성 함수에 전달하기 위해
 * 사용됩니다.
 */
struct fork_data {
    struct thread *parent;        /**< 부모 스레드 포인터 */
    struct intr_frame *parent_if; /**< 부모의 인터럽트 프레임 포인터 */
};

struct init_data {
    struct thread *parent;
    const char *file_name;
};

/* General process initializer for initd and other process. */
static void process_init(void) {
    // struct thread *current = thread_current();
}

/* Starts the first userland program, called "initd", loaded from FILE_NAME.
 * The new thread may be scheduled (and may even exit)
 * before process_create_initd() returns. Returns the initd's
 * thread id, or TID_ERROR if the thread cannot be created.
 * Notice that THIS SHOULD BE CALLED ONCE. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;
    struct init_data init_data;
    struct thread *main_thread = thread_current();

    /* Make a copy of FILE_NAME.
     * Otherwise there's a race between the caller and load(). */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);
    init_data.file_name = fn_copy;
    init_data.parent = main_thread;

    char *saveptr = NULL;
    char *file_cut = strtok_r((char *)file_name, " ", &saveptr);

    /* Create a new thread to execute FILE_NAME. */
    tid = thread_create(file_cut, PRI_DEFAULT, initd, &init_data);
    if (tid == TID_ERROR)
        palloc_free_page(fn_copy);
    else {
        sema_down(&main_thread->fork_sema);
    }
    return tid;
}

/* A thread function that launches first user process. */
static void initd(void *init_data_) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif
    process_init();
    struct init_data *init_data = (struct init_data *)init_data_;
    struct thread *t = thread_current();
    const char *file_name = init_data->file_name;
    t->parent = init_data->parent;
    list_push_back(&t->parent->childs, &t->sibling_elem);
    sema_up(&t->parent->fork_sema);
    if (process_exec(file_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

/* Clones the current process as `name`. Returns the new process's thread id, or
 * TID_ERROR if the thread cannot be created. */
/**
 * @brief 현재 프로세스를 복제하여 새로운 프로세스를 생성합니다.
 * @branch feat/fork_handler
 * @param name 새 프로세스의 이름
 * @param if_ 부모 프로세스의 인터럽트 프레임
 * @return 성공 시 자식 프로세스의 TID, 실패 시 TID_ERROR
 * 이 함수는 현재 실행 중인 프로세스의 메모리와 상태를 복사하여
 * 새로운 자식 프로세스를 생성합니다. 부모 프로세스는 자식 프로세스의
 * 생성이 완료될 때까지 세마포어를 통해 대기
 * @details
 * 1. fork_data 구조체를 할당하여 부모 정보와 인터럽트 프레임을 저장
 * 2. thread_create를 통해 __do_fork 함수를 실행할 새 스레드 생성
 * 3. 세마포어를 통해 자식 프로세스 생성 완료 대기
 * 4. 자식 프로세스의 TID 반환
 * @note 메모리 할당 실패 시 TID_ERROR를 반환합니다.
 * @see __do_fork()
 */
tid_t process_fork(const char *name, struct intr_frame *if_) {
    /* Clone current thread to new thread.*/
    struct thread *curr = thread_current();

    struct fork_data *fork_data = malloc(sizeof(struct fork_data));
    fork_data->parent = curr;
    fork_data->parent_if = if_;

    tid_t tid = thread_create(name, PRI_DEFAULT, __do_fork, fork_data);
    if (tid == TID_ERROR) {
        free(fork_data);
        return TID_ERROR;
    }

    sema_down(&curr->fork_sema);
    if (list_empty(&curr->childs)) {
        return -1;
    }
    struct thread *t = list_entry(list_back(&curr->childs), struct thread, sibling_elem);
    if (t->exit_status == -1) {
        return -1;
    }
    return tid;
}

/* A thread function that copies parent's execution context.
 * Hint) parent->tf does not hold the userland context of the process.
 *       That is, you are required to pass second argument of process_fork to
 *       this function. */
/**
 * @brief 부모 프로세스의 실행 컨텍스트를 복사하여 자식 프로세스를 생성합니다.
 *
 * @branch feat/fork_handler
 * @param aux fork_data 구조체 포인터 (부모 정보와 인터럽트 프레임 포함)
 *
 * 이 함수는 새로 생성된 스레드에서 실행되며, 부모 프로세스의 메모리와
 * 상태를 복사하여 자식 프로세스를 완전히 생성합니다.
 *
 * @details
 * 1. 부모-자식 관계 설정 (parent, childs 리스트)
 * 2. 부모의 인터럽트 프레임을 자식에게 복사
 * 3. 페이지 테이블 생성 및 메모리 복사
 * 4. 파일 디스크립터 복사 (TODO)
 * 5. 프로세스 초기화
 * 6. 부모에게 완료 신호 전송
 * 7. 자식 프로세스 실행 시작
 *
 * @note 부모 프로세스는 이 함수가 완료될 때까지 대기합니다.
 * @see process_fork()
 */
static void __do_fork(void *aux) {
    struct intr_frame if_;
    struct fork_data *fork_data = (struct fork_data *)aux;
    struct thread *parent = fork_data->parent;
    struct thread *current = thread_current();

    struct intr_frame *parent_if = fork_data->parent_if;
    bool succ = true;

    /* 부모-자식 관계 설정 */
    current->parent = parent;
    list_push_back(&parent->childs, &current->sibling_elem);

    /* 1. Read the cpu context to local stack. */
    memcpy(&if_, parent_if, sizeof(struct intr_frame));

    /* 2. Duplicate PT */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);

#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (parent->pml4 && !pml4_for_each(parent->pml4, duplicate_pte, parent)) {
        goto error;
    }
#endif

    /* TODO: Your code goes here.
     * TODO: Hint) To duplicate the file object, use `file_duplicate`
     * TODO:       in include/filesys/file.h. Note that parent should not return
     * TODO:       from the fork() until this function successfully duplicates
     * TODO:       the resources of parent.*/
    // 부모의 파일 디스크립터 테이블 복사
    if (fork_fdt(parent, current) == -1) {
        goto error;
    }

    process_init();

    free(fork_data);
    if_.R.rax = 0;  // 자식 rax 초기화

    /* Finally, switch to the newly created process. */
    if (succ) {
        sema_up(&(current->parent->fork_sema));
        do_iret(&if_);
    }
error:
    free(fork_data);
    current->exit_status = -1;
    sema_up(&(current->parent->fork_sema));
    thread_exit();
}

/* Switch the current execution context to the f_name.
 * Returns -1 on fail. */
int process_exec(void *f_name) {
    //  $feat/arg-parse
    char *args;
    char *file_name = strtok_r(f_name, " ", &args);
    //  feat/arg-parse
    bool success;

    /* We cannot use the intr_frame in t3e thread structure.
     * This is because when current thread rescheduled,
     * it stores the execution information to the member. */
    struct intr_frame _if;
    _if.ds = _if.es = _if.ss = SEL_UDSEG;
    _if.cs = SEL_UCSEG;
    _if.eflags = FLAG_IF | FLAG_MBS;

    /* We first kill the current context */
    process_cleanup();

    /* And then load the binary */
    success = load(file_name, args, &_if);
    /* If load failed, quit. */
    palloc_free_page(f_name);
    if (!success) {
        thread_current()->exit_status = -1;
        thread_exit();
    }

    /* Start switched process. */
    do_iret(&_if);
    NOT_REACHED();
}

/* Waits for thread TID to die and returns its exit status.  If
 * it was terminated by the kernel (i.e. killed due to an
 * exception), returns -1.  If TID is invalid or if it was not a
 * child of the calling process, or if process_wait() has already
 * been successfully called for the given TID, returns -1
 * immediately, without waiting.
 *
 * This function will be implemented in problem 2-2.  For now, it
 * does nothing. */
int process_wait(tid_t child_tid) {
    int child_exit_status = -1;
    struct thread *curr = thread_current();
    for (struct list_elem *e = list_begin(&curr->childs); e != list_end(&curr->childs);
         e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, sibling_elem);
        if (t && t->tid == child_tid) {
            // sema_down(&t->exit_sema);
            sema_down(&t->wait_sema);
            barrier();
            child_exit_status = t->exit_status;
            list_remove(&t->sibling_elem);
            sema_up(&t->exit_sema);
            break;
        }
    }
    return child_exit_status;
}

/* Exit the process. This function is called by thread_exit (). */
void process_exit(void) {
    struct thread *cur = thread_current();
    clear_fdt(cur);
    bool is_user = is_user_thread();
    process_cleanup();
    if (cur->parent != NULL) {
        if (is_user) {
            printf("%s: exit(%d)\n", cur->name, cur->exit_status);
        }
        if (list_back(&cur->parent->childs) == &(cur->sibling_elem) &&
            !list_empty(&cur->parent->fork_sema.waiters)) {
            sema_up(&cur->parent->fork_sema);
        }
        sema_up(&cur->wait_sema);
        sema_down(&cur->exit_sema);
    }
}

/* Sets up the CPU for running user code in the nest thread.
 * This function is called on every context switch. */
void process_activate(struct thread *next) {
    /* Activate thread's page tables. */
    pml4_activate(next->pml4);

    /* Set thread's kernel stack for use in processing interrupts. */
    tss_update(next);
}
