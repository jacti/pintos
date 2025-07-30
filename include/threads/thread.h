#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "fixed_point.h"  // $Add/fixed_point_h
#include "threads/interrupt.h"
#include "threads/synch.h"  // $ feat/fork_handler

//$ADD/write_handler
#ifdef USERPROG
/**    @iizxcv
 *     @brief 쓰레드 구조체에 file-table 추가를 위해 헤더추가
 *     @see
 * https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c
 */
#include "userprog/file_abstract.h"
#endif
// ADD/write_handler

#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY,   /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) - 1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

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
    tid_t tid;                 /* Thread identifier. */
    enum thread_status status; /* Thread state. */
    char name[16];             /* Name (for debugging purposes). */
    int priority;              /* Priority. */

    //	$feat/timer_sleep
    /** @brief 스레드를 깨울 tick 시각 초기화 시 0*/
    uint64_t wake_tick;
    //	feat/timer_sleep

    //$Add/thread_set_nice
    /**
     * @brief 프로세스의 nice 값 (우선순위 보정 값)
     *
     * 이 값은 유저가 임의로 설정할 수 있으며,
     * 우선순위 계산 시 사용
     *	값이 클수록 우선순위 낮아짐
     * @note 유효한 범위는 -20 ~ 20이며, 기본값은 0입니다.
     */
    int nice;

    /**
     * @brief 최근 CPU 점유율을 나타내는 고정소수점 값
     *
     * 이 값은 해당 스레드가 최근에 얼마나 자주 CPU를 점유했는지를 나타내며,
     * 스케줄러의 우선순위 계산에 사용
     * 값이 클수록 우선순위가 낮아짐
     *
     * @details 1틱마다 값이 갱신됩니다.
     */
    fixed_t recent_cpu;
    // Add/thread_set_nice

    /* Shared between thread.c and synch.c. */
    struct list_elem elem; /* List element. */

    //	$우선순위 기부
    struct lock *wait_on_lock;
    struct list donor_list;
    struct list_elem donor_elem;
    //	우선순위 기부

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint64_t *pml4; /* Page map level 4 */

    /**
     * @iizxcv
     * @brief write 함수구현을 위해 putbuf사용을 위해 생성.
     * @see
     * https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c
     */

    struct File **fdt;
    size_t fd_pg_cnt;
    size_t open_file_cnt;

    // $feat/process-wait
    struct thread *parent;
    struct list childs;
    struct list_elem sibling_elem;
    struct semaphore wait_sema;
    struct semaphore fork_sema;
    struct semaphore exit_sema;
    int exit_status;
    // feat/process-wait

#endif
#ifdef VM
    /* Table for whole virtual memory owned by thread. */
    struct supplemental_page_table spt;
#endif

    /* Owned by thread.c. */
    struct intr_frame tf; /* Information for switching */
    unsigned magic;       /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

void thread_yield_r(void);

//	$feat/timer_sleep
void thread_sleep(int64_t tick);
void thread_awake(void);
//	feat/timer_sleep

// $feat/thread_priority_less
bool thread_priority_less(const struct list_elem *a, const struct list_elem *b, void *aux UNUSED);
// feat/thread_priority_less

int get_effective_priority(struct thread *);  //	$우선순위 기부
int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

// $test-temp/mlfqs
void mlfq_run_for_sec(void);
void priority_update(void);
// test-temp/mlfqs

//$feat/process-wait
bool is_user_thread(void);
// feat/process-wait

#endif /* threads/thread.h */
