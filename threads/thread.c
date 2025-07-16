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
#include "thread.h"
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
static struct list sleep_list; //	$feat/timer_sleep

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

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

//$Add/MLFQ_thread_elem
static fixed_t load_avg; /** @brief 전역변수: 부하 평균량  */
//Add/MLFQ_thread_elem

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule (void);
static tid_t allocate_tid (void);

//$test-temp/mlfqs-iizxcv
static void threads_recent_update(void);
static int calaculate_priority(fixed_t recent_cpu, int nice);
static size_t get_count_threads(void);
static void load_avg_update(void);
//test-temp/mlfqs-iizxcv

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

	list_init (&sleep_list);		//	$feat/timer_sleep
	load_avg = 0;

	/* Set up a thread structure for the running thread. */
	initial_thread = running_thread ();
	init_thread (initial_thread, "main", PRI_DEFAULT);
	initial_thread->status = THREAD_RUNNING;
	initial_thread->tid = allocate_tid ();
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
	else
		kernel_ticks++;

	/* Enforce preemption. */
	if (++thread_ticks >= TIME_SLICE)
	{
		intr_yield_on_return ();
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

	/* Call the kernel_thread if it scheduled.
	 * Note) rdi is 1st argument, and rsi is 2nd argument. */
	t->tf.rip = (uintptr_t) kernel_thread;
	t->tf.R.rdi = (uint64_t) function;
	t->tf.R.rsi = (uint64_t) aux;
	t->tf.ds = SEL_KDSEG;
	t->tf.es = SEL_KDSEG;
	t->tf.ss = SEL_KDSEG;
	t->tf.cs = SEL_KCSEG;
	t->tf.eflags = FLAG_IF;

	/* Add to run queue. */
	thread_unblock (t);
	
	thread_yield();  // 스레드가 생성될 때, 생성된 스레드의 우선 순위가 높을 때 양보

	return tid;
}

/**
 * @brief 두 스레드의 우선순위를 비교하여, 리스트에서 우선순위 높은 스레드가 먼저 오도록 하기 위한 비교 함수
 * @details 이 함수는 list_insert_ordered() 사용되어 ready_list와 같은 스레드 리스트를 우선순위(priority)가 높은 순서로 정렬하는 데 사용
 * @param a a 리스트에 들어 있는 첫 번째 요소 (struct list_elem *)
 * @param b b 리스트에 들어 있는 두 번째 요소 (struct list_elem *)
 * @param aux 추가 전달 데이터 (사용되지 않음, NULL이 전달됨)
 * @return 첫 번째 스레드의 우선순위가 더 높으면 true, 두 번째 스레드의 우선순위가 더 높으면 false 
 */
bool
thread_priority_less (const struct list_elem *a, const struct list_elem *b, void *aux UNUSED) {
	struct thread *t_a = list_entry(a, struct thread, elem);
	struct thread *t_b = list_entry(b, struct thread, elem);
	return get_effective_priority(t_a) > get_effective_priority(t_b);
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
	list_insert_ordered(&ready_list, &t->elem, thread_priority_less, NULL);
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
		list_insert_ordered(&ready_list, &curr->elem, thread_priority_less, NULL);
	do_schedule (THREAD_READY);
	intr_set_level (old_level);
}

/**
 * @brief 스레드 리스트 요소를 깨울 시각(wake_tick) 기준으로 비교하는 함수
 *
 * 스케줄러의 Sleeping 스레드 목록에서, 두 리스트 엘리먼트가 가리키는
 * struct thread 구조체에 정의된 wake_tick 값을 비교하여 정렬 순서를 결정할 때 사용됩니다.
 *
 * @param a 첫 번째 리스트 엘리먼트 (struct thread의 elem)
 * @param b 두 번째 리스트 엘리먼트 (struct thread의 elem)
 * @param aux UNUSED 매개변수 (사용되지 않음)
 * @return a가 가리키는 스레드의 wake_tick이 b보다 작으면 true, 그렇지 않으면 false
 */
static bool
thread_wake_less (const struct list_elem *a,
                  const struct list_elem *b,
                  void *aux UNUSED) {
    struct thread *t_a = list_entry(a, struct thread, elem);
    struct thread *t_b = list_entry(b, struct thread, elem);
    return t_a->wake_tick < t_b->wake_tick;
}


/**
 * @brief tick 시각까지 thread를 sleep 상태로 만든다
 * 
 * @branch feat/timer_sleep
 * 
 * @warning tick 시간 동안 sleep 하는 것이 아닌, tick 시각 까지 sleep 한다
 * @param ticks thread가 sleep할 시각
 * @return void
 * @see https://www.notion.so/jactio/timer_sleep-22dc9595474e8016bb2ef8290608ba21?source=copy_link
 */
void thread_sleep(int64_t tick)
{
	enum intr_level old_level = intr_disable ();
	int64_t cur = timer_ticks ();
	struct thread *t = thread_current();
	if(t != idle && cur < tick){
		t->wake_tick = tick;
		list_insert_ordered(&sleep_list, &t->elem, thread_wake_less, NULL);
		thread_block();
	}
	intr_set_level(old_level);
}

/**
 * @brief Sleeping 상태의 스레드 중에서 지정된 시각에 도달한 스레드를 깨우는 함수
 *
 * sleep_list에 등록된 각 스레드의 wake_tick 값을 확인하여,
 * 현재 타이머 틱(cur)이 wake_tick 이상인 스레드를 목록에서 제거하고
 * thread_unblock()을 호출하여 Ready 상태로 전환합니다.
 * sleep_list가 비어 있으면 즉시 반환합니다.
 * 
 * @branch feat/timer_sleep
 * 
 */
void
thread_awake (void) {

    int64_t cur = timer_ticks ();
    struct thread *t;

    /* wake_tick이 지난 스레드를 순차적으로 깨움 */
	while(!list_empty (&sleep_list)) {
		t = list_entry(list_front(&sleep_list), struct thread, elem);
		if (t->wake_tick > cur)
            break;
		list_pop_front(&sleep_list);
		if(thread_mlfqs){
			t->priority = calaculate_priority(t->recent_cpu, t->nice);
		}
		thread_unblock(t);
	}
}


/* Sets the current thread's priority to NEW_PRIORITY. */
/**
 * @brief 현재 스레드의 우선순위를 새로운 값으로 설정하고, 우선순위 기부 상황을 재조정하는 함수
 * 
 * 현재 스레드의 우선순위가 변경될 때, 기존에 우선순위를 기부받고 있던 donor_list를 검사하여
 * 더 이상 기부가 필요하지 않은 스레드들을 제거합니다.
 * 
 * 동작 과정:
 * 1. 현재 스레드의 우선순위를 new_priority로 업데이트
 * 2. donor_list의 각 기부자(donor)를 순회
 * 3. 각 기부자의 유효 우선순위가 새로운 우선순위보다 낮거나 같으면 해당 기부자를 donor_list에서 제거
 * 4. 우선순위 변경 후 스케줄링을 위해 thread_yield() 호출
 * 
 * @param new_priority 설정할 새로운 우선순위 값
 */
void
thread_set_priority (int new_priority) {
	
	if(thread_mlfqs == false) {//$test-temp/mlfqs
		struct thread *cur = thread_current();
		cur->priority = new_priority;

		struct list_elem *prev = list_front(&cur->donor_list);
		struct list_elem *e = list_next(prev);
		while (e != list_tail(&cur->donor_list)) {
			prev = e->prev;
			struct thread *donor = list_entry(e, struct thread, donor_elem);
			int donor_priority = get_effective_priority(donor);

			if (donor_priority <= new_priority) {
				list_extract(&donor->donor_list);
				e = list_next(prev);
			} else {
				e = list_next(e);
			}
		}
	}
	
	thread_yield();
}

/**
 * @brief  * 기부자의 priority 값을 반환
 * 단, `donor_list`는 **우선순위 오름차순**으로 정렬되야함
 * `list_back()`이 가장 높은 우선순위의 기부자를 가리키는 구조임을 전제
 * 
 * @param t 우선순위를 확인할 대상 스레드
 * @return 기부를 고려한 현재 유효 우선순위 값*/

int get_effective_priority(struct thread *t) {
	struct thread *donor_thread = list_entry(list_back(&t->donor_list), struct thread, donor_elem);
    return donor_thread->priority;
}


/* Returns the current thread's priority. */
/**
 * @brief 현재 실행 중인 스레드의 유효 우선순위(effective priority)를 반환하는 함수
 *
 * 현재 스레드의 원래 우선순위(`priority`)를 반환하는 것이 아니라,
 * 우선순위 기부(priority donation) 상황을 고려하여 기부받은 우선순위가 존재할 경우,
 * 그 중 가장 높은 우선순위를 반영한 값을 반환
 *
 * 내부적으로 `get_effective_priority()` 함수를 호출하여 실제 우선순위를 계산
 *
 * @return int 현재 스레드의 유효 우선순위 값
 */
int
thread_get_priority (void) {
	return get_effective_priority(thread_current ());
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) {
	/* TODO: Your implementation goes here */
	enum intr_level old_level = intr_disable();
	struct thread *t = thread_current();
	t->nice = nice;
	t->priority = calaculate_priority(t->recent_cpu, t->nice);
	intr_set_level(old_level);
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) {
	/* TODO: Your implementation goes here */
	return thread_current()->nice*100;
}

/* Returns 100 times the system load average. */
/** @iizxcv @brief 100곱해서 정수형으로 리턴*/
int
thread_get_load_avg (void) {
	/* TODO: Your implementation goes here */
	return FTOI_N(MUXFI_F(load_avg,100));
	
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) {
	/* TODO: Your implementation goes here */
	return FTOI_N(MUXFI_F(thread_current()->recent_cpu,100));
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

	memset (t, 0, sizeof *t);
	t->status = THREAD_BLOCKED;
	strlcpy (t->name, name, sizeof t->name);
	t->tf.rsp = (uint64_t) t + PGSIZE - sizeof (void *);
	t->priority = priority;

	t->nice = 0;
	t->recent_cpu =0;
	if(thread_mlfqs) {
		t->priority = calaculate_priority(t->recent_cpu, t->nice);
	}


	t->magic = THREAD_MAGIC;

	list_init(&t->donor_list);  // 기부자 리스트 초기화
	list_push_back(&t->donor_list, &t->donor_elem);  // 자신의 donor_elem을 추가하여 빈 리스트 방지
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
			list_push_back (&destruction_req, &curr->elem);
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


//$test-temp/mlfqs
/**
 * @brief 시스템의 load_avg 값을 갱신합니다.
 *
 * load_avg는 지난 1분 동안 시스템이 얼마나 바빴는지를 나타내는 값으로,
 * 아래 수식으로 계산됩니다:
 *
 * load_avg = (59/60) * load_avg + (1/60) * ready_threads
 *
 * @details ready_list에 있는 스레드 수를 기반으로 계산합니다.
 */
static void load_avg_update(void) {
	load_avg = DIVFI_F(ADDFF_F(MUXFI_F(load_avg, 59), CITOF(get_count_threads())), 60);
	// load_avg = MUXFF_F(DIVFF_F(CITOF(59),CITOF(60)), load_avg) + MUXFI_F(DIVFF_F(CITOF(1),CITOF(60)), get_count_threads());
}

/**
 * @brief 모든 스레드의 recent_cpu 값을 갱신합니다.
 *
 * recent_cpu는 스레드가 최근 얼마나 CPU를 사용했는지를 나타내며,
 * 다음 수식에 따라 재계산됩니다:
 *
 * recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice
 *
 * @details 이 함수는 all_list에 있는 모든 스레드에 대해 값을 갱신해야 합니다.
 */
static void threads_recent_update(void) {
	struct list_elem* e;
	struct thread* t;

	// decay = (2*load_avg)/(2*load_avg + 1)
	fixed_t decay = DIVFF_F(MUXFI_F(load_avg, 2),
	                             ADDFF_F(MUXFI_F(load_avg, 2), CITOF(1)));
	t = thread_current();
	t->recent_cpu = ADDFF_F(MUXFF_F(t->recent_cpu, decay), CITOF(t->nice));

	for (e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e)) {
		t = list_entry(e, struct thread, elem);
		t->recent_cpu = ADDFF_F(MUXFF_F(t->recent_cpu, decay), CITOF(t->nice));
	}

	//sleep list 추가
	for (e = list_begin(&sleep_list); e != list_end(&sleep_list); e = list_next(e)) {
		t = list_entry(e, struct thread, elem);
		t->recent_cpu = ADDFF_F(MUXFF_F(t->recent_cpu, decay), CITOF(t->nice));
	}
}

static int calaculate_priority(fixed_t recent_cpu, int nice) {
	int priority = FTOI_N(CITOF(PRI_MAX) - DIVFI_F(recent_cpu,4) - CITOF(nice *2)) ;
	return priority >= PRI_MIN ? priority : PRI_MIN;
}

/**
 * @brief 리스트에 포함된 스레드 수를 계산합니다.
 *
 * @param li 카운트할 리스트 포인터 (예: ready_list)
 * @return 리스트에 포함된 thread 개수
 */
static size_t get_count_threads(void) {
	size_t count = list_size(&ready_list);
	// return count+1;
	return thread_current() != idle_thread ? count+1 : count;
}

/** 
 * @brief 1초마다 부하평균, 쓰레드-recent_cpu 업데이트 모아둔 함수
 */
void mlfq_run_for_sec(void){
	load_avg_update();
	threads_recent_update();
	// intr_yield_on_return();
}

void priority_update(void)
{
	struct thread *t = thread_current();
	t->priority = calaculate_priority(t->recent_cpu, t->nice);
	// printf("tid : %lld, priority : %lld, nice : %lld, recent-cpu : %lld\n", t->tid, t->priority, t->nice, t->recent_cpu);

	for (struct list_elem *e = list_begin(&ready_list); e != list_end(&ready_list); e = list_next(e)) {
		t = list_entry(e, struct thread, elem);
		t->priority = calaculate_priority(t->recent_cpu, t->nice);
		// printf("tid : %lld, priority : %lld, nice : %lld, recent-cpu : %lld\n", t->tid, t->priority, t->nice, t->recent_cpu);
	}
	list_sort(&ready_list, thread_priority_less, NULL);
	intr_yield_on_return();
}

//test-temp/mlfqs