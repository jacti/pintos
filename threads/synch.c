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

/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
void sema_init(struct semaphore *sema, unsigned value) {
    ASSERT(sema != NULL);

    sema->value = value;
    list_init(&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void sema_down(struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);
    ASSERT(!intr_context());

    old_level = intr_disable();
    while (sema->value == 0) {
        // $feat/thread_priority_less
        list_insert_ordered(&sema->waiters, &thread_current()->elem, thread_priority_less, NULL);
        // feat/thread_priority_less
        thread_block();
    }
    sema->value--;
    intr_set_level(old_level);
}

/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool sema_try_down(struct semaphore *sema) {
    enum intr_level old_level;
    bool success;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (sema->value > 0) {
        sema->value--;
        success = true;
    } else
        success = false;
    intr_set_level(old_level);

    return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void sema_up(struct semaphore *sema) {
    enum intr_level old_level;

    ASSERT(sema != NULL);

    old_level = intr_disable();
    if (!list_empty(&sema->waiters))
        thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
    sema->value++;

    thread_yield();  // 높은 우선순위 스레드가 대기 상태에서 깨어날 때, 즉시 CPU를 점유할 수 있도록
                     // 보장
    intr_set_level(old_level);
}

static void sema_test_helper(void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void sema_self_test(void) {
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++) {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

/* Thread function used by sema_self_test(). */
static void sema_test_helper(void *sema_) {
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++) {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
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
void lock_init(struct lock *lock) {
    ASSERT(lock != NULL);

    lock->holder = NULL;
    sema_init(&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
/**
 * @brief 락을 획득하고 우선순위 기부를 처리하는 함수
 *
 * 락이 이미 다른 스레드에 의해 보유되고 있을 때, 현재 스레드의 우선순위를
 * 락 보유자에게 기부하여 우선순위 역전 문제를 해결
 *
 * 우선순위 기부는 다음과 같은 상황에서 발생합니다:
 * - 높은 우선순위 스레드가 낮은 우선순위 스레드가 보유한 락을 기다릴 때
 * - 기부 체인이 형성되어 우선순위가 연쇄적으로 전파될 때
 *
 * 동작 과정:
 * 1. 락 획득 시도 (sema_try_down)
 * 2. 실패 시 우선순위 기부 로직 실행:
 *    a) 중복 기부 제거: 같은 락을 기다리는 기존 기부자 찾아서 제거
 *    b) 새로운 기부 관계 설정: donor의 donor_list를 holder에 추가
 *    c) 기부 체인 전파: holder가 다른 락을 기다린다면 기부 체인 확장
 *    d) 우선순위 재정렬: 기부 후 우선순위 순서로 정렬
 * 3. 락 대기 (sema_down)
 * 4. 락 보유자 설정
 *
 * 주의사항:
 * - 인터럽트가 비활성화된 상태에서 실행되어야 함
 * - donor_list는 우선순위 순서로 정렬되어야 함
 * - 기부 체인은 무한 루프를 방지하기 위해 주의 깊게 처리
 *
 * @param lock 획득할 락
 */
void lock_acquire(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    enum intr_level old_level;
    old_level = intr_disable();
    if (!sema_try_down(&lock->semaphore)) {
        struct thread *donor = thread_current(), *holder = lock->holder;
        donor->wait_on_lock = lock;
        struct list_elem *e = list_next(list_begin(&holder->donor_list));

        while (e != list_end(&holder->donor_list) && e->next != NULL) {
            struct thread *existing_donor = list_entry(e, struct thread, donor_elem);
            if (existing_donor->wait_on_lock == lock) {
                list_extract(&existing_donor->donor_list);
                break;
            }
            e = list_next(e);
        }

        list_extend(&holder->donor_list, &donor->donor_list);
        struct thread *cur = holder, *cur_holder;
        struct list_elem *donor_end = list_back(&donor->donor_list);

        while (cur->wait_on_lock && (cur_holder = cur->wait_on_lock->holder) != NULL) {
            list_tail(&cur_holder->donor_list)->prev = donor_end;
            donor_end->next = list_tail(&cur_holder->donor_list);
            cur = cur_holder;
        }

        struct list *holder_list = find_list(&holder->elem);
        list_sort(holder_list, thread_priority_less, NULL);

        sema_down(&lock->semaphore);
    }
    intr_set_level(old_level);

    lock->holder = thread_current();
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool lock_try_acquire(struct lock *lock) {
    bool success;

    ASSERT(lock != NULL);
    ASSERT(!lock_held_by_current_thread(lock));

    success = sema_try_down(&lock->semaphore);
    if (success)
        lock->holder = thread_current();
    return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
/**
 * @brief 락을 해제하고 우선순위 기부를 정리하는 함수
 *
 * 현재 스레드가 보유하고 있는 락을 해제하고, 해당 락을 기다리고 있던
 * 스레드들에게 우선순위 기부를 정리
 *
 * 우선순위 기부 정리는 다음과 같은 이유로 중요:
 * - 락이 해제되면 기부 관계가 더 이상 필요하지 않음
 * - 기부받은 우선순위를 원래 우선순위로 복원해야 함
 * - 기부 체인에서 해당 스레드를 제거해야 함
 *
 * 동작 과정:
 * 1. 인터럽트 비활성화 (원자적 연산 보장)
 * 2. 대기 중인 스레드의 우선순위 기부 정리:
 *    - 세마포어 대기 리스트에서 첫 번째 스레드 선택
 *    - 해당 스레드의 donor_list에서 기부 관계 제거
 *    - wait_on_lock을 NULL로 설정하여 기다리는 락 없음을 표시
 * 3. 락 보유자 정보 제거 (lock->holder = NULL)
 * 4. 세마포어 해제 (대기 중인 스레드 깨우기)
 * 5. 인터럽트 재활성화
 *
 * 주의사항:
 * - 인터럽트가 비활성화된 상태에서 실행되어야 함
 * - 기부 정리 순서가 중요함 (기부자 제거 → 락 해제)
 * - 세마포어 대기 리스트가 비어있을 수 있음
 *
 * @param lock 해제할 락
 */
void lock_release(struct lock *lock) {
    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    enum intr_level old_level = intr_disable();

    if (!list_empty(&lock->semaphore.waiters)) {
        struct thread *release_thread =
            list_entry(list_front(&lock->semaphore.waiters), struct thread, elem);
        list_extract(&release_thread->donor_list);
        release_thread->wait_on_lock = NULL;
    }
    lock->holder = NULL;
    sema_up(&lock->semaphore);
    intr_set_level(old_level);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool lock_held_by_current_thread(const struct lock *lock) {
    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

/* One semaphore in a list. */
struct semaphore_elem {
    struct list_elem elem;      /* List element. */
    struct semaphore semaphore; /* This semaphore. */
};

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void cond_init(struct condition *cond) {
    ASSERT(cond != NULL);

    list_init(&cond->waiters);
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

/**
 * @brief 조건 변수 대기자들의 우선순위를 비교하는 함수
 *
 * 조건 변수의 대기자 리스트에서 두 세마포어 요소의 우선순위를 비교
 * 각 세마포어 요소의 대기자 중 첫 번째 스레드의 유효 우선순위를 비교하여
 * 우선순위가 높은 순서로 정렬
 *
 * @param a 첫 번째 세마포어 요소 (struct semaphore_elem의 elem)
 * @param b 두 번째 세마포어 요소 (struct semaphore_elem의 elem)
 * @return a의 우선순위가 b보다 높으면 true, 그렇지 않으면 false
 */
int waiter_priority_less(struct list_elem *a, struct list_elem *b) {
    struct semaphore_elem *w_a = list_entry(a, struct semaphore_elem, elem);
    struct semaphore_elem *w_b = list_entry(b, struct semaphore_elem, elem);
    struct thread *t_a = list_entry(list_front(&w_a->semaphore.waiters), struct thread, elem);
    struct thread *t_b = list_entry(list_front(&w_b->semaphore.waiters), struct thread, elem);

    return get_effective_priority(t_a) > get_effective_priority(t_b);
}

void cond_wait(struct condition *cond, struct lock *lock) {
    struct semaphore_elem waiter;

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    sema_init(&waiter.semaphore, 0);
    list_push_back(&cond->waiters, &waiter.elem);
    lock_release(lock);
    sema_down(&waiter.semaphore);
    lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
/**
 * @brief 조건 변수에서 대기 중인 스레드 중 하나를 깨우는 함수
 *
 * 조건 변수의 대기자 리스트에서 우선순위가 가장 높은 스레드를 선택하여 깨움
 * 우선순위 기부를 고려한 유효 우선순위로 정렬한 후
 * 가장 높은 우선순위의 스레드를 깨움
 *
 * @param cond 시그널을 보낼 조건 변수
 * @param lock UNUSED 매개변수 (사용되지 않음)
 */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    if (!list_empty(&cond->waiters)) {
        list_sort(&cond->waiters, waiter_priority_less, NULL);

        sema_up(
            &list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
    }
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!list_empty(&cond->waiters)) cond_signal(cond, lock);
}
