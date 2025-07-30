#include "userprog/process_impl.h"

#include <string.h>

#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

//  static 함수 선정의

/**
 * @details
 * 1. thread_current()로 현재 스레드를 가져옵니다.
 * 2. VM이 활성화된 경우 supplemental_page_table_kill()을 호출하여
 *    supplemental page table을 해제합니다.
 * 3. curr->pml4(현재 프로세스 페이지 디렉터리)를 확인 후 NULL이 아니면:
 *    - curr->pml4를 NULL로 설정
 *    - pml4_activate(NULL) 호출
 *    - pml4_destroy() 호출
 *
 * @warning 페이지 디렉터리 전환 순서가 매우 중요합니다:
 *   - 먼저 curr->pml4 = NULL; 설정
 *     (설정하지 않으면 타이머 인터럽트가 해제된 페이지 디렉터리로 복귀할 수 있음)
 *   - 그다음 pml4_activate(NULL); 호출하여 커널 페이지 디렉터리 활성화
 *     (순서가 바뀌면 이미 해제된 페이지 디렉터리를 활성화할 위험이 있음)
 *
 * @branch feat/refactoring
 * @see https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
void process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    uint64_t *pml4 = curr->pml4;
    if (pml4 != NULL) {
        curr->pml4 = NULL;
        pml4_activate(NULL);
        pml4_destroy(pml4);
    }
}

/**
 * @details
 * - `rsp`를 `size`만큼 감소시켜 스택 공간을 확보하고, 필요한 페이지를 할당·매핑합니다.
 * - 페이지 할당 실패 시 할당된 페이지를 해제하고 `rsp`를 원래대로 복원한 후 `NULL`을 반환합니다.
 * - 확보된 스택 영역에 `arg` 데이터를 복사하거나(`arg != NULL`), `'\0'`을 채웁니다.
 *
 * @warning
 * - `USER_STACK` 경계 및 페이지 정렬(`pg_round_down`, `PGBITS`) 규칙에 의존하므로,
 *   정의가 올바르지 않으면 예기치 않은 동작이 발생할 수 있습니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
uint64_t *push_stack(char *arg, size_t size, struct intr_frame *if_) {
    bool alloc_fail = false;
    uintptr_t old_rsp = if_->rsp;
    if_->rsp = old_rsp - size;

    size_t n = pg_diff(old_rsp, if_->rsp);

    if (old_rsp == USER_STACK) {
        n -= 1;
    }

    uintptr_t page_bottom = pg_round_down(old_rsp);
    for (int i = 0; i < n; i++) {
        page_bottom -= PGSIZE;
        uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        if (kpage != NULL) {
            if (!install_page((void *)page_bottom, kpage, true)) {
                palloc_free_page(kpage);
                page_bottom += PGSIZE;
                alloc_fail = true;
                break;
            }
        }
    }

    if (alloc_fail) {
        for (; page_bottom < (uintptr_t)pg_round_down(old_rsp); page_bottom += PGSIZE) {
            palloc_free_page((void *)page_bottom);
        }
        if_->rsp = old_rsp;
        return NULL;
    }

    arg == NULL ? memset(if_->rsp, 0, size) : memcpy(if_->rsp, arg, size);

    return (uint64_t *)if_->rsp;
}

/**
 * @details
 * - `rsp`를 `size`만큼 증가시켜 스택 데이터를 팝하고,
 *   사용되지 않는 페이지를 사용자 페이지 풀로 반환합니다.
 * - `size`가 0이거나 `rsp + size`가 `USER_STACK`을 초과하면 ASSERT로 패닉합니다.
 *
 * @warning
 * - `USER_STACK` 경계 및 페이지 정렬 매크로(`pg_round_down`, `PGBITS`) 정의에 의존합니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
uint64_t *pop_stack(size_t size, struct intr_frame *if_) {
    ASSERT(size > 0);
    ASSERT(if_->rsp + size <= USER_STACK);

    uintptr_t page_bottom = pg_round_down(if_->rsp);
    if_->rsp += size;

    size_t n = ((uintptr_t)pg_round_down(if_->rsp) - page_bottom) >> PGBITS;

    if (if_->rsp == USER_STACK) {
        n -= 1;
    }

    for (int i = 0; i < n; i++) {
        palloc_free_page(page_bottom);
        page_bottom += PGSIZE;
    }

    return if_->rsp;
}

#ifndef VM

/**
 * @details
 * - `va`가 사용자 가상 주소인지 확인합니다. 커널 주소이면 즉시 true를 반환합니다.
 * - 부모 스레드의 PML4에서 `va`에 해당하는 페이지를 가져옵니다.
 * - 자식 스레드의 PML4에 이미 매핑된 페이지가 있으면 해제합니다.
 * - `palloc_get_page(PAL_USER | PAL_ZERO)`로 새 페이지를 할당하지 못하면 false를 반환합니다.
 * - `memcpy`로 부모 페이지 내용을 복사하고, `is_writable(pte)` 결과를 유지하여
 *   `pml4_set_page`로 매핑합니다.
 * - 매핑에 실패하면 할당된 페이지를 해제하고 false를 반환하며, 성공 시 true를 반환합니다.
 *
 * @warning
 * - `aux`는 반드시 부모 스레드(`struct thread *`)를 가리켜야 합니다.
 * - `parent->pml4` 및 `thread_current()->pml4`가 유효하게 초기화되어 있어야 합니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    if (!is_user_vaddr(va)) {
        return true;
    }

    parent_page = pml4_get_page(parent->pml4, va);

    if ((newpage = pml4_get_page(current->pml4, va)) != NULL) {
        palloc_free_page(newpage);
    }
    newpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (newpage == NULL) {
        return false;
    }

    writable = is_writable(pte);
    memcpy(newpage, parent_page, PGSIZE);

    if (!pml4_set_page(current->pml4, va, newpage, writable)) {
        palloc_free_page(newpage);
        return false;
    }
    return true;
}

/**
 * @details
 * - `pml4_get_page`로 `upage`의 기존 매핑을 확인하고, 매핑이 없으면
 *   `pml4_set_page`로 `kpage`를 `upage`에 매핑합니다.
 * - 매핑 성공 시 `true`, 이미 매핑되어 있거나 매핑 실패 시 `false`를 반환합니다.
 *
 * @warning
 * - `kpage`는 반드시 `palloc_get_page(PAL_USER)`로 할당된 사용자 페이지여야 합니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    return (pml4_get_page(t->pml4, upage) == NULL &&
            pml4_set_page(t->pml4, upage, kpage, writable));
}
#endif