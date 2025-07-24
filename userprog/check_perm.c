#include "userprog/check_perm.h"

#include "threads/vaddr.h"

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
int64_t get_user(const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile(
        "movabsq $done_get, %0\n"  // done_get 레이블의 주소를 result에 저장
        "movzbq %1, %0\n"  // *uaddr에서 1바이트를 읽어 %0 (result)에 저장. 세그폴트 발생 시 이 부분
                           // 건너뜀.
        "done_get:\n"  // (페이지 폴트 핸들러가 result를 -1로 설정하고 여기에 점프하도록 수정되어야
                       // 함)
        : "=&a"(result)
        : "m"(*uaddr), "c"(uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
bool put_user(uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile(
        "movabsq $done_put, %0\n"  // done_put 레이블의 주소를 error_code에 저장
        "movb %b2, %1\n"  // byte를 *udst에 쓴다. 세그폴트 발생 시 이 부분 건너뜀.
        "done_put:\n"  // (페이지 폴트 핸들러가 error_code를 -1로 설정하고 여기에 점프하도록
                       // 수정되어야 함)
        : "=&a"(error_code), "=m"(*udst)
        : "q"(byte), "c"(udst));
    return error_code != -1;
}

/**
 * @brief 사용자 메모리 영역이 접근 가능한지 검사합니다.
 *
 * @branch ADD/write_handler
 * @see
 * https://www.notion.so/jactio/access_control-235c9595474e8083ba94d4bc3d1ce7e3?source=copy_link
 * @param start 검사 시작 주소(포인터)
 * @param size 검사할 바이트 크기
 * @param write 쓰기 접근 권한도 확인할지 여부 (true일 경우 put_user로 쓰기 검증)
 * @return 접근 가능하면 true, 그렇지 않으면 false
 *
 * start 주소부터 size 바이트 범위 내 각 페이지마다 get_user를 통해 읽기 접근을 확인하고,
 * write가 true일 경우 put_user를 통해 쓰기 접근도 검증합니다.
 * 또한, 검사 범위가 커널 영역(KERN_BASE)이상일 경우 즉시 false를 반환합니다.
 * get_user 및 put_user는 페이지 폴트 발생 시 -1을 반환하도록 구현되어 있습니다.
 */
bool is_user_accesable(void *start, size_t size, enum pointer_check_flags flag) {
    if (flag & IS_STR) {
        if (get_user((uint8_t *)start) == (int64_t)-1) {
            return false;
        }
        size = strlen(start) + 1;
    }

    uintptr_t end = (uintptr_t)start + size, ptr = start;
    size_t n = pg_diff(start, end);
    int64_t byte;

    ASSERT((uintptr_t)start <= (uintptr_t)end);

    if (start == NULL || ((flag & P_USER) && !is_user_vaddr(end))) {
        return false;
    }

    for (int i = 0; i < n + 1; i++) {
        if ((byte = get_user((uint8_t *)ptr)) == (int64_t)-1) {
            return false;
        }
        if (flag & P_WRITE) {
            if (put_user(ptr, (uint8_t)byte) == (int64_t)-1) {
                return false;
            }
        }
        ptr += PGSIZE;
        if (ptr > end) {
            ptr = end;
        }
    }
    return true;
}
