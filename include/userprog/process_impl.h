#ifndef PROCESS_IMPL_H
#define PROCESS_IMPL_H

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>

#include "threads/interrupt.h"

// process.c 파일에서만 사용하는 구현 함수들 모음
// 파일 크기가 너무 커 분리를 위해 사용

/**
 * @brief 프로세스 정리 함수
 *
 * 현재 실행 중인 스레드의 프로세스 자원을 해제하고,
 * 페이지 디렉터리를 커널 전용 페이지 디렉터리로 전환합니다.
 */
void process_cleanup(void);

/**
 * @brief 스택에 인자를 푸시합니다.
 * @param arg 푸시할 인자가 저장된 버퍼의 포인터. NULL이면 NULL 바이트로 채웁니다.
 * @param size 푸시할 바이트 수
 * @param if_ 인터럽트 프레임 구조체. rsp 값이 업데이트됩니다.
 * @return 성공 시 새로 푸시된 스택 상단의 주소, 실패 시 NULL
 */
uint64_t *push_stack(char *arg, size_t size, struct intr_frame *if_);

/**
 * @brief 스택에서 지정된 바이트 수만큼 팝(pop)하고 페이지를 반환합니다.
 * @param size 팝할 바이트 수 (0보다 커야 함)
 * @param if_   인터럽트 프레임 구조체. rsp 값이 업데이트됩니다.
 * @return 팝된 후의 새로운 스택 포인터(rsp)를 가리키는 주소, 실패 시 NULL이 아닌 정상 주소 반환
 */
uint64_t *pop_stack(size_t size, struct intr_frame *if_);

#ifndef VM

/**
 * @brief 부모 스레드의 주소 공간을 복제하는 콜백 함수입니다.
 * @param pte 페이지 테이블 엔트리의 포인터
 * @param va  복제할 가상 주소
 * @param aux 부모 스레드의 포인터(`struct thread *`)
 * @return 성공 시 true, 실패 시 false
 */
bool duplicate_pte(uint64_t *pte, void *va, void *aux);

/**
 * @brief 사용자 가상 주소 `upage`를 커널 페이지 `kpage`에 매핑합니다.
 * @param upage     매핑할 사용자 가상 주소 (미리 페이지 정렬되어 있어야 함)
 * @param kpage     매핑할 커널 페이지 주소. `palloc_get_page`로 할당된 페이지여야 합니다.
 * @param writable  true면 사용자 프로세스가 페이지를 수정할 수 있으며, false면 읽기 전용입니다.
 * @return 매핑 성공 시 `true`, `upage`가 이미 매핑되어 있거나 매핑 실패 시 `false`
 */
bool install_page(void *upage, void *kpage, bool writable);
#endif

/**
 * @brief ELF 실행 파일을 현재 스레드에 로드하고 초기 실행 상태를 설정합니다.
 * @param file_name 실행할 ELF 파일의 경로
 * @param args      공백으로 구분된 명령줄 인자 문자열
 * @param if_       인터럽트 프레임. `RIP` (진입점) 및 `RSP` (스택 포인터)가 설정됩니다.
 * @return 로드 및 초기화 성공 시 `true`, 실패 시 `false`
 */
bool load(const char *file_name, char *args, struct intr_frame *if_);

#endif /* PROCESS_IMPL_H */
