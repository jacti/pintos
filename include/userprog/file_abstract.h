#ifndef USERPROG_FILE_ABSTRACT_H
#define USERPROG_FILE_ABSTRACT_H

#include "filesys/file.h"

enum file_type { STDIN, STDOUT, FILE, DIRECTORY };
struct File {
    enum file_type type;
    struct file* file_ptr;
};

extern struct File STDIN_FILE;
extern struct File STDOUT_FILE;

/**
 * @brief 주어진 경로의 파일을 열어 File 객체를 생성합니다.
 *
 * @param name 열려는 파일의 경로를 나타내는 문자열
 * @return 성공 시 새로 생성된 struct File* 포인터, 실패 시 NULL 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
struct File* open_file(const char* name);

/**
 * @brief 파일의 전체 크기를 바이트 단위로 반환합니다.
 *
 * @param file 크기를 확인할 파일 객체
 * @return 파일 크기(바이트), 오류 시 음수 값 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
off_t get_file_size(struct File* file);

/**
 * @brief 파일에서 데이터를 읽어 지정된 버퍼에 저장합니다.
 *
 * @param file 데이터를 읽을 파일 객체
 * @param buffer 읽어온 데이터를 저장할 버퍼의 시작 주소
 * @param size 읽을 바이트 수
 * @return 실제로 읽은 바이트 수, 오류 시 음수 값 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
int read_file(struct File* file, void* buffer, off_t size);

/**
 * @brief 버퍼에 담긴 데이터를 파일에 씁니다.
 *
 * @param file 데이터를 쓸 파일 객체
 * @param buffer 기록할 데이터가 담긴 버퍼의 시작 주소
 * @param size 쓸 바이트 수
 * @return 실제로 기록된 바이트 수, 오류 시 음수 값 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
off_t write_file(struct File* file, const void* buffer, off_t size);

/**
 * @brief 파일 스트림의 현재 오프셋을 지정 위치로 이동합니다.
 *
 * @param file 오프셋을 조정할 파일 객체
 * @param size 파일 시작 위치로부터 이동할 바이트 수
 * @return 성공 시 0, 오류 시 음수 값 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
int seek_file(struct File* file, off_t size);

/**
 * @brief 파일 스트림의 현재 오프셋 위치를 바이트 단위로 반환합니다.
 *
 * @param file 오프셋을 확인할 파일 객체
 * @return 파일 시작 위치로부터의 현재 오프셋(바이트)
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
off_t tell_file(struct File* file);

/**
 * @brief 열린 파일을 닫고 관련 자원을 해제합니다.
 *
 * @param file 닫을 파일 객체
 * @return 성공 시 0, 오류 시 음수 값 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
int close_file(struct File* file);

/**
 * @brief 기존 File 객체를 복제하여 새로운 File 객체를 생성합니다.
 *
 * @param file 복제할 원본 파일 객체
 * @return 성공 시 복제된 struct File* 포인터, 실패 시 NULL 반환
 *
 * @see https://www.notion.so/jactio/238c9595474e803ca067e6ca17b9c12c?source=copy_link
 *
 * @branch feat/new_file_structure
 */
struct File* duplicate_file(struct File* file);

bool is_file_writable(struct File* file);

bool is_same_file(struct File* a, struct File* b);

#endif /* USERPROG_FILE_ABSTRACT_H */