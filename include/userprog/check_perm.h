#ifndef USERPROG_CHECK_PERM_H
#define USERPROG_CHECK_PERM_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* check_perm.h의 내용은 이곳에 작성하세요 */
enum pointer_check_flags {
    P_KERNEL = 0b0, /* kernel addr */
    P_USER = 0b1,   /* user addr */
    P_WRITE = 0b10, /* need write permission */
    IS_STR = 0b100  /* pointer is char* */
};

int64_t get_user(const uint8_t *uaddr);
bool put_user(uint8_t *udst, uint8_t byte);
bool is_user_accesable(void *start, size_t size, enum pointer_check_flags flag);

#endif /* USERPROG_CHECK_PERM_H */
