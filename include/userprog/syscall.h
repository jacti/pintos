#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init(void);
int set_fd(struct file *file);
#endif /* userprog/syscall.h */
