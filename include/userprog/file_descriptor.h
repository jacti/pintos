#ifndef USERPROG_FILE_DESCRIPTOR_H
#define USERPROG_FILE_DESCRIPTOR_H

#include <stdbool.h>
#include <stddef.h>
struct File;
struct thread;

int set_fd(struct File *file);
int set_n_fd(struct File *file, size_t n);
int remove_fd(int fd);

int dup2_fd(size_t oldfd, size_t newfd);

int init_fd(struct thread *t);

struct File *get_file_from_fd(int fd);

void clear_fdt(struct thread *t);
int fork_fdt(struct thread *, struct thread *);
#endif /* USERPROG_FILE_DESCRIPTOR_H */