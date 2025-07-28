#include "userprog/file_descriptor.h"

#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/check_perm.h"
#include "userprog/file_abstract.h"

static int _extend_fdt(struct thread *t, size_t n);
static int _set_fd(struct File *file, struct thread *t);
static int _remove_fd(int fd, struct thread *t);

static int _extend_fdt(struct thread *t, size_t n) {
    ASSERT(t->fd_pg_cnt < n);
    uint64_t *kpage = palloc_get_multiple((PAL_ZERO), n);
    if (kpage == NULL) {
        return -1;
    }
    if (t->fd_pg_cnt != 0) {
        void *old_fdt = t->fdt;
        memcpy(kpage, old_fdt, (t->fd_pg_cnt << PGBITS));
        palloc_free_multiple(old_fdt, t->fd_pg_cnt);
    }
    t->fd_pg_cnt = n;
    t->fdt = kpage;
    return t->fd_pg_cnt;
}

static int _set_fd(struct File *file, struct thread *t) {
    if (t->open_file_cnt < t->fd_pg_cnt << (PGBITS - 3)) {
        for (int i = 0; i < t->fd_pg_cnt << (PGBITS - 3); i++) {
            if (t->fdt[i] == NULL) {
                t->fdt[i] = file;
                t->open_file_cnt++;
                return i;
            }
        }
    } else {
        if (_extend_fdt(t, t->fd_pg_cnt + 1) == -1) {
            return -1;
        }
        t->fdt[t->open_file_cnt++] = file;
        return t->open_file_cnt - 1;
    }
    return -1;
}

int set_fd(struct File *file) {
    return _set_fd(file, thread_current());
}

int set_n_fd(struct File *file, size_t n) {
    struct thread *cur = thread_current();
    if (!is_user_accesable((struct File **)(cur->fdt + n), 8, P_KERNEL | P_WRITE)) {
        if (_extend_fdt(cur, (n >> (PGBITS - 3)) + 1) == -1) {
            return -1;
        }
    }
    if (remove_fd(n) == -1) {
        return -1;
    }
    cur->fdt[n] = file;
    cur->open_file_cnt += 1;
    return n;
}

static int _remove_fd(int fd, struct thread *t) {
    int result = -2;
    if (!is_user_accesable((struct File **)(t->fdt + fd), 8, P_KERNEL | P_WRITE)) {
        return -1;
    }
    struct File *removed_fd = t->fdt[fd];
    t->fdt[fd] = NULL;
    if (removed_fd != NULL) {
        if (close_file(removed_fd) > 0) {
            // t->total_dup_cnt--;
        }
        t->open_file_cnt -= 1;
        result = fd;
    }
    return result;
}

int remove_fd(int fd) {
    return _remove_fd(fd, thread_current());
}

int dup2_fd(size_t oldfd, size_t newfd) {
    if (oldfd < 0 || newfd < 0) {
        return -1;
    }
    if (oldfd == newfd) {
        return newfd;
    }
    struct File *get_file = get_file_from_fd(oldfd);
    if (get_file == NULL) {
        return -1;
    }

    int result;
    if ((result = set_n_fd(get_file, newfd)) != -1) {
        get_file->dup++;
    }
    return result;
}

static int remove_if_duplicated(int fd) {
    struct thread *cur = thread_current();
    struct File *file;
    struct File *origin;
    if ((file = cur->fdt[fd]) == NULL) {
        return -1;
    }
    int check_cnt = 0;
    for (int i = 0; check_cnt < cur->open_file_cnt - 1; i++) {
        origin = cur->fdt[i];
        if (i == fd) {
            continue;
        }
        if (origin != NULL) {
            check_cnt++;
            if (is_same_file(origin, file)) {
                remove_fd(i);
                cur->fdt[i] = file;
                cur->fdt[fd] = NULL;
                return i;
            }
        }
    }
    return fd;
}

int init_fd(struct thread *t) {
    if (_set_fd(init_stdin(), t) == -1 || _set_fd(init_stdout(), t) == -1) {
        clear_fdt(t);
        return -1;
    }
    return 0;
}

struct File *get_file_from_fd(int fd) {
    if (get_user((thread_current()->fdt + fd)) == (int64_t)-1) {
        return NULL;
    }
    return thread_current()->fdt[fd];
}

void clear_fdt(struct thread *t) {
    int log = 0;
    if (t->fdt != NULL && t->fd_pg_cnt != 0) {
        for (int i = 0; (t->open_file_cnt > 0); i++) {
            barrier();
            if (_remove_fd(i, t) == -1) {
                break;
            }
            log++;
        }
        palloc_free_multiple(t->fdt, t->fd_pg_cnt);
    }
    t->open_file_cnt = 0;
    t->fdt = NULL;
    t->fd_pg_cnt = 0;
}

int fork_fdt(struct thread *parent, struct thread *child) {
    clear_fdt(child);
    ASSERT(child->fdt == NULL);
    if (parent->fd_pg_cnt == 0)
        return 0;
    child->fd_pg_cnt = parent->fd_pg_cnt;
    int n = 0;
    bool dup_finish = false;
    if ((child->fdt = palloc_get_multiple(PAL_ZERO, child->fd_pg_cnt)) == NULL) {
        child->fd_pg_cnt = 0;
        return -1;
    }
    int buff_page_cnt = child->fd_pg_cnt / 4 + 1;
    int *buffer = palloc_get_multiple(PAL_ZERO, buff_page_cnt);
    if (buffer == NULL) {
        palloc_free_multiple(child->fdt, child->fd_pg_cnt);
        child->fd_pg_cnt = 0;
        return -1;
    }
    for (int i = 0; child->open_file_cnt < parent->open_file_cnt; i++) {
        if (parent->fdt[i] != NULL) {
            child->open_file_cnt++;
            if (parent->fdt[i]->dup > 1) {
                for (int j = 0; j < n; j++) {
                    if (parent->fdt[buffer[j]] == parent->fdt[i]) {
                        child->fdt[i] = child->fdt[buffer[j]];
                        child->fdt[i]->dup++;
                        dup_finish = true;
                        break;
                    }
                }
                if (dup_finish) {
                    dup_finish = false;
                    continue;
                }
                buffer[n++] = i;
            }
            child->fdt[i] = duplicate_file(parent->fdt[i]);
            if (child->fdt[i] == NULL) {
                child->open_file_cnt--;
                palloc_free_multiple(buffer, buff_page_cnt);
                return -1;
            }
        }
    }
    palloc_free_multiple(buffer, buff_page_cnt);
    return 0;
}