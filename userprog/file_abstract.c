#include "userprog/file_abstract.h"

#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "userprog/check_perm.h"
#include "userprog/file_abstract.h"

struct File* open_file(const char* name) {
    // 추후 디렉토리 오픈도 구분해서 추가
    struct File* file = calloc(1, sizeof(struct File));
    struct file* _file = filesys_open(name);
    if (_file == NULL) {
        free(file);
        return NULL;
    }

    file->file_ptr = _file;
    file->type = FILE;
    file->dup = 1;
    return file;
}

off_t get_file_size(struct File* file) {
    switch (file->type) {
        case FILE:
            return file_length(file->file_ptr);

        default:
            return -1;
    }
}

int read_file(struct File* file, void* buffer, off_t size) {
    switch (file->type) {
        case FILE:
            return file_read(file->file_ptr, buffer, size);

        case STDIN:
            int i = 0;
            for (; i < size; i++) {
                char a = input_getc();
                buffer = &a;
                if (a == '\n' || a == '\0') {
                    break;
                }
                buffer++;
            }
            return i;

        default:
            return -1;
    }
}

off_t write_file(struct File* file, const void* buffer, off_t size) {
    switch (file->type) {
        case STDOUT:
            return putbuf(buffer, size);

        case FILE:
            return file_write(file->file_ptr, buffer, size);

        default:
            return -1;
    }
}

int seek_file(struct File* file, off_t size) {
    switch (file->type) {
        case FILE:
            file_seek(file->file_ptr, size);
            return 0;
            break;

        default:
            return -1;
            break;
    }
}

off_t tell_file(struct File* file) {
    switch (file->type) {
        case FILE:
            return file_tell(file->file_ptr);

        default:
            return -1;
    }
}

int close_file(struct File* file) {
    ASSERT(file != NULL);
    ASSERT(file->dup > 0);
    if (--file->dup == 0) {
        switch (file->type) {
            case FILE:
                file_close(file->file_ptr);
                free(file);
                return 0;

            case STDIN:
                free(file);
                return 0;

            case STDOUT:
                free(file);
                return 0;

            default:
                free(file);
                return -1;
        }
    }
    return file->dup;
}

struct File* duplicate_file(struct File* file) {
    struct File* new_file;
    switch (file->type) {
        case FILE:
            new_file = calloc(1, sizeof(struct File));
            if (new_file) {
                new_file->file_ptr = file_duplicate(file->file_ptr);
                if (new_file->file_ptr == NULL) {
                    free(new_file);
                    new_file = NULL;
                }
            }
            break;
        case STDIN:
            new_file = init_stdin();
            break;
        case STDOUT:
            new_file = init_stdout();
            break;
        default:
            break;
    }
    if (new_file == NULL) {
        return NULL;
    }
    new_file->type = file->type;
    new_file->dup = file->dup;
    return new_file;
}

bool is_file_writable(struct File* file) {
    switch (file->type) {
        case STDIN:
            return false;

        case STDOUT:
            return true;

        case FILE:
            return file->file_ptr->deny_write;

        default:
            return false;
    }
}

bool is_same_file(struct File* a, struct File* b) {
    if (a->type != b->type) {
        return false;
    }
    switch (a->type) {
        case FILE:
            return (a->file_ptr->inode == b->file_ptr->inode);

        default:
            return true;
    }
}

struct File* init_stdin() {
    struct File* stdin_ = calloc(1, sizeof(struct File));
    if (stdin_ == NULL) {
        return NULL;
    }
    stdin_->dup = 1;
    stdin_->file_ptr = NULL;
    stdin_->type = STDIN;
    return stdin_;
};
struct File* init_stdout() {
    struct File* stdout_ = calloc(1, sizeof(struct File));
    if (stdout_ == NULL) {
        return NULL;
    }
    stdout_->dup = 1;
    stdout_->file_ptr = NULL;
    stdout_->type = STDOUT;
    return stdout_;
};