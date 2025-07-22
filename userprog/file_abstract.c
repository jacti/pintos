#include "userprog/file_abstract.h"

#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "userprog/file_abstract.h"

struct File STDIN_FILE = {.type = STDIN, .file_ptr = NULL};
struct File STDOUT_FILE = {.type = STDOUT, .file_ptr = NULL};

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
            break;

        default:
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
    switch (file->type) {
        case FILE:
            file_close(file->file_ptr);
            free(file);
            return 0;

        default:
            return -1;
    }
}

struct File* duplicate_file(struct File* file) {
    struct File* new_file;
    switch (file->type) {
        case FILE:
            new_file = calloc(1, sizeof(struct File));
            new_file->file_ptr = file_duplicate(file->file_ptr);
            break;
        case STDIN:
            new_file = &STDIN_FILE;
            break;
        case STDOUT:
            new_file = &STDOUT_FILE;
            break;
        default:
            break;
    }
    new_file->type = file->type;
    return new_file;
}
