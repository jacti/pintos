#include "filesys/file.h"

enum file_type { STDIN, STDOUT, FILE, DIRECTORY };
struct File {
    enum file_type type;
    struct file* file_ptr;
};

struct File* open_file(const char* name);
off_t get_file_size(struct File* file);
int read_file(struct File*, void*, off_t);
off_t write_file(struct File*, const void*, off_t);
void seek_file(struct File*, off_t);
off_t tell_file(struct File*);
int close_file(struct File*);
struct File* duplicate_file(struct File* file);