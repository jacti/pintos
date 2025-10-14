#ifndef VM_ANON_H
#define VM_ANON_H
#include "kernel/bitmap.h"
#include "vm/vm.h"
struct page;
enum vm_type;

struct anon_page {
    bool alloc_swap;
    size_t swap_slot;
};

void vm_anon_init(void);
bool anon_initializer(struct page *page, enum vm_type type, void *kva);
bool copy_anon_page(struct hash *hash, struct page *dst_page, struct page *src_page);

#endif
