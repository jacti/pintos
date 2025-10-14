#ifndef VM_VM_H
#define VM_VM_H
#include <stdbool.h>

#include "kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/anon.h"
#include "vm/file.h"
#include "vm/uninit.h"
#include "vm/vm_type.h"
#ifdef EFILESYS
#include "filesys/page_cache.h"
#endif

struct page_operations;
struct thread;

#define VM_TYPE(type) ((type) & 7)

void page_delete(struct hash_elem *e, void *aux);
unsigned page_hash(const struct hash_elem *p_, void *aux);
bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux);

struct page_group {
    struct frame *frame;
    struct list page_list;
    struct lock lock;
};

/* The representation of "page".
 * This is kind of "parent class", which has four "child class"es, which are
 * uninit_page, file_page, anon_page, and page cache (project4).
 * DO NOT REMOVE/MODIFY PREDEFINED MEMBER OF THIS STRUCTURE. */
struct page {
    const struct page_operations *operations;
    void *va; /* Address in terms of user space */
    struct page_group *page_group;

    /* Your implementation */
    bool writable;
    struct hash_elem hash_elem;
    struct list_elem list_elem;
    uint64_t *pml4; /* Page map level 4 */

    // uint64_t *pte;
    /* Per-type data are binded into the union.
     * Each function automatically detects the current union */
    union {
        struct uninit_page uninit;
        struct anon_page anon;
        struct file_page file;
#ifdef EFILESYS
        struct page_cache page_cache;
#endif
    };
};

/* The representation of "frame" */
struct frame {
    void *kva;
    bool avoid_swap;
    struct page_group *page_group;
};

/* The function table for page operations.
 * This is one way of implementing "interface" in C.
 * Put the table of "method" into the struct's member, and
 * call it whenever you needed. */
struct page_operations {
    bool (*swap_in)(struct page *, void *);
    bool (*swap_out)(struct page *);
    void (*destroy)(struct page *);
    enum vm_type type;
};

#define swap_in(page, v) (page)->operations->swap_in((page), v)
#define swap_out(page) (page)->operations->swap_out(page)
#define destroy(page)                \
    if ((page)->operations->destroy) \
    (page)->operations->destroy(page)

/* Representation of current process's memory space.
 * We don't want to force you to obey any specific design for this struct.
 * All designs up to you for this. */
struct supplemental_page_table {
    struct hash table;
};

#include "threads/thread.h"
void supplemental_page_table_init(struct supplemental_page_table *spt);
bool supplemental_page_table_copy(struct supplemental_page_table *dst,
                                  struct supplemental_page_table *src);
void supplemental_page_table_kill(struct supplemental_page_table *spt);
struct page *spt_find_page(struct supplemental_page_table *spt, void *va);
bool spt_insert_page(struct supplemental_page_table *spt, struct page *page);
void spt_remove_page(struct supplemental_page_table *spt, struct page *page);

void vm_init(void);
bool vm_try_handle_fault(struct intr_frame *f, void *addr, bool user, bool write, bool not_present);

#define vm_alloc_page(type, upage, writable) \
    vm_alloc_page_with_initializer((type), (upage), (writable), NULL, NULL)
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux);
void vm_dealloc_page(struct page *page);
bool vm_claim_page(void *va);
enum vm_type page_get_type(struct page *page);
bool copy_base_init(struct hash *hash, struct page *dst_page, struct page *src_page);
void vm_free_frame(struct frame *frame);
void remove_page_group(struct page_group *page_group, struct page *page);
void vm_dealloc_pte(struct list *page_list);

#endif /* VM_VM_H */
