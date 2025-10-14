/* file.c: Implementation of memory backed file object (mmaped object). */

#include "string.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "vm/vm.h"

static bool file_backed_swap_in(struct page *page, void *kva);
static bool file_backed_swap_out(struct page *page);
static void file_backed_destroy(struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
    .swap_in = file_backed_swap_in,
    .swap_out = file_backed_swap_out,
    .destroy = file_backed_destroy,
    .type = VM_FILE,
};

/* The initializer of file vm */
void vm_file_init(void) {}

/* Initialize the file backed page */
bool file_backed_initializer(struct page *page, enum vm_type type, void *kva) {
    /* Set up the handler */
    page->operations = &file_ops;
    struct file_page *data = page->uninit.aux;
    if (data == NULL)
        return false;
    struct file_page *file_page = &page->file;
    memcpy(file_page, data, sizeof(struct file_page));
    free(data);
    if (page->page_group->frame != NULL) {
        file_backed_swap_in(page, kva);
    }
    return true;
}

/* Swap in the page by read contents from the file. */
static bool file_backed_swap_in(struct page *page, void *kva) {
    struct file_page *file_page = &page->file;
    if (file_read_at(file_page->file, page->page_group->frame->kva, file_page->page_read_bytes,
                     file_page->ofs) != (off_t)file_page->page_read_bytes) {
        return false;
    }
    memset(page->page_group->frame->kva + file_page->page_read_bytes, 0,
           file_page->page_zero_bytes);
    pml4_set_dirty(page->pml4, page->va, false);
    return true;
}

/* Swap out the page by writeback contents to the file. */
static bool file_backed_swap_out(struct page *page) {
    struct file_page *file_page = &page->file;
    if (pml4_is_dirty(page->pml4, page->va)) {
        if (file_write_at(file_page->file, page->page_group->frame->kva, file_page->page_read_bytes,
                          file_page->ofs) != (off_t)file_page->page_read_bytes) {
            return false;
        }
        pml4_set_dirty(page->pml4, page->va, false);
    }
    return true;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void file_backed_destroy(struct page *page) {
    struct file_page *file_page = &page->file;
    file_backed_swap_out(page);
    file_close(file_page->file);
    remove_page_group(page->page_group, page);
}

/* Do the mmap */
void *do_mmap(void *addr, size_t length, int writable, struct file *file, off_t offset) {
    size_t read_bytes = length;
    size_t file_left_size = file_length(file) - offset;
    void *va = addr;
    while (read_bytes > 0) {
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        page_read_bytes = page_read_bytes > file_left_size ? file_left_size : page_read_bytes;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        struct file_page *data = malloc(sizeof(struct file_page));
        if (data == NULL) {
            PANIC("here");
        }
        data->file = file_reopen(file);
        data->ofs = offset;
        data->page_read_bytes = page_read_bytes;
        data->page_zero_bytes = page_zero_bytes;
        data->length = length;
        data->start_addr = addr;

        if (!vm_alloc_page_with_initializer(VM_FILE, va, writable, NULL, data)) {
            PANIC("tid : %d 에서, %p 주소 mmap 할당 오류\n", thread_current()->tid, va);
        }

        read_bytes -= read_bytes > PGSIZE ? PGSIZE : read_bytes;
        file_left_size -= page_read_bytes;
        va += PGSIZE;
        offset += page_read_bytes;
    }
    return addr;
}

/* Do the munmap */
void do_munmap(void *addr) {
    struct supplemental_page_table *spt = &thread_current()->spt;
    struct page *page = spt_find_page(spt, pg_round_down(addr));
    if (page == NULL || page->operations->type != VM_FILE) {
        return;
    }

    void *va = page->file.start_addr;
    size_t n = pg_no(pg_round_up(page->file.length));

    for (int i = 0; i < n; i++) {
        page = spt_find_page(spt, va + i * PGSIZE);
        spt_remove_page(spt, page);
    }
}

bool copy_file_page(struct hash *hash, struct page *dst_page, struct page *src_page) {
    if (src_page->page_group->frame != NULL) {
        swap_out(src_page);
    }
    uninit_new(dst_page, src_page->va, NULL, VM_FILE, NULL, file_backed_initializer);
    copy_base_init(hash, dst_page, src_page);
    swap_in(dst_page, src_page->page_group->frame->kva);
    pml4_set_perm(src_page->pml4, src_page->va, false, PTE_W);
    return true;
}