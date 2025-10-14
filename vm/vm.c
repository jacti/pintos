/* vm.c: Generic interface for virtual memory objects. */
#include "vm/vm.h"

#include <string.h>

#include "kernel/hash.h"
#include "threads/malloc.h"
#include "threads/mmu.h"
#include "threads/vaddr.h"
#include "userprog/check_perm.h"
#include "vm/inspect.h"

static struct frame *frame_table;
static size_t next;

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void vm_init(void) {
    vm_anon_init();
    vm_file_init();
#ifdef EFILESYS /* For project 4 */
    pagecache_init();
#endif
    register_inspect_intr();
    /* DO NOT MODIFY UPPER LINES. */
    /* TODO: Your code goes here. */
    // 필요한 페이지 수 계산
    size_t n = (user_pages * sizeof(struct frame) + PGSIZE - 1) >> PGBITS;
    frame_table = palloc_get_multiple(PAL_ZERO, n);
    next = 0;

    ASSERT(frame_table);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type page_get_type(struct page *page) {
    int ty = VM_TYPE(page->operations->type);
    switch (ty) {
        case VM_UNINIT:
            return VM_TYPE(page->uninit.type);
        default:
            return ty;
    }
}

/* Helpers */
static struct frame *vm_get_victim(void);
static bool vm_do_claim_page(struct page *page);
static struct frame *vm_evict_frame(void);
static struct page_group *init_page_group();
static void page_init(struct page *page, bool writable, struct hash *hash);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool vm_alloc_page_with_initializer(enum vm_type type, void *upage, bool writable,
                                    vm_initializer *init, void *aux) {
    ASSERT(VM_TYPE(type) != VM_UNINIT)

    struct supplemental_page_table *spt = &thread_current()->spt;

    /* Check wheter the upage is already occupied or not. */
    if (spt_find_page(spt, upage) == NULL) {
        /* Create the page, fetch the initializer according to the VM type,
         * and then create "uninit" page struct by calling uninit_new. You
         * should modify the field after calling the uninit_new. */
        struct page *Page = malloc(sizeof(struct page));
        if (Page == NULL) {
            goto err;
        } else {
            void *initializer;
            switch (type) {
                case VM_ANON:
                    initializer = anon_initializer;
                    break;
                case VM_FILE:
                    initializer = file_backed_initializer;
                default:
                    break;
            }

            uninit_new(Page, upage, init, type, aux, initializer);
            page_init(Page, writable, spt);
        }
        /* Insert the page into the spt. */
        spt_insert_page(spt, Page);

        return true;
    }
err:
    return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page(struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    struct page *page = NULL;
    struct page p;
    p.va = pg_round_down(va);
    struct hash_elem *e = hash_find(&spt->table, &p.hash_elem);
    if (e == NULL) {
        return NULL;
    }
    page = hash_entry(e, struct page, hash_elem);

    return page;
}

/* Insert PAGE into spt with validation. */
bool spt_insert_page(struct supplemental_page_table *spt UNUSED, struct page *page UNUSED) {
    return hash_insert(&spt->table, &page->hash_elem);
}

void remove_page_group(struct page_group *page_group, struct page *page) {
    lock_acquire(&page_group->lock);
    pml4_clear_page(page->pml4, page->va);

    if (list_size(&page_group->page_list) == 1) {
        lock_release(&page_group->lock);
        if (page_group->frame != NULL) {
            vm_free_frame(page_group->frame);
        }
        free(page_group);
        return;
    } else {
        if (page_group->frame == NULL) {
            if (list_front(&page_group->page_list) == &page->list_elem &&
                page->operations->type == VM_ANON) {
                struct page *p = list_entry(list_next(&page->list_elem), struct page, list_elem);
                p->anon = page->anon;
            }
        }
        list_remove(&page->list_elem);
        lock_release(&page_group->lock);
    }
}

void spt_remove_page(struct supplemental_page_table *spt, struct page *page) {
    struct page_group *page_group = page->page_group;
    void *va = page->va;

    // hash 테이블에서 제거
    struct hash_elem *e = hash_delete(&spt->table, &page->hash_elem);

    vm_dealloc_page(page);
}

/* Get the struct frame, that will be evicted. */
static struct frame *vm_get_victim(void) {
    struct frame *victim;
    for (int i = 0; i <= user_pages; i++) {
        victim = &(frame_table[next++]);
        if (next >= user_pages) {
            next = 0;
        }
        if (victim->avoid_swap == true) {
            continue;
        }
        lock_acquire(&victim->page_group->lock);
        struct page *p =
            list_entry(list_back(&victim->page_group->page_list), struct page, list_elem);
        if (pml4_is_accessed(p->pml4, p->va)) {
            pml4_set_accessed(p->pml4, p->va, false);
            lock_release(&victim->page_group->lock);
            continue;
        }
        lock_release(&victim->page_group->lock);

        return victim;
    }
    return NULL;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *vm_evict_frame(void) {
    struct frame *victim = vm_get_victim();
    /*  swap out the victim and return the evicted frame. */
    struct list_elem *e = list_begin(&victim->page_group->page_list);
    if (!swap_out(list_entry(e, struct page, list_elem))) {
        NOT_REACHED();
    }
    lock_acquire(&victim->page_group->lock);
    vm_dealloc_pte(&victim->page_group->page_list);
    lock_release(&victim->page_group->lock);
    victim->page_group->frame = NULL;
    victim->page_group = NULL;
    return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *vm_get_frame(void) {
    struct frame *frame = NULL;
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage == NULL) {
        // swapping
        return vm_evict_frame();
    }
    frame = &frame_table[pg_no(kpage) - pg_no(user_pool_base)];
    ASSERT(frame != NULL);
    frame->kva = kpage;
    return frame;
}

void vm_dealloc_pte(struct list *page_list) {
    for (struct list_elem *e = list_begin(page_list); e != list_end(page_list); e = list_next(e)) {
        struct page *p = list_entry(e, struct page, list_elem);
        pml4_clear_page(p->pml4, p->va);
    }
}

void vm_free_frame(struct frame *frame) {
    lock_acquire(&frame->page_group->lock);
    vm_dealloc_pte(&frame->page_group->page_list);
    frame->page_group->frame = NULL;
    lock_release(&frame->page_group->lock);
    frame->page_group = NULL;
    frame->avoid_swap = false;
    palloc_free_page(frame->kva);
}

/* Growing the stack. */
static void vm_stack_growth(void *addr UNUSED) {
    vm_alloc_page(VM_ANON, pg_round_down(addr), true);
}

/* Handle the fault on write_protected page */
static bool vm_handle_wp(struct page *page UNUSED) {
    struct page_group *old_page_group = page->page_group;
    lock_acquire(&old_page_group->lock);
    if (list_size(&page->page_group->page_list) > 1) {
        struct page_group *new_page_group;
        if ((new_page_group = init_page_group()) == NULL) {
            return false;
        }

        old_page_group->frame->avoid_swap = true;
        struct frame *new_frame = vm_get_frame();
        old_page_group->frame->avoid_swap = false;
        new_page_group->frame = new_frame;
        new_frame->page_group = new_page_group;
        memcpy(new_frame->kva, old_page_group->frame->kva, PGSIZE);

        list_remove(&page->list_elem);
        list_push_back(&new_page_group->page_list, &page->list_elem);
        page->page_group = new_page_group;
    }
    lock_release(&old_page_group->lock);
    pml4_set_perm(page->pml4, page->va, true, PTE_W);
    return true;
}

static bool vm_check_stack_growth(void *addr) {
    // pushq 명령어의 경우 최대 8 까지만 내려감(레지스터 크기가 8)
    return (addr >= thread_current()->saved_user_rsp - 8 && addr < USER_STACK &&
            addr >= USER_STACK - (1 << 20));
}

/* Return true on success */
bool vm_try_handle_fault(struct intr_frame *f UNUSED, void *addr UNUSED, bool user UNUSED,
                         bool write UNUSED, bool not_present UNUSED) {
    // struct supplemental_page_table *spt UNUSED = &thread_current()->spt;
    // struct page *page = NULL;
    /* Validate the fault */
    if (!check_user_addr_valid(addr)) {
        return false;
    }

    // spt 보고 stack groth 판단
    struct page *page = NULL;
    page = spt_find_page(&thread_current()->spt, pg_round_down(addr));
    if (page == NULL) {
        if (vm_check_stack_growth(addr)) {
            vm_stack_growth(pg_round_down(addr));
            page = spt_find_page(&thread_current()->spt, pg_round_down(addr));
        }
        if (page == NULL) {
            return false;
        }
    }
    // COW 때 고쳐야 함
    if (!not_present) {
        if (!(write && page->writable)) {
            return false;
        }
        if (!vm_handle_wp(page)) {
            return false;
        }
    }
    return vm_do_claim_page(page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void vm_dealloc_page(struct page *page) {
    destroy(page);
    free(page);
}

/* Claim the page that allocate on VA. */
bool vm_claim_page(void *va UNUSED) {
    // TODO: 여기에는 주소 검증이 없어도 될까?
    struct page *page = NULL;
    page = spt_find_page(&thread_current()->spt, va);
    if (page == NULL) {
        return false;
    }

    return vm_do_claim_page(page);
}

/* Claim the PAGE and set up the mmu. */
static bool vm_do_claim_page(struct page *page) {
    bool already_exist = true;
    if (page == NULL) {
        return false;
    }

    if (page->page_group == NULL) {
        if ((page->page_group = init_page_group()) == NULL) {
            return false;
        }
        list_push_back(&page->page_group->page_list, &page->list_elem);
    }

    if (page->page_group->frame == NULL) {
        page->page_group->frame = vm_get_frame();
        /* Set links */
        page->page_group->frame->page_group = page->page_group;
        already_exist = false;
    }

    /* Insert page table entry to map page's VA to frame's PA. */
    if (!pml4_set_page(page->pml4, page->va, page->page_group->frame->kva,
                       page->writable && list_size(&page->page_group->page_list) == 1)) {
        return false;
    }
    if (!already_exist) {
        return swap_in(page, page->page_group->frame->kva);
    }
    return true;
}

/* Initialize new supplemental page table */
void supplemental_page_table_init(struct supplemental_page_table *spt UNUSED) {
    if (!hash_init(&spt->table, page_hash, page_less, spt)) {
        PANIC("!!왜 말록함? 진짜 킹받네!!\n");
    }
}

static bool anon_init_for_cp(struct page *page, void *aux) {
    if (page->page_group->frame == NULL) {
        struct page *front =
            list_entry(list_front(&page->page_group->page_list), struct page, list_elem);
        return swap_in(front, front->va);
    }
    return true;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
                                  struct supplemental_page_table *src UNUSED) {
    struct hash_iterator it;
    struct page *src_page, *dst_page;
    hash_first(&it, &src->table);
    while (hash_next(&it)) {
        dst_page = NULL;
        src_page = hash_entry(hash_cur(&it), struct page, hash_elem);
        if ((dst_page = malloc(sizeof(struct page))) == NULL) {
            return false;
        }

        switch (src_page->operations->type) {
            case VM_UNINIT:
                // void *aux = NULL;
                // if (src_page->uninit.aux) {
                //     size_t *size = src_page->uninit.aux;
                //     // TODO : 자식은 어디서 free하지?
                //     if ((aux = malloc(*size)) == NULL) {
                //         goto copy_err;
                //     }
                //     memcpy(aux, src_page->uninit.aux, *size);
                // }
                uninit_new(dst_page, src_page->va, anon_init_for_cp, src_page->uninit.type, NULL,
                           src_page->uninit.page_initializer);
                copy_base_init(&dst->table, dst_page, src_page);
                break;
            case VM_ANON:
                if (!copy_anon_page(&dst->table, dst_page, src_page)) {
                    goto copy_err;
                }
                break;
            case FILE:
                if (!copy_file_page(&dst->table, dst_page, src_page)) {
                    goto copy_err;
                }
                break;
            default:
                goto copy_err;
        }
    }
    return true;
copy_err:
    return false;
}

/* Free the resource hold by the supplemental page table */
void supplemental_page_table_kill(struct supplemental_page_table *spt UNUSED) {
    /* Destroy all the supplemental_page_table hold by thread and
     * writeback all the modified contents to the storage. */
    hash_destroy(&spt->table, page_delete);
}

void page_delete(struct hash_elem *e, void *aux) {
    struct page *p = hash_entry(e, struct page, hash_elem);
    vm_dealloc_page(p);
}

unsigned page_hash(const struct hash_elem *p_, void *aux) {
    const struct page *p = hash_entry(p_, struct page, hash_elem);
    return hash_bytes(&p->va, sizeof p->va);
}

bool page_less(const struct hash_elem *a_, const struct hash_elem *b_, void *aux) {
    const struct page *a = hash_entry(a_, struct page, hash_elem);
    const struct page *b = hash_entry(b_, struct page, hash_elem);
    return a->va < b->va;
}

static void page_init(struct page *page, bool writable, struct hash *hash) {
    page->writable = writable;
    page->pml4 = thread_current()->pml4;
    hash_insert(hash, &page->hash_elem);
}

// dst는 무조건 current의 page여야 함
bool copy_base_init(struct hash *hash, struct page *dst_page, struct page *src_page) {
    page_init(dst_page, src_page->writable, hash);
    if (src_page->page_group == NULL) {
        if ((src_page->page_group = init_page_group()) == NULL) {
            return false;
        }
        list_push_back(&src_page->page_group->page_list, &src_page->list_elem);
    }
    lock_acquire(&src_page->page_group->lock);
    list_push_back(&src_page->page_group->page_list, &dst_page->list_elem);
    lock_release(&src_page->page_group->lock);
    dst_page->page_group = src_page->page_group;
}

static struct page_group *init_page_group() {
    struct page_group *page_group = NULL;
    if ((page_group = malloc(sizeof(struct page_group))) == NULL) {
        return NULL;
    }
    list_init(&page_group->page_list);
    page_group->frame = NULL;
    lock_init(&page_group->lock);
    return page_group;
}