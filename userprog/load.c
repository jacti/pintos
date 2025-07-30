#include <round.h>
#include <stdio.h>
#include <string.h>

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/file_abstract.h"
#include "userprog/file_descriptor.h"
#include "userprog/process.h"
#include "userprog/process_impl.h"

// vm 때 include 오류나면 해제할 것
//  #include "filesys/directory.h"
//  #include "filesys/file.h"
//  #include "filesys/filesys.h"
//  #include "intrinsic.h"
// #include "threads/init.h"
// #include "threads/interrupt.h"
// #include "threads/synch.h"
// #include "userprog/gdt.h"

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

// 선정의

/**
 * @brief ELF 실행 파일을 열고 헤더를 읽어 검증한 후 파일 디스크립터를 반환합니다.
 * @param file_name 열고자 하는 ELF 실행 파일의 경로
 * @param ehdr      ELF 헤더 정보를 저장할 구조체 포인터
 * @return 성공 시 열린 파일의 `File *`, 실패 시 `NULL`
 */
static inline struct File *load_file(const char *file_name, struct ELF *ehdr);

/**
 * @brief 실행 인자 문자열을 파싱하여 스택 및 레지스터에 설정합니다.
 * @param file_name 프로그램 실행 파일 이름
 * @param args      공백으로 구분된 실행 인자 문자열
 * @param if_       인터럽트 프레임 구조체. `rsp` 및 레지스터 `R.rdi`, `R.rsi`가 업데이트됩니다.
 * @return 인자 파싱 및 스택 푸시 성공 시 true, 실패 시 false
 */
static inline bool arg_parse(const char *file_name, char *args, struct intr_frame *if_);
static bool validate_segment(const struct Phdr *phdr, struct file *file);
#ifndef VM
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);
static bool setup_stack(struct intr_frame *if_);
#else
static bool lazy_load_segment(struct page *page, void *aux);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);
static bool setup_stack(struct intr_frame *if_);
#endif /* VM */

/**
 * @details
 * - `pml4_create`로 새로운 페이지 디렉토리를 생성하고 활성화합니다.
 * - `load_file`을 호출해 ELF 파일을 열고 프로그램 헤더를 메모리에 매핑합니다.
 * - `setup_stack`으로 초기 사용자 스택 한 페이지를 할당 받습니다.
 * - `if_->rip`에 ELF 헤더의 진입점(`ehdr.e_entry`)을 설정합니다.
 * - `arg_parse`로 명령줄 인자를 스택과 레지스터(`R.rdi`, `R.rsi`)에 설정합니다.
 * - `file_deny_write`로 실행 중인 파일에 쓰기를 금지하고, `set_fd`로 파일 디스크립터를 등록합니다.
 * - 어느 단계에서든 실패하면 열린 파일을 닫고 `false`를 반환합니다.
 *
 * @warning
 * - 실행파일의 이름이 정확해야하고, 메모리에 할당가능한 여유가 있어야 합니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
bool load(const char *file_name, char *args, struct intr_frame *if_) {
    struct thread *t = thread_current();
    struct File *file;
    struct ELF ehdr;

    /* Allocate and activate page directory. */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto error;
    process_activate(thread_current());

    // open excutable file and load
    if ((file = load_file(file_name, &ehdr)) == NULL) {
        goto error;
    }

    /* Set up stack. */
    if (!setup_stack(if_))
        goto error;

    /* Start address. */
    if_->rip = ehdr.e_entry;

    if (!arg_parse(file_name, args, if_)) {
        goto error;
    }

    file_deny_write(file->file_ptr);
    int fd = set_fd(file);
    if (fd == -1) {
        goto error;
    }
    return true;
error:
    if (file != NULL) {
        close_file(file);
    }
    return false;
}

/* Source 파일용 (`process.c` 또는 `load.c`) */
/**
 * @details
 * - `open_file`로 실행 파일을 열고 ELF 헤더를 검증합니다.
 * - 프로그램 헤더를 순회하며 `PT_LOAD` 세그먼트만 `load_segment`로 메모리에 매핑합니다.
 * - 매핑 중 오류가 발생하면 파일을 닫고 `NULL`을 반환합니다.
 *
 * @warning
 * - `ehdr->e_phnum`이 과도하게 크거나(`>1024`),
 *   파일 오프셋(`e_phoff`)이 파일 길이를 벗어나는 경우 즉시 실패 처리됩니다.
 * - 헤더 검증 및 세그먼트 매핑 중 오류 발생 시 파일을 반드시 닫고 `NULL`을 반환합니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
static inline struct File *load_file(const char *file_name, struct ELF *ehdr) {
    struct File *fd = NULL;
    struct file *file = NULL;
    off_t file_ofs;
    int i;

    /* Open executable file. */
    fd = open_file(file_name);
    if (fd == NULL) {
        printf("load: %s: open failed\n", file_name);
        return NULL;
    }
    file = fd->file_ptr;

    /* Read and verify executable header. */
    if (file_read(file, ehdr, sizeof *ehdr) != sizeof *ehdr ||
        memcmp(ehdr->e_ident, "\177ELF\2\1\1", 7) || ehdr->e_type != 2 ||
        ehdr->e_machine != 0x3E  // amd64
        || ehdr->e_version != 1 || ehdr->e_phentsize != sizeof(struct Phdr) ||
        ehdr->e_phnum > 1024) {
        printf("load: %s: error loading executable\n", file_name);
        close_file(fd);
        return NULL;
    }

    /* Read program headers. */
    file_ofs = ehdr->e_phoff;
    for (i = 0; i < ehdr->e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file)) {
            close_file(fd);
            return NULL;
        }
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr) {
            close_file(fd);
            return NULL;
        }
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
            case PT_NULL:
            case PT_NOTE:
            case PT_PHDR:
            case PT_STACK:
            default:
                /* Ignore this segment. */
                break;
            case PT_DYNAMIC:
            case PT_INTERP:
            case PT_SHLIB:
                close_file(fd);
                return NULL;
            case PT_LOAD:
                if (validate_segment(&phdr, file)) {
                    bool writable = (phdr.p_flags & PF_W) != 0;
                    uint64_t file_page = phdr.p_offset & ~PGMASK;
                    uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                    uint64_t page_offset = phdr.p_vaddr & PGMASK;
                    uint32_t read_bytes, zero_bytes;
                    if (phdr.p_filesz > 0) {
                        /* Normal segment.
                         * Read initial part from disk and zero the rest. */
                        read_bytes = page_offset + phdr.p_filesz;
                        zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                    } else {
                        /* Entirely zero.
                         * Don't read anything from disk. */
                        read_bytes = 0;
                        zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                    }
                    if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes,
                                      writable)) {
                        close_file(fd);
                        return NULL;
                    }
                } else {
                    close_file(fd);
                    return NULL;
                }
                break;
        }
    }
    return fd;
}

/**
 * @details
 * - 입력된 문자열 `args`를 공백 단위로 분리하여 `argv` 배열에 저장합니다.
 * - 각 인자를 스택에 푸시하고, 8바이트 정렬을 위해 필요한 만큼 패딩을 추가합니다.
 * - 인자 포인터 배열을 스택에 푸시한 후 `argc`와 `argv` 시작 주소를
 *   `if_->R.rdi`와 `if_->R.rsi`에 설정합니다.
 *
 * @warning
 * - `LOADER_ARGS_LEN`에 따라 최대 인자 수와 스택 사용량이 제한됩니다.
 * - `args`가 NULL이거나 길이가 너무 길면 예기치 않은 동작이 발생할 수 있습니다.
 *
 * @branch feat/refactoring
 * @see   https://www.notion.so/jactio/23ec9595474e803a8299dbbc5655fc56?source=copy_link
 */
static inline bool arg_parse(const char *file_name, char *args, struct intr_frame *if_) {
    //  $feat/arg-parse
    char *argv[LOADER_ARGS_LEN / 2];
    uintptr_t stack_ptr[LOADER_ARGS_LEN / 2];
    argv[0] = file_name;
    uint8_t argc = 1;
    char *save_ptr = NULL;
    argv[argc] = strtok_r(args, " ", &save_ptr);
    while (argv[argc] != NULL) {
        argv[++argc] = strtok_r(NULL, " ", &save_ptr);
    }

    size_t total_mod8 = 0;
    size_t arg_len;
    for (int i = argc - 1; i >= 0; i--) {
        arg_len = strlen(argv[i]) + 1;
        if ((stack_ptr[i] = push_stack(argv[i], arg_len, if_)) == NULL) {
            return false;
        }
        total_mod8 = (total_mod8 + arg_len) % 8;
    }

    if (push_stack(NULL, (8 - total_mod8) % 8, if_) == NULL) {
        return false;
    }

    if (push_stack(NULL, sizeof(uintptr_t), if_) == NULL) {
        return false;
    };
    for (int i = argc - 1; i >= 0; i--) {
        if (push_stack((char *)(&stack_ptr[i]), sizeof(uintptr_t), if_) == NULL) {
            return false;
        }
    }
    if (push_stack(NULL, sizeof(uintptr_t), if_) == NULL) {
        return false;
    }

    if_->R.rsi = sizeof(uintptr_t) + if_->rsp;
    if_->R.rdi = argc;
    return true;
    //  feat/arg-parse
}

/* Checks whether PHDR describes a valid, loadable segment in
 * FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {
    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

#else
/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        void *aux = NULL;
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */

    return success;
}
#endif /* VM */