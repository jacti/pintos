#include "userprog/syscall.h"

#include <stdio.h>
#include <syscall-nr.h>

#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"

void syscall_entry(void);
void syscall_handler(struct intr_frame*);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kerneål
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */

void syscall_handler(struct intr_frame* f) {
    // // TODO: Your implementation goes here.
    //  enum intr_level old_level = intr_disable();
    // int syscall_num = f->R.rax;

    // switch (syscall_num) {
    //     case SYS_WRITE:
    //         /* code */
    //         write_handler(f->R.rdi, f->R.rsi, f->R.rdx);

    //         intr_set_level(old_level);
    //         break;

    //     default:
    //         //printf("system call!\n");
    //         printf("\n  undifind syscall : %d \n", syscall_num);
    //         thread_exit();

    //         intr_set_level(old_level);
    //         break;
    // }
    
}

//$ADD/write_handler
/**
 * @iizxcv
 * @brief 쓰기 함수 구현. fd를 받아와서 buf에 있는 값을 size 만큼 쓰는 함수임.
 * @see https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c

*/
static int write_handler(size_t fd, char* buf, int size) {  // write의 목적은 buf를 fd에 쓰기해주는 함수
   
    if (is_user_vaddr(buf)) {
        if (fd == stdin) {
            printf("you do wrting stdin. haven't writed at the stdin"); 
        } else if (fd == stdout) {
            putbuf(buf, size);                                          
        } else if (fd > stdout) {
            acquire_console();                                          
            struct file* get_file = get_file_from_fd(fd);
            file_write(get_file, buf, size);
            release_console();
        }
        return size;
    }
}
/**
 * @iizxcv
 * @brief fd-no로 현재 쓰레드에 매핑된 file-table에서 file 주소 가져오기
 * @see https://www.notion.so/jactio/write_handler-233c9595474e804f998de012a4d9a075?source=copy_link#233c9595474e80b8bcd0e4ab9d1fa96c
*/
static struct file* get_file_from_fd(fd) {
    return thread_current()->fdt[fd];
}
//ADD/write_handler
