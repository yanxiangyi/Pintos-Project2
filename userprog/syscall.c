#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"

static void syscall_handler(struct intr_frame *);

//extern bool running;

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int process_write(int fd, const void *buffer, unsigned size)
{
    if (fd == STDOUT_FILENO){
        putbuf((char *)buffer, (size_t)size);
        return (int)size;
    }
    return -1;
}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    int fd;
    int *p = f->esp;
    int system_call = *p;

    switch (system_call) {
        case SYS_WRITE:
            fd = *(int *)(f->esp + 4);
            void *buffer = *(char**)(f->esp + 8);
            unsigned size = *(unsigned *)(f->esp + 12);
            int written_size = process_write(fd, buffer, size);
            int a = thread_current()->parent->tid;
            thread_current()->parent->dead = true;
//            printf("name: %d\n",a);
            break;
        case SYS_HALT:
            shutdown_power_off();

            break;
        case SYS_EXIT:
            thread_current()->dead = true;
            thread_exit();
            break;

        default:
            printf("No match\n");
    }

//    thread_exit();
}