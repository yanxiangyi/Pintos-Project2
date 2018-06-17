#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "devices/input.h"

static void syscall_handler(struct intr_frame *);

void *check_addr(const void *vaddr);

int process_write(int fd, const void *buffer, unsigned size);

struct proc_file *list_search(struct list *files, int fd);

void close_file(struct list *files, int fd);

void close_all_files(struct list *files);

struct proc_file {
    struct file *ptr;
    int fd;
    struct list_elem elem;
};

void *check_addr(const void *vaddr) {
    if (!is_user_vaddr(vaddr)) {
        thread_current()->exit_code = -1;
        thread_exit();
        return 0;
    }
    void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
    if (!pagedir_get_page(thread_current()->pagedir, vaddr)) {
        thread_current()->exit_code = -1;
        thread_exit();
        return 0;
    }
    return ptr;
}

void
syscall_init(void) {
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int process_write(int fd, const void *buffer, unsigned size) {
    if (fd == STDOUT_FILENO) {
        putbuf((char *) buffer, (size_t) size);
        return (int) size;
    } else {
        struct proc_file *fptr = list_search(&thread_current()->files, fd);
        if (fptr == NULL)
            return -1;
        else
            return file_write_at(fptr->ptr, buffer, size, 0);
    }
    return -1;
}

int process_read(int fd, uint8_t *buffer, unsigned size) {
    if (fd == STDIN_FILENO) {
        for (int i = 0; i < size; i++) {
            buffer[i] = input_getc();
        }
        putbuf((char *) buffer, (size_t) size);
        return (int) size;
    } else {
        struct proc_file *fptr = list_search(&thread_current()->files, fd);
        if (fptr == NULL)
            return -1;
        else {
            return file_read_at(fptr->ptr, buffer, size, 0);
        }
    }
}

struct proc_file *list_search(struct list *files, int fd) {
    struct list_elem *e;

    for (e = list_begin(files); e != list_end(files); e = list_next(e)) {
        struct proc_file *f = list_entry (e, struct proc_file, elem);
        if (f->fd == fd) {
            return f;
        }
    }
    return NULL;
}

void close_file(struct list *files, int fd) {
    struct list_elem *e;
    for (e = list_begin(files); e != list_end(files); e = list_next(e)) {
        struct proc_file *f = list_entry (e, struct proc_file, elem);
        if (f->fd == fd) {
            file_close(f->ptr);
            list_remove(e);
        }
    }
}

//void close_all_files(struct list* files){
//    struct list_elem *e;
//    for (e = list_begin (files); e != list_end (files);
//         e = list_next (e)){
//        struct proc_file *f = list_entry (e, struct proc_file, elem);
//        file_close(f->ptr);
//        list_remove(e);
//    }
//}

static void
syscall_handler(struct intr_frame *f UNUSED) {

    int fd;
    void *buffer;
    unsigned size;
    int *p = f->esp;
    check_addr(f->esp);
    int system_call = *p;
    int exit_code;

    switch (system_call) {
        case SYS_HALT:                   /* Halt the operating system. */
            shutdown_power_off();
        case SYS_EXIT:                   /* Terminate this process. */
            check_addr(p + 1);
            exit_code = *(int *) (f->esp + 4);
            thread_current()->exit_code = exit_code;
            thread_exit();

        case SYS_EXEC:                   /* Start another process. */
            check_addr(p + 1);
            check_addr((void *) *(p + 1));
            f->eax = process_execute(*(p + 1));
            break;

        case SYS_WAIT:                   /* Wait for a child process to die. */
            check_addr(p + 1);
            f->eax = process_wait(*(p + 1));
            break;

        case SYS_CREATE:                 /* Create a file. */
            check_addr(p + 2);
            check_addr(p + 1);
            check_addr((void *) *(p + 1));
            f->eax = filesys_create(*(p + 1), *(p + 2));
            break;
        case SYS_REMOVE:                 /* Delete a file. */
            check_addr(p + 1);
            f->eax = filesys_remove(*(p + 1));
            break;
        case SYS_OPEN:                   /* Open a file. */
            check_addr(p + 1);
            check_addr((void *) *(p + 1));
            struct file *fptr = filesys_open(*(p + 1));
            if (fptr == NULL) {
                f->eax = -1;
            } else {
                struct proc_file *pfile = malloc(sizeof(*pfile));
                pfile->ptr = fptr;
                pfile->fd = thread_current()->fd_count;
                thread_current()->fd_count++;
                list_push_back(&thread_current()->files, &pfile->elem);
                f->eax = pfile->fd;
            }
            break;
        case SYS_FILESIZE:               /* Obtain a file's size. */
            check_addr(p + 1);
            f->eax = file_length(list_search(&thread_current()->files, *(p + 1))->ptr);
            break;
        case SYS_READ:                   /* Read from a file. */
            check_addr(p + 3);
            check_addr(p + 2);
            check_addr(p + 1);
            check_addr((void *) *(p + 2));
            fd = *(int *) (f->esp + 4);
            buffer = *(char **) (f->esp + 8);
            size = *(unsigned *) (f->esp + 12);
            f->eax = process_read(fd, buffer, size);
            break;

        case SYS_WRITE:                  /* Write to a file. */
            check_addr(p + 3);
            check_addr(p + 2);
            check_addr(p + 1);
            check_addr((void *) *(p + 2));
            fd = *(int *) (f->esp + 4);
            buffer = *(char **) (f->esp + 8);
            size = *(unsigned *) (f->esp + 12);
            f->eax = process_write(fd, buffer, size);
            break;

        case SYS_SEEK:                   /* Change position in a file. */
            check_addr(p + 2);
            check_addr(p + 1);
            break;
        case SYS_TELL:                   /* Report current position in a file. */
            check_addr(p + 1);
            break;
        case SYS_CLOSE:                  /* Close a file. */
            check_addr(p + 1);
            break;

        default:
            printf("No match\n");
    }
}