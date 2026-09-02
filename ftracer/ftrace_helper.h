// ftrace_helper.h
#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

// Helper to look up symbols, required on recent kernels
static unsigned long lookup_name(const char *name) {
    struct kprobe kp = {.symbol_name = name};
    if (register_kprobe(&kp) < 0) return 0;
    unregister_kprobe(&kp);
    return (unsigned long)kp.addr;
}

struct ftrace_hook {
    const char *name;
    void *hook;
    void *orig; // This is a pointer to our function pointer variable
    struct ftrace_ops ops;
};

// The ftrace callback function
static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip,
                                  struct ftrace_ops *ops,
                                  struct ftrace_regs *fregs) {
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    // Check if the call is from within our own module to prevent recursion
    if (!within_module(parent_ip, THIS_MODULE)) {
        // This is key: we replace the instruction pointer with our hook function's address.
        // The ftrace_regs struct contains the pt_regs struct.
        fregs->regs.ip = (unsigned long)hook->hook;
    }
}

// Main function to install a single hook
int fh_install_hook(struct ftrace_hook *hook) {
    int err;
    unsigned long address = lookup_name(hook->name);
    if (!address) {
        pr_err("ftrace_helper: unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }

    // This is the critical step: we store the original address
    // in the variable that hook->orig points to.
    *((unsigned long *)hook->orig) = address;

    hook->ops.func = fh_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION | FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, address, 0, 0);
    if (err) {
        pr_err("ftrace_helper: ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        pr_err("ftrace_helper: register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, address, 1, 0); // Clean up
        return err;
    }
    return 0;
}

// Function to remove a hook
void fh_remove_hook(struct ftrace_hook *hook) {
    int err;
    err = unregister_ftrace_function(&hook->ops);
    if (err) {
        pr_err("ftrace_helper: unregister_ftrace_function() failed: %d\n", err);
    }
    err = ftrace_set_filter_ip(&hook->ops, lookup_name(hook->name), 1, 0);
    if (err) {
        pr_err("ftrace_helper: ftrace_set_filter_ip() cleanup failed: %d\n", err);
    }
}

// Helper functions for installing/removing multiple hooks
int fh_install_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) {
        if (fh_install_hook(&hooks[i])) {
            while (i--) fh_remove_hook(&hooks[i]); // Rollback on error
            return -1;
        }
    }
    return 0;
}

void fh_remove_hooks(struct ftrace_hook *hooks, size_t count) {
    size_t i;
    for (i = 0; i < count; i++) fh_remove_hook(&hooks[i]);
}

#define HOOK(_name, _hook, _orig) \
  { .name = (_name), .hook = (_hook), .orig = (_orig) }

#endif
