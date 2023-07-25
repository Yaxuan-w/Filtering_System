#include <linux/seccomp.h>

static int install_filter(int nr, int arch, int error) {
    struct sock_filter filter[] = {
        /* 
        BPF_LD: Load data from memory to registers.
        BPF_JMP: Jump to the specified location according to the condition.
        BPF_RET: Return and terminate the filtering process.
        */
        // Load the value of the `arch` in the `seccomp_data` into the register
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
        // Compare `arch` with constant, jump to the next instruction (offset0), otherwise jump to the 4th instruction (offset3)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 3),
        // Load the value of the `nr` in the `seccomp_data` into the register
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
        // Compare `nr` with constant, jump to the next instruction (offset0), otherwise jump to the 6th instruction (offset1)
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 1),
        // Return erro
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
        // Allow
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return 1;
    }
    // Apply seccomp policy
    if (prctl(PR_SET_SECCOMP, 2, &prog)) {
        return 1;
    }
    return 0;
}

static int revoke_seccomp_manipulation(int error) {
    int nr = __NR_prctl;
    int arch = AUDIT_ARCH_X86_64;
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, arch))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, arch, 0, 5),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, nr))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, nr, 0, 3),
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offsetof(struct seccomp_data, args[0]))),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, PR_SET_SECCOMP, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (error & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        return 1;
    }
    if (prctl(PR_SET_SECCOMP, 2, &prog)) {
        return 1;
    }
    return 0;
}