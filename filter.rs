// https://docs.rs/seccompiler/latest/seccompiler/
use seccompiler::BpfMap;
use std::convert::TryInto;

let json_input = r#"{
    "main_thread": {
        "mismatch_action": "trap",
        "match_action": "allow",
        "filter": [
            {
                "syscall": "sysinfo"
            },
            {
                "syscall": "execve"
            },
            {
                "syscall": "prlimit64"
            },
            {
                "syscall": "set_tid_address"
            },
            {
                "syscall": "munmap"
            },
            {
                "syscall": "access"
            },
            {
                "syscall": "getdents64"
            },
            {
                "syscall": "pread64"
            },
            {
                "syscall": "arch_prctl"
            },
            {
                "syscall": "getegid"
            },
            {
                "syscall": "dup2"
            },
            {
                "syscall": "write"
            },
            {
                "syscall": "openat"
            },
            {
                "syscall": "connect"
            },
            {
                "syscall": "brk"
            },
            {
                "syscall": "read"
            },
            {
                "syscall": "lseek"
            },
            {
                "syscall": "getpgrp"
            },
            {
                "syscall": "rt_sigaction"
            },
            {
                "syscall": "close"
            },
            {
                "syscall": "rseq"
            },
            {
                "syscall": "socket"
            },
            {
                "syscall": "getppid"
            },
            {
                "syscall": "chdir"
            },
            {
                "syscall": "mprotect"
            },
            {
                "syscall": "mmap"
            },
            {
                "syscall": "getuid"
            },
            {
                "syscall": "uname"
            },
            {
                "syscall": "getrandom"
            },
            {
                "syscall": "geteuid"
            },
            {
                "syscall": "set_robust_list"
            },
            {
                "syscall": "ioctl"
            },
            {
                "syscall": "fcntl"
            },
            {
                "syscall": "getgid"
            },
            {
                "syscall": "getpid"
            },
            {
                "syscall": "futex"
            },
            {
                "syscall": "clone"
            }
        ]
    }
}"#;

let filter_map: BpfMap = seccompiler::compile_from_json(
    json_input.as_bytes(),
    std::env::consts::ARCH.try_into().unwrap(),
)
.unwrap();
let filter = filter_map.get("main_thread").unwrap();

seccompiler::apply_filter(&filter).unwrap();
