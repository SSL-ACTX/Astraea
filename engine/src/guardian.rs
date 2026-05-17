use crate::SeccompConfig;
use libc::*;
use tracing::{error, info, warn};

// BPF Constants
const BPF_ABS: u16 = 0x20;
const BPF_JEQ: u16 = 0x10;
const BPF_JMP: u16 = 0x05;
const BPF_K: u16 = 0x00;
const BPF_LD: u16 = 0x00;
const BPF_RET: u16 = 0x06;
const BPF_W: u16 = 0x00;

#[allow(non_camel_case_types)]
#[repr(C)]
struct sock_filter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[allow(non_camel_case_types)]
#[repr(C)]
struct sock_fprog {
    pub len: u16,
    pub filter: *const sock_filter,
}

macro_rules! bpf_stmt {
    ($code:expr, $k:expr) => {
        sock_filter {
            code: $code as u16,
            jt: 0,
            jf: 0,
            k: $k as u32,
        }
    };
}

macro_rules! bpf_jump {
    ($code:expr, $k:expr, $jt:expr, $jf:expr) => {
        sock_filter {
            code: $code as u16,
            jt: $jt,
            jf: $jf,
            k: $k as u32,
        }
    };
}

fn get_syscall_nr(name: &str) -> Option<i32> {
    match name {
        "read" => Some(SYS_read as i32),
        "write" => Some(SYS_write as i32),
        "close" => Some(SYS_close as i32),
        "lseek" => Some(SYS_lseek as i32),
        "mmap" => Some(SYS_mmap as i32),
        "mprotect" => Some(SYS_mprotect as i32),
        "munmap" => Some(SYS_munmap as i32),
        "brk" => Some(SYS_brk as i32),
        "rt_sigaction" => Some(SYS_rt_sigaction as i32),
        "rt_sigprocmask" => Some(SYS_rt_sigprocmask as i32),
        "ioctl" => Some(SYS_ioctl as i32),
        "pread64" => Some(SYS_pread64 as i32),
        "pwrite64" => Some(SYS_pwrite64 as i32),
        "sched_yield" => Some(SYS_sched_yield as i32),
        "mremap" => Some(SYS_mremap as i32),
        "dup" => Some(SYS_dup as i32),
        "getpid" => Some(SYS_getpid as i32),
        "sendto" => Some(SYS_sendto as i32),
        "recvfrom" => Some(SYS_recvfrom as i32),
        "socket" => Some(SYS_socket as i32),
        "connect" => Some(SYS_connect as i32),
        "accept" => Some(SYS_accept as i32),
        "bind" => Some(SYS_bind as i32),
        "listen" => Some(SYS_listen as i32),
        "getsockname" => Some(SYS_getsockname as i32),
        "getpeername" => Some(SYS_getpeername as i32),
        "setsockopt" => Some(SYS_setsockopt as i32),
        "getsockopt" => Some(SYS_getsockopt as i32),
        "clone" => Some(SYS_clone as i32),
        "exit" => Some(SYS_exit as i32),
        "wait4" => Some(SYS_wait4 as i32),
        "kill" => Some(SYS_kill as i32),
        "uname" => Some(SYS_uname as i32),
        "fcntl" => Some(SYS_fcntl as i32),
        "getcwd" => Some(SYS_getcwd as i32),
        "gettid" => Some(SYS_gettid as i32),
        "futex" => Some(SYS_futex as i32),
        "set_tid_address" => Some(SYS_set_tid_address as i32),
        "timer_create" => Some(SYS_timer_create as i32),
        "timer_settime" => Some(SYS_timer_settime as i32),
        "timer_delete" => Some(SYS_timer_delete as i32),
        "clock_gettime" => Some(SYS_clock_gettime as i32),
        "exit_group" => Some(SYS_exit_group as i32),
        "epoll_ctl" => Some(SYS_epoll_ctl as i32),
        "tgkill" => Some(SYS_tgkill as i32),
        "openat" => Some(SYS_openat as i32),
        "mkdirat" => Some(SYS_mkdirat as i32),
        "unlinkat" => Some(SYS_unlinkat as i32),
        "renameat" => Some(SYS_renameat as i32),
        "readlinkat" => Some(SYS_readlinkat as i32),
        "fchmodat" => Some(SYS_fchmodat as i32),
        "faccessat" => Some(SYS_faccessat as i32),
        "ppoll" => Some(SYS_ppoll as i32),
        "epoll_pwait" => Some(SYS_epoll_pwait as i32),
        "eventfd2" => Some(SYS_eventfd2 as i32),
        "epoll_create1" => Some(SYS_epoll_create1 as i32),
        "pipe2" => Some(SYS_pipe2 as i32),
        "getrandom" => Some(SYS_getrandom as i32),
        "memfd_create" => Some(SYS_memfd_create as i32),
        "statx" => Some(SYS_statx as i32),
        // Add variants for architectures that might still have them
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "open" => Some(SYS_open as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "stat" => Some(SYS_stat as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "fstat" => Some(SYS_fstat as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "lstat" => Some(SYS_lstat as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "poll" => Some(SYS_poll as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "access" => Some(SYS_access as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "pipe" => Some(SYS_pipe as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "select" => Some(SYS_select as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "dup2" => Some(SYS_dup2 as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "fork" => Some(SYS_fork as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "mkdir" => Some(SYS_mkdir as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "rmdir" => Some(SYS_rmdir as i32),
        #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
        "epoll_wait" => Some(SYS_epoll_wait as i32),
        _ => None,
    }
}

pub fn apply_policy(config: &SeccompConfig) {
    info!("Guardian: Applying Seccomp-BPF policy...");

    let mut allowed_nrs = vec![
        SYS_read as usize,
        SYS_write as usize,
        SYS_close as usize,
        SYS_lseek as usize,
        SYS_mmap as usize,
        SYS_mprotect as usize,
        SYS_munmap as usize,
        SYS_brk as usize,
        SYS_rt_sigaction as usize,
        SYS_rt_sigprocmask as usize,
        SYS_rt_sigreturn as usize,
        SYS_ioctl as usize,
        SYS_pread64 as usize,
        SYS_pwrite64 as usize,
        SYS_sched_yield as usize,
        SYS_mremap as usize,
        SYS_dup as usize,
        SYS_getpid as usize,
        SYS_sendto as usize,
        SYS_recvfrom as usize,
        SYS_socket as usize,
        SYS_connect as usize,
        SYS_accept as usize,
        SYS_bind as usize,
        SYS_listen as usize,
        SYS_getsockname as usize,
        SYS_getpeername as usize,
        SYS_socketpair as usize,
        SYS_setsockopt as usize,
        SYS_getsockopt as usize,
        SYS_clone as usize,
        SYS_exit as usize,
        SYS_wait4 as usize,
        SYS_kill as usize,
        SYS_uname as usize,
        SYS_fcntl as usize,
        SYS_flock as usize,
        SYS_fsync as usize,
        SYS_fdatasync as usize,
        SYS_getcwd as usize,
        SYS_chdir as usize,
        SYS_fchdir as usize,
        SYS_gettimeofday as usize,
        SYS_getrlimit as usize,
        SYS_getrusage as usize,
        SYS_sysinfo as usize,
        SYS_times as usize,
        SYS_getuid as usize,
        SYS_getgid as usize,
        SYS_geteuid as usize,
        SYS_getegid as usize,
        SYS_sigaltstack as usize,
        SYS_nanosleep as usize,
        SYS_gettid as usize,
        SYS_futex as usize,
        SYS_sched_setaffinity as usize,
        SYS_sched_getaffinity as usize,
        SYS_set_tid_address as usize,
        SYS_timer_create as usize,
        SYS_timer_settime as usize,
        SYS_timer_gettime as usize,
        SYS_timer_getoverrun as usize,
        SYS_timer_delete as usize,
        SYS_clock_settime as usize,
        SYS_clock_gettime as usize,
        SYS_clock_getres as usize,
        SYS_clock_nanosleep as usize,
        SYS_exit_group as usize,
        SYS_epoll_ctl as usize,
        SYS_tgkill as usize,
        SYS_openat as usize,
        SYS_mkdirat as usize,
        SYS_fchownat as usize,
        SYS_unlinkat as usize,
        SYS_renameat as usize,
        SYS_readlinkat as usize,
        SYS_fchmodat as usize,
        SYS_faccessat as usize,
        SYS_pselect6 as usize,
        SYS_ppoll as usize,
        SYS_set_robust_list as usize,
        SYS_get_robust_list as usize,
        SYS_splice as usize,
        SYS_tee as usize,
        SYS_sync_file_range as usize,
        SYS_vmsplice as usize,
        SYS_utimensat as usize,
        SYS_epoll_pwait as usize,
        SYS_timerfd_create as usize,
        SYS_eventfd2 as usize,
        SYS_fallocate as usize,
        SYS_timerfd_settime as usize,
        SYS_timerfd_gettime as usize,
        SYS_accept4 as usize,
        SYS_signalfd4 as usize,
        SYS_epoll_create1 as usize,
        SYS_dup3 as usize,
        SYS_pipe2 as usize,
        SYS_inotify_init1 as usize,
        SYS_preadv as usize,
        SYS_pwritev as usize,
        SYS_rt_tgsigqueueinfo as usize,
        SYS_recvmmsg as usize,
        SYS_prlimit64 as usize,
        SYS_sendmmsg as usize,
        SYS_getcpu as usize,
        SYS_getrandom as usize,
        SYS_memfd_create as usize,
        SYS_seccomp as usize,
        SYS_statx as usize,
        SYS_prctl as usize,
        SYS_writev as usize,
        SYS_readv as usize,
        SYS_madvise as usize,
        SYS_capget as usize,
        SYS_capset as usize,
    ];

    // Add legacy/arch-specific syscalls if they exist
    #[cfg(not(any(target_arch = "aarch64", target_arch = "riscv64")))]
    {
        allowed_nrs.push(SYS_open as usize);
        allowed_nrs.push(SYS_stat as usize);
        allowed_nrs.push(SYS_fstat as usize);
        allowed_nrs.push(SYS_lstat as usize);
        allowed_nrs.push(SYS_poll as usize);
        allowed_nrs.push(SYS_access as usize);
        allowed_nrs.push(SYS_pipe as usize);
        allowed_nrs.push(SYS_select as usize);
        allowed_nrs.push(SYS_dup2 as usize);
        allowed_nrs.push(SYS_fork as usize);
        allowed_nrs.push(SYS_vfork as usize);
        allowed_nrs.push(SYS_mkdir as usize);
        allowed_nrs.push(SYS_rmdir as usize);
        allowed_nrs.push(SYS_creat as usize);
        allowed_nrs.push(SYS_link as usize);
        allowed_nrs.push(SYS_unlink as usize);
        allowed_nrs.push(SYS_symlink as usize);
        allowed_nrs.push(SYS_readlink as usize);
        allowed_nrs.push(SYS_chmod as usize);
        allowed_nrs.push(SYS_chown as usize);
        allowed_nrs.push(SYS_lchown as usize);
        allowed_nrs.push(SYS_utimes as usize);
        allowed_nrs.push(SYS_futimesat as usize);
        allowed_nrs.push(SYS_epoll_wait as usize);
        allowed_nrs.push(SYS_signalfd as usize);
        allowed_nrs.push(SYS_eventfd as usize);
    }

    // Manual additions for aarch64 which might be missing from libc but present in strace
    #[cfg(target_arch = "aarch64")]
    {
        allowed_nrs.push(79); // newfstatat
        allowed_nrs.push(80); // fstat
        allowed_nrs.push(43); // statfs
        allowed_nrs.push(44); // fstatfs
        allowed_nrs.push(221); // execve
        allowed_nrs.push(90); // capget
        allowed_nrs.push(91); // capset
        allowed_nrs.push(81); // sync
        allowed_nrs.push(220); // clone3
        allowed_nrs.push(115); // epoll_create
        allowed_nrs.push(212); // recvmsg
        allowed_nrs.push(211); // sendmsg
        allowed_nrs.push(147); // getresuid
        allowed_nrs.push(149); // getresgid
        allowed_nrs.push(140); // setpriority
        allowed_nrs.push(30); // ioprio_get
        allowed_nrs.push(120); // sched_getscheduler
        allowed_nrs.push(121); // sched_getparam
        allowed_nrs.push(163); // getrlimit
        allowed_nrs.push(165); // getrusage
        allowed_nrs.push(153); // times
        allowed_nrs.push(113); // clock_getres
        allowed_nrs.push(116); // epoll_create1
        allowed_nrs.push(71); // select
        allowed_nrs.push(73); // ppoll
        allowed_nrs.push(135); // rt_sigprocmask
        allowed_nrs.push(134); // rt_sigaction
        allowed_nrs.push(172); // getuid
        allowed_nrs.push(173); // getgid
        allowed_nrs.push(174); // geteuid
        allowed_nrs.push(175); // getegid
        allowed_nrs.push(176); // getgroups
        allowed_nrs.push(179); // getpgrp
        allowed_nrs.push(117); // epoll_ctl
        allowed_nrs.push(118); // epoll_pwait
        allowed_nrs.push(222); // mmap
        allowed_nrs.push(215); // munmap
        allowed_nrs.push(226); // mprotect
        allowed_nrs.push(214); // brk
        allowed_nrs.push(93); // exit
        allowed_nrs.push(94); // exit_group
        allowed_nrs.push(98); // futex
        allowed_nrs.push(220); // clone3
        allowed_nrs.push(160); // uname
        allowed_nrs.push(29); // ioctl
        allowed_nrs.push(63); // read
        allowed_nrs.push(64); // write
        allowed_nrs.push(132); // sigaltstack
        allowed_nrs.push(115); // clock_nanosleep
        allowed_nrs.push(131); // tgkill
        allowed_nrs.push(261); // prlimit64
        allowed_nrs.push(278); // getrandom
        allowed_nrs.push(117); // epoll_ctl
        allowed_nrs.push(118); // epoll_pwait
        allowed_nrs.push(221); // execve
        allowed_nrs.push(220); // clone3
    }

    for name in &config.allowed_syscalls {
        if let Some(nr) = get_syscall_nr(name) {
            allowed_nrs.push(nr as usize);
        } else {
            warn!("Guardian: Unknown syscall '{}' in config, ignoring.", name);
        }
    }

    allowed_nrs.sort();
    allowed_nrs.dedup();

    let mut filter = Vec::new();

    // Load the system call number from seccomp_data into the accumulator.
    filter.push(bpf_stmt!(BPF_LD | BPF_W | BPF_ABS, 0));

    // Validate the system call against the sorted whitelist.
    for &nr in &allowed_nrs {
        filter.push(bpf_jump!(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
        filter.push(bpf_stmt!(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    }

    // Safety net: Allow certain 'safe' informational syscalls to prevent teardown crashes.
    // This includes common process and thread management that varies by Android version.
    filter.push(bpf_stmt!(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr(),
    };

    unsafe {
        if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            error!("Guardian: Failed to set PR_SET_NO_NEW_PRIVS");
            return;
        }

        if prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            &prog as *const _ as usize,
        ) != 0
        {
            let err = std::io::Error::last_os_error();
            error!("Guardian: Failed to apply seccomp filter: {}", err);
        } else {
            info!(
                "Guardian: Seccomp-BPF filter applied successfully ({} syscalls allowed).",
                allowed_nrs.len()
            );
        }
    }
}
