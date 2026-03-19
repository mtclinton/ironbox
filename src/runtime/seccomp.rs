use containerd_shim::{other, Error, Result};
use log::debug;
use oci_spec::runtime::{LinuxSeccomp, LinuxSeccompAction, Spec};

// BPF instruction constants
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// seccomp return values
const SECCOMP_RET_KILL_PROCESS: u32 = 0x80000000;
const SECCOMP_RET_KILL_THREAD: u32 = 0x00000000;
const SECCOMP_RET_TRAP: u32 = 0x00030000;
const SECCOMP_RET_ERRNO: u32 = 0x00050000;
const SECCOMP_RET_TRACE: u32 = 0x7ff00000;
const SECCOMP_RET_LOG: u32 = 0x7ffc0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff0000;

// seccomp_data offsets
const OFFSET_NR: u32 = 0;      // syscall number
const OFFSET_ARCH: u32 = 4;    // architecture

// x86_64 audit arch
const AUDIT_ARCH_X86_64: u32 = 0xc000003e;

// seccomp mode
const SECCOMP_SET_MODE_FILTER: u32 = 1;

/// Apply seccomp filters from the OCI spec.
pub fn apply_seccomp(spec: &Spec) -> Result<()> {
    let linux = match spec.linux() {
        Some(l) => l,
        None => return Ok(()),
    };

    let seccomp = match linux.seccomp() {
        Some(s) => s,
        None => return Ok(()),
    };

    let filter = build_bpf_filter(seccomp)?;
    load_seccomp_filter(&filter)?;

    debug!("seccomp filter applied with {} instructions", filter.len());
    Ok(())
}

/// Convert OCI seccomp action to kernel return value.
fn action_to_ret(action: &LinuxSeccompAction) -> u32 {
    match action {
        LinuxSeccompAction::ScmpActKill => SECCOMP_RET_KILL_THREAD,
        LinuxSeccompAction::ScmpActKillThread => SECCOMP_RET_KILL_THREAD,
        LinuxSeccompAction::ScmpActKillProcess => SECCOMP_RET_KILL_PROCESS,
        LinuxSeccompAction::ScmpActTrap => SECCOMP_RET_TRAP,
        LinuxSeccompAction::ScmpActErrno => SECCOMP_RET_ERRNO | (libc::EPERM as u32),
        LinuxSeccompAction::ScmpActTrace => SECCOMP_RET_TRACE,
        LinuxSeccompAction::ScmpActAllow => SECCOMP_RET_ALLOW,
        LinuxSeccompAction::ScmpActLog => SECCOMP_RET_LOG,
        LinuxSeccompAction::ScmpActNotify => SECCOMP_RET_TRACE,
    }
}

/// Build a BPF filter program from the OCI seccomp spec.
fn build_bpf_filter(seccomp: &LinuxSeccomp) -> Result<Vec<libc::sock_filter>> {
    let mut filter: Vec<libc::sock_filter> = Vec::new();
    let default_action = action_to_ret(&seccomp.default_action());

    // 1. Load architecture and verify it's x86_64
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_ARCH));
    // If arch != x86_64, kill
    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0));
    filter.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. Load syscall number
    filter.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, OFFSET_NR));

    // 3. For each syscall rule, add a comparison + action
    if let Some(syscalls) = seccomp.syscalls() {
        for syscall_rule in syscalls {
            let rule_action = action_to_ret(&syscall_rule.action());

            // Skip rules where action matches the default (they're redundant)
            if rule_action == default_action {
                continue;
            }

            for name in syscall_rule.names() {
                if let Some(nr) = syscall_name_to_nr(name) {
                    // JEQ syscall_nr → return action, else continue
                    filter.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, 0, 1));
                    filter.push(bpf_stmt(BPF_RET | BPF_K, rule_action));
                }
            }
        }
    }

    // 4. Default action
    filter.push(bpf_stmt(BPF_RET | BPF_K, default_action));

    Ok(filter)
}

/// Load a BPF seccomp filter into the kernel.
fn load_seccomp_filter(filter: &[libc::sock_filter]) -> Result<()> {
    // PR_SET_NO_NEW_PRIVS is required before loading seccomp filters
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(other!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        ));
    }

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    let ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER as i64,
            0i64,
            &prog as *const libc::sock_fprog,
        )
    };

    if ret != 0 {
        return Err(other!(
            "seccomp(SET_MODE_FILTER): {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

/// Create a BPF statement (no jump).
fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

/// Create a BPF jump instruction.
fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Map x86_64 syscall names to numbers.
fn syscall_name_to_nr(name: &str) -> Option<u32> {
    // Common x86_64 syscalls (subset — covers the vast majority of OCI profiles)
    match name {
        "read" => Some(0),
        "write" => Some(1),
        "open" => Some(2),
        "close" => Some(3),
        "stat" => Some(4),
        "fstat" => Some(5),
        "lstat" => Some(6),
        "poll" => Some(7),
        "lseek" => Some(8),
        "mmap" => Some(9),
        "mprotect" => Some(10),
        "munmap" => Some(11),
        "brk" => Some(12),
        "rt_sigaction" => Some(13),
        "rt_sigprocmask" => Some(14),
        "rt_sigreturn" => Some(15),
        "ioctl" => Some(16),
        "pread64" => Some(17),
        "pwrite64" => Some(18),
        "readv" => Some(19),
        "writev" => Some(20),
        "access" => Some(21),
        "pipe" => Some(22),
        "select" => Some(23),
        "sched_yield" => Some(24),
        "mremap" => Some(25),
        "msync" => Some(26),
        "mincore" => Some(27),
        "madvise" => Some(28),
        "shmget" => Some(29),
        "shmat" => Some(30),
        "shmctl" => Some(31),
        "dup" => Some(32),
        "dup2" => Some(33),
        "pause" => Some(34),
        "nanosleep" => Some(35),
        "getitimer" => Some(36),
        "alarm" => Some(37),
        "setitimer" => Some(38),
        "getpid" => Some(39),
        "sendfile" => Some(40),
        "socket" => Some(41),
        "connect" => Some(42),
        "accept" => Some(43),
        "sendto" => Some(44),
        "recvfrom" => Some(45),
        "sendmsg" => Some(46),
        "recvmsg" => Some(47),
        "shutdown" => Some(48),
        "bind" => Some(49),
        "listen" => Some(50),
        "getsockname" => Some(51),
        "getpeername" => Some(52),
        "socketpair" => Some(53),
        "setsockopt" => Some(54),
        "getsockopt" => Some(55),
        "clone" => Some(56),
        "fork" => Some(57),
        "vfork" => Some(58),
        "execve" => Some(59),
        "exit" => Some(60),
        "wait4" => Some(61),
        "kill" => Some(62),
        "uname" => Some(63),
        "semget" => Some(64),
        "semop" => Some(65),
        "semctl" => Some(66),
        "shmdt" => Some(67),
        "msgget" => Some(68),
        "msgsnd" => Some(69),
        "msgrcv" => Some(70),
        "msgctl" => Some(71),
        "fcntl" => Some(72),
        "flock" => Some(73),
        "fsync" => Some(74),
        "fdatasync" => Some(75),
        "truncate" => Some(76),
        "ftruncate" => Some(77),
        "getdents" => Some(78),
        "getcwd" => Some(79),
        "chdir" => Some(80),
        "fchdir" => Some(81),
        "rename" => Some(82),
        "mkdir" => Some(83),
        "rmdir" => Some(84),
        "creat" => Some(85),
        "link" => Some(86),
        "unlink" => Some(87),
        "symlink" => Some(88),
        "readlink" => Some(89),
        "chmod" => Some(90),
        "fchmod" => Some(91),
        "chown" => Some(92),
        "fchown" => Some(93),
        "lchown" => Some(94),
        "umask" => Some(95),
        "gettimeofday" => Some(96),
        "getrlimit" => Some(97),
        "getrusage" => Some(98),
        "sysinfo" => Some(99),
        "times" => Some(100),
        "ptrace" => Some(101),
        "getuid" => Some(102),
        "syslog" => Some(103),
        "getgid" => Some(104),
        "setuid" => Some(105),
        "setgid" => Some(106),
        "geteuid" => Some(107),
        "getegid" => Some(108),
        "setpgid" => Some(109),
        "getppid" => Some(110),
        "getpgrp" => Some(111),
        "setsid" => Some(112),
        "setreuid" => Some(113),
        "setregid" => Some(114),
        "getgroups" => Some(115),
        "setgroups" => Some(116),
        "setresuid" => Some(117),
        "getresuid" => Some(118),
        "setresgid" => Some(119),
        "getresgid" => Some(120),
        "getpgid" => Some(121),
        "setfsuid" => Some(122),
        "setfsgid" => Some(123),
        "getsid" => Some(124),
        "capget" => Some(125),
        "capset" => Some(126),
        "rt_sigpending" => Some(127),
        "rt_sigtimedwait" => Some(128),
        "rt_sigqueueinfo" => Some(129),
        "rt_sigsuspend" => Some(130),
        "sigaltstack" => Some(131),
        "utime" => Some(132),
        "mknod" => Some(133),
        "personality" => Some(135),
        "ustat" => Some(136),
        "statfs" => Some(137),
        "fstatfs" => Some(138),
        "sysfs" => Some(139),
        "getpriority" => Some(140),
        "setpriority" => Some(141),
        "sched_setparam" => Some(142),
        "sched_getparam" => Some(143),
        "sched_setscheduler" => Some(144),
        "sched_getscheduler" => Some(145),
        "sched_get_priority_max" => Some(146),
        "sched_get_priority_min" => Some(147),
        "sched_rr_get_interval" => Some(148),
        "mlock" => Some(149),
        "munlock" => Some(150),
        "mlockall" => Some(151),
        "munlockall" => Some(152),
        "vhangup" => Some(153),
        "pivot_root" => Some(155),
        "prctl" => Some(157),
        "arch_prctl" => Some(158),
        "adjtimex" => Some(159),
        "setrlimit" => Some(160),
        "chroot" => Some(161),
        "sync" => Some(162),
        "acct" => Some(163),
        "settimeofday" => Some(164),
        "mount" => Some(165),
        "umount2" => Some(166),
        "swapon" => Some(167),
        "swapoff" => Some(168),
        "reboot" => Some(169),
        "sethostname" => Some(170),
        "setdomainname" => Some(171),
        "ioperm" => Some(173),
        "init_module" => Some(175),
        "delete_module" => Some(176),
        "quotactl" => Some(179),
        "gettid" => Some(186),
        "readahead" => Some(187),
        "setxattr" => Some(188),
        "lsetxattr" => Some(189),
        "fsetxattr" => Some(190),
        "getxattr" => Some(191),
        "lgetxattr" => Some(192),
        "fgetxattr" => Some(193),
        "listxattr" => Some(194),
        "llistxattr" => Some(195),
        "flistxattr" => Some(196),
        "removexattr" => Some(197),
        "lremovexattr" => Some(198),
        "fremovexattr" => Some(199),
        "tkill" => Some(200),
        "time" => Some(201),
        "futex" => Some(202),
        "sched_setaffinity" => Some(203),
        "sched_getaffinity" => Some(204),
        "io_setup" => Some(206),
        "io_destroy" => Some(207),
        "io_getevents" => Some(208),
        "io_submit" => Some(209),
        "io_cancel" => Some(210),
        "lookup_dcookie" => Some(212),
        "epoll_create" => Some(213),
        "remap_file_pages" => Some(216),
        "getdents64" => Some(217),
        "set_tid_address" => Some(218),
        "restart_syscall" => Some(219),
        "semtimedop" => Some(220),
        "fadvise64" => Some(221),
        "timer_create" => Some(222),
        "timer_settime" => Some(223),
        "timer_gettime" => Some(224),
        "timer_getoverrun" => Some(225),
        "timer_delete" => Some(226),
        "clock_settime" => Some(227),
        "clock_gettime" => Some(228),
        "clock_getres" => Some(229),
        "clock_nanosleep" => Some(230),
        "exit_group" => Some(231),
        "epoll_wait" => Some(232),
        "epoll_ctl" => Some(233),
        "tgkill" => Some(234),
        "utimes" => Some(235),
        "mbind" => Some(237),
        "set_mempolicy" => Some(238),
        "get_mempolicy" => Some(239),
        "mq_open" => Some(240),
        "mq_unlink" => Some(241),
        "mq_timedsend" => Some(242),
        "mq_timedreceive" => Some(243),
        "mq_notify" => Some(244),
        "mq_getsetattr" => Some(245),
        "kexec_load" => Some(246),
        "waitid" => Some(247),
        "add_key" => Some(248),
        "request_key" => Some(249),
        "keyctl" => Some(250),
        "ioprio_set" => Some(251),
        "ioprio_get" => Some(252),
        "inotify_init" => Some(253),
        "inotify_add_watch" => Some(254),
        "inotify_rm_watch" => Some(255),
        "openat" => Some(257),
        "mkdirat" => Some(258),
        "mknodat" => Some(259),
        "fchownat" => Some(260),
        "futimesat" => Some(261),
        "newfstatat" => Some(262),
        "unlinkat" => Some(263),
        "renameat" => Some(264),
        "linkat" => Some(265),
        "symlinkat" => Some(266),
        "readlinkat" => Some(267),
        "fchmodat" => Some(268),
        "faccessat" => Some(269),
        "pselect6" => Some(270),
        "ppoll" => Some(271),
        "unshare" => Some(272),
        "set_robust_list" => Some(273),
        "get_robust_list" => Some(274),
        "splice" => Some(275),
        "tee" => Some(276),
        "sync_file_range" => Some(277),
        "vmsplice" => Some(278),
        "move_pages" => Some(279),
        "utimensat" => Some(280),
        "epoll_pwait" => Some(281),
        "signalfd" => Some(282),
        "timerfd_create" => Some(283),
        "eventfd" => Some(284),
        "fallocate" => Some(285),
        "timerfd_settime" => Some(286),
        "timerfd_gettime" => Some(287),
        "accept4" => Some(288),
        "signalfd4" => Some(289),
        "eventfd2" => Some(290),
        "epoll_create1" => Some(291),
        "dup3" => Some(292),
        "pipe2" => Some(293),
        "inotify_init1" => Some(294),
        "preadv" => Some(295),
        "pwritev" => Some(296),
        "rt_tgsigqueueinfo" => Some(297),
        "perf_event_open" => Some(298),
        "recvmmsg" => Some(299),
        "fanotify_init" => Some(300),
        "fanotify_mark" => Some(301),
        "prlimit64" => Some(302),
        "name_to_handle_at" => Some(303),
        "open_by_handle_at" => Some(304),
        "clock_adjtime" => Some(305),
        "syncfs" => Some(306),
        "sendmmsg" => Some(307),
        "setns" => Some(308),
        "getcpu" => Some(309),
        "process_vm_readv" => Some(310),
        "process_vm_writev" => Some(311),
        "kcmp" => Some(312),
        "finit_module" => Some(313),
        "sched_setattr" => Some(314),
        "sched_getattr" => Some(315),
        "renameat2" => Some(316),
        "seccomp" => Some(317),
        "getrandom" => Some(318),
        "memfd_create" => Some(319),
        "kexec_file_load" => Some(320),
        "bpf" => Some(321),
        "execveat" => Some(322),
        "membarrier" => Some(324),
        "mlock2" => Some(325),
        "copy_file_range" => Some(326),
        "preadv2" => Some(327),
        "pwritev2" => Some(328),
        "statx" => Some(332),
        "rseq" => Some(334),
        "pidfd_send_signal" => Some(424),
        "io_uring_setup" => Some(425),
        "io_uring_enter" => Some(426),
        "io_uring_register" => Some(427),
        "open_tree" => Some(428),
        "move_mount" => Some(429),
        "fsopen" => Some(430),
        "fsconfig" => Some(431),
        "fsmount" => Some(432),
        "fspick" => Some(433),
        "pidfd_open" => Some(434),
        "clone3" => Some(435),
        "close_range" => Some(436),
        "openat2" => Some(437),
        "pidfd_getfd" => Some(438),
        "faccessat2" => Some(439),
        "process_madvise" => Some(440),
        "epoll_pwait2" => Some(441),
        "mount_setattr" => Some(442),
        "landlock_create_ruleset" => Some(444),
        "landlock_add_rule" => Some(445),
        "landlock_restrict_self" => Some(446),
        "memfd_secret" => Some(447),
        "process_mrelease" => Some(448),
        "futex_waitv" => Some(449),
        "set_mempolicy_home_node" => Some(450),
        _ => None,
    }
}
