use crate::macros::unroll_7;
use crate::macros::unroll_120;
use crate::fs::PathPattern;
use crate::path::MAX_PATH_DEPTH;

const MAX_IDX: usize = MAX_PATH_DEPTH as usize;

/// Classify a path into a PathPattern
/// Returns (pattern, is_sensitive, is_cross_process)
#[inline(always)]
pub unsafe fn classify_path(
    path: &[u8; MAX_IDX],
    current_pid: u32,
) -> (PathPattern, bool, bool) {
    // Check /proc/ (6 bytes)
    if path[0] == b'/'
        && path[1] == b'p'
        && path[2] == b'r'
        && path[3] == b'o'
        && path[4] == b'c'
        && path[5] == b'/'
    {
        return classify_proc(path, 6, current_pid);
    }

    // Check /sys/ (5 bytes)
    if path[0] == b'/'
        && path[1] == b's'
        && path[2] == b'y'
        && path[3] == b's'
        && path[4] == b'/'
    {
        return classify_sys(path, 5);
    }

    // Check /run/ (5 bytes)
    if path[0] == b'/'
        && path[1] == b'r'
        && path[2] == b'u'
        && path[3] == b'n'
        && path[4] == b'/'
    {
        return classify_run(path, 5);
    }

    // Check /dev/ (5 bytes)
    if path[0] == b'/'
        && path[1] == b'd'
        && path[2] == b'e'
        && path[3] == b'v'
        && path[4] == b'/'
    {
        return classify_dev(path, 5);
    }

    // Check /tmp/ (5 bytes)
    if path[0] == b'/'
        && path[1] == b't'
        && path[2] == b'm'
        && path[3] == b'p'
        && path[4] == b'/'
    {
        return classify_tmp(path, 5);
    }

    (PathPattern::Regular, false, false)
}

/// Classify /proc/* paths
/// offset points to the byte after "/proc/" (i.e., 6)
#[inline(always)]
unsafe fn classify_proc(
    path: &[u8; MAX_IDX],
    offset: usize,
    current_pid: u32,
) -> (PathPattern, bool, bool) {
    // Bounds check - if offset is already too high, bail out
    if offset + 5 > MAX_IDX {
        return (PathPattern::ProcGlobal, false, false);
    }

    // Check /proc/self/ (5 bytes: "self/")
    if path[offset] == b's'
        && path[offset + 1] == b'e'
        && path[offset + 2] == b'l'
        && path[offset + 3] == b'f'
        && path[offset + 4] == b'/'
    {
        let new_offset = offset + 5;
        let (pattern, sensitive) = classify_proc_suffix(path, new_offset);
        return (pattern, sensitive, false);
    }

    // Check /proc/[PID]/
    // Parse PID (up to 7 digits: max PID is 4194304)
    let mut pid: u32 = 0;
    let mut pid_len: usize = 0;
    let mut found_non_digit = false;

    unroll_7!(I, {
        if !found_non_digit {
            let idx = offset + I;
            if idx < MAX_IDX {
                let c = path[idx];
                if c >= b'0' && c <= b'9' {
                    pid = pid * 10 + (c - b'0') as u32;
                    pid_len = I + 1;
                } else {
                    found_non_digit = true;
                }
            } else {
                found_non_digit = true;
            }
        }
    });

    // No PID found - this is a global /proc path
    if pid_len == 0 {
        return classify_proc_global(path, offset);
    }

    // Check for slash after PID
    let after_pid_idx = offset + pid_len;
    if after_pid_idx >= MAX_IDX {
        return (PathPattern::ProcGlobal, false, false);
    }

    if path[after_pid_idx] != b'/' {
        return (PathPattern::ProcGlobal, false, false);
    }

    // Get suffix after /proc/PID/
    let suffix_offset = after_pid_idx + 1;
    let is_cross_process = pid != current_pid;
    let (pattern, sensitive) = classify_proc_suffix(path, suffix_offset);

    (pattern, sensitive, is_cross_process)
}

/// Classify the suffix after /proc/[PID]/ or /proc/self/
#[inline(always)]
fn classify_proc_suffix(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool) {
    // Bounds check
    if offset >= MAX_IDX {
        return (PathPattern::ProcPidOther, false);
    }

    let first = path[offset];

    match first {
        0 => (PathPattern::ProcPidOther, false),

        b'c' => classify_proc_suffix_c(path, offset),
        b'e' => classify_proc_suffix_e(path, offset),
        b'f' => classify_proc_suffix_f(path, offset),
        b'm' => classify_proc_suffix_m(path, offset),
        b'n' => classify_proc_suffix_n(path, offset),
        b'r' => classify_proc_suffix_r(path, offset),
        b's' => classify_proc_suffix_s(path, offset),
        b't' => classify_proc_suffix_t(path, offset),

        _ => (PathPattern::ProcPidOther, false),
    }
}

#[inline(always)]
fn classify_proc_suffix_c(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // cmdline (7), comm (4), cwd (3), cgroup (6)
    if offset + 7 <= MAX_IDX
        && path[offset] == b'c'
        && path[offset + 1] == b'm'
        && path[offset + 2] == b'd'
        && path[offset + 3] == b'l'
        && path[offset + 4] == b'i'
        && path[offset + 5] == b'n'
        && path[offset + 6] == b'e'
    {
        return (PathPattern::ProcPidCmdline, false);
    }

    if offset + 6 <= MAX_IDX
        && path[offset] == b'c'
        && path[offset + 1] == b'g'
        && path[offset + 2] == b'r'
        && path[offset + 3] == b'o'
        && path[offset + 4] == b'u'
        && path[offset + 5] == b'p'
    {
        return (PathPattern::ProcPidCgroup, false);
    }

    if offset + 4 <= MAX_IDX
        && path[offset] == b'c'
        && path[offset + 1] == b'o'
        && path[offset + 2] == b'm'
        && path[offset + 3] == b'm'
    {
        return (PathPattern::ProcPidComm, false);
    }

    if offset + 3 <= MAX_IDX
        && path[offset] == b'c'
        && path[offset + 1] == b'w'
        && path[offset + 2] == b'd'
    {
        return (PathPattern::ProcPidCwd, false);
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_e(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // environ (7), exe (3)
    if offset + 7 <= MAX_IDX
        && path[offset] == b'e'
        && path[offset + 1] == b'n'
        && path[offset + 2] == b'v'
        && path[offset + 3] == b'i'
        && path[offset + 4] == b'r'
        && path[offset + 5] == b'o'
        && path[offset + 6] == b'n'
    {
        return (PathPattern::ProcPidEnviron, true); // SENSITIVE
    }

    if offset + 3 <= MAX_IDX
        && path[offset] == b'e'
        && path[offset + 1] == b'x'
        && path[offset + 2] == b'e'
    {
        return (PathPattern::ProcPidExe, false);
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_f(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // fd (2)
    if offset + 2 <= MAX_IDX
        && path[offset] == b'f'
        && path[offset + 1] == b'd'
    {
        return (PathPattern::ProcPidFd, false);
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_m(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // mountinfo (9), mounts (6), maps (4), mem (3)
    if offset + 9 <= MAX_IDX
        && path[offset] == b'm'
        && path[offset + 1] == b'o'
        && path[offset + 2] == b'u'
        && path[offset + 3] == b'n'
        && path[offset + 4] == b't'
        && path[offset + 5] == b'i'
        && path[offset + 6] == b'n'
        && path[offset + 7] == b'f'
        && path[offset + 8] == b'o'
    {
        return (PathPattern::ProcPidMountinfo, false);
    }

    if offset + 6 <= MAX_IDX
        && path[offset] == b'm'
        && path[offset + 1] == b'o'
        && path[offset + 2] == b'u'
        && path[offset + 3] == b'n'
        && path[offset + 4] == b't'
        && path[offset + 5] == b's'
    {
        return (PathPattern::ProcPidMounts, false);
    }

    if offset + 4 <= MAX_IDX
        && path[offset] == b'm'
        && path[offset + 1] == b'a'
        && path[offset + 2] == b'p'
        && path[offset + 3] == b's'
    {
        return (PathPattern::ProcPidMaps, true); // SENSITIVE
    }

    if offset + 3 <= MAX_IDX
        && path[offset] == b'm'
        && path[offset + 1] == b'e'
        && path[offset + 2] == b'm'
    {
        return (PathPattern::ProcPidMem, true); // VERY SENSITIVE
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_n(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // ns (2 or 3 with /), net (3 or 4 with /)
    if offset + 3 <= MAX_IDX
        && path[offset] == b'n'
        && path[offset + 1] == b's'
        && path[offset + 2] == b'/'
    {
        return (PathPattern::ProcPidNs, false);
    }

    if offset + 2 <= MAX_IDX
        && path[offset] == b'n'
        && path[offset + 1] == b's'
    {
        // Check if it's just "ns" (null or slash follows, or at end)
        if offset + 2 == MAX_IDX || path[offset + 2] == 0 || path[offset + 2] == b'/' {
            return (PathPattern::ProcPidNs, false);
        }
    }

    if offset + 4 <= MAX_IDX
        && path[offset] == b'n'
        && path[offset + 1] == b'e'
        && path[offset + 2] == b't'
        && path[offset + 3] == b'/'
    {
        return (PathPattern::ProcPidNet, false);
    }

    if offset + 3 <= MAX_IDX
        && path[offset] == b'n'
        && path[offset + 1] == b'e'
        && path[offset + 2] == b't'
    {
        if offset + 3 == MAX_IDX || path[offset + 3] == 0 || path[offset + 3] == b'/' {
            return (PathPattern::ProcPidNet, false);
        }
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_r(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // root (4)
    if offset + 4 <= MAX_IDX
        && path[offset] == b'r'
        && path[offset + 1] == b'o'
        && path[offset + 2] == b'o'
        && path[offset + 3] == b't'
    {
        return (PathPattern::ProcPidRoot, true); // ESCAPE VECTOR
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_s(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // status (6), stat (4)
    if offset + 6 <= MAX_IDX
        && path[offset] == b's'
        && path[offset + 1] == b't'
        && path[offset + 2] == b'a'
        && path[offset + 3] == b't'
        && path[offset + 4] == b'u'
        && path[offset + 5] == b's'
    {
        return (PathPattern::ProcPidStatus, false);
    }

    if offset + 4 <= MAX_IDX
        && path[offset] == b's'
        && path[offset + 1] == b't'
        && path[offset + 2] == b'a'
        && path[offset + 3] == b't'
    {
        // Make sure it's exactly "stat" not "status" (already checked above)
        if offset + 4 == MAX_IDX || path[offset + 4] == 0 || path[offset + 4] == b'/' {
            return (PathPattern::ProcPidStat, false);
        }
    }

    (PathPattern::ProcPidOther, false)
}

#[inline(always)]
fn classify_proc_suffix_t(path: &[u8; MAX_IDX], offset: usize) -> (PathPattern, bool) {
    // task (4 or 5 with /)
    if offset + 5 <= MAX_IDX
        && path[offset] == b't'
        && path[offset + 1] == b'a'
        && path[offset + 2] == b's'
        && path[offset + 3] == b'k'
        && path[offset + 4] == b'/'
    {
        return (PathPattern::ProcPidTask, false);
    }

    if offset + 4 <= MAX_IDX
        && path[offset] == b't'
        && path[offset + 1] == b'a'
        && path[offset + 2] == b's'
        && path[offset + 3] == b'k'
    {
        if offset + 4 == MAX_IDX || path[offset + 4] == 0 {
            return (PathPattern::ProcPidTask, false);
        }
    }

    (PathPattern::ProcPidOther, false)
}

/// Classify global /proc paths (not /proc/PID/ or /proc/self/)
#[inline(always)]
fn classify_proc_global(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool, bool) {
    // sys/ (4)
    if offset + 4 <= MAX_IDX
        && path[offset] == b's'
        && path[offset + 1] == b'y'
        && path[offset + 2] == b's'
        && path[offset + 3] == b'/'
    {
        return (PathPattern::ProcGlobalSys, false, false);
    }

    // net/ (4)
    if offset + 4 <= MAX_IDX
        && path[offset] == b'n'
        && path[offset + 1] == b'e'
        && path[offset + 2] == b't'
        && path[offset + 3] == b'/'
    {
        return (PathPattern::ProcGlobalNet, false, false);
    }

    (PathPattern::ProcGlobal, false, false)
}

/// Classify /sys/* paths
#[inline(always)]
unsafe fn classify_sys(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool, bool) {
    // Check for docker pattern first
    if contains_docker(path) {
        return (PathPattern::SysCgroupDocker, false, false);
    }

    // fs/cgroup (9)
    if offset + 9 <= MAX_IDX
        && path[offset] == b'f'
        && path[offset + 1] == b's'
        && path[offset + 2] == b'/'
        && path[offset + 3] == b'c'
        && path[offset + 4] == b'g'
        && path[offset + 5] == b'r'
        && path[offset + 6] == b'o'
        && path[offset + 7] == b'u'
        && path[offset + 8] == b'p'
    {
        return (PathPattern::SysCgroupOther, false, false);
    }

    // class/net/ (10)
    if offset + 10 <= MAX_IDX
        && path[offset] == b'c'
        && path[offset + 1] == b'l'
        && path[offset + 2] == b'a'
        && path[offset + 3] == b's'
        && path[offset + 4] == b's'
        && path[offset + 5] == b'/'
        && path[offset + 6] == b'n'
        && path[offset + 7] == b'e'
        && path[offset + 8] == b't'
        && path[offset + 9] == b'/'
    {
        return (PathPattern::SysClassNet, false, false);
    }

    (PathPattern::SysOther, false, false)
}

/// Classify /run/* paths
#[inline(always)]
fn classify_run(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool, bool) {
    // docker/ (7)
    if offset + 7 <= MAX_IDX
        && path[offset] == b'd'
        && path[offset + 1] == b'o'
        && path[offset + 2] == b'c'
        && path[offset + 3] == b'k'
        && path[offset + 4] == b'e'
        && path[offset + 5] == b'r'
        && path[offset + 6] == b'/'
    {
        return (PathPattern::RunDocker, false, false);
    }

    // user/ (5)
    if offset + 5 <= MAX_IDX
        && path[offset] == b'u'
        && path[offset + 1] == b's'
        && path[offset + 2] == b'e'
        && path[offset + 3] == b'r'
        && path[offset + 4] == b'/'
    {
        return (PathPattern::RunUser, false, false);
    }

    (PathPattern::RunOther, false, false)
}

/// Classify /dev/* paths
#[inline(always)]
fn classify_dev(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool, bool) {
    // pts/ (4)
    if offset + 4 <= MAX_IDX
        && path[offset] == b'p'
        && path[offset + 1] == b't'
        && path[offset + 2] == b's'
        && path[offset + 3] == b'/'
    {
        return (PathPattern::DevPts, false, false);
    }

    // shm/ (4)
    if offset + 4 <= MAX_IDX
        && path[offset] == b's'
        && path[offset + 1] == b'h'
        && path[offset + 2] == b'm'
        && path[offset + 3] == b'/'
    {
        return (PathPattern::DevShm, false, false);
    }

    (PathPattern::DevOther, false, false)
}

/// Classify /tmp/* paths
#[inline(always)]
fn classify_tmp(
    path: &[u8; MAX_IDX],
    offset: usize,
) -> (PathPattern, bool, bool) {
    // tmp (3)
    if offset + 3 <= MAX_IDX
        && path[offset] == b't'
        && path[offset + 1] == b'm'
        && path[offset + 2] == b'p'
    {
        return (PathPattern::TmpRandom, false, false);
    }

    (PathPattern::TmpOther, false, false)
}

/// Check if path contains "/docker/" anywhere
#[inline(always)]
fn contains_docker(path: &[u8; MAX_IDX]) -> bool {
    let mut found = false;

    // Need 8 bytes for "/docker/", so max start position is MAX_IDX - 8
    unroll_120!(I, {
        if !found && I + 8 <= MAX_IDX {
            if path[I] == 0 {
                // Hit null terminator, stop checking further
                // Can't break in unroll, but found stays false
            } else if path[I] == b'/'
                && path[I + 1] == b'd'
                && path[I + 2] == b'o'
                && path[I + 3] == b'c'
                && path[I + 4] == b'k'
                && path[I + 5] == b'e'
                && path[I + 6] == b'r'
                && path[I + 7] == b'/'
            {
                found = true;
            }
        }
    });

    found
}
