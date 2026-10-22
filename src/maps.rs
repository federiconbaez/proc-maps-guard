//! Parser for the `/proc/<pid>/maps` format (proc(5)).
//!
//! ```text
//! 7f6ea56ef000-7f6ea56f1000 r-xp 00000000 00:00 0          [vdso]
//! start-end                 perms offset  dev   inode      pathname
//! ```

use std::fmt;

/// What backs a mapping, from the pathname column.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Backing {
    /// No pathname: plain anonymous memory.
    Anon,
    /// `[anon:<name>]`, set with `prctl(PR_SET_VMA_ANON_NAME)`.
    AnonNamed(String),
    /// `[anon_shmem:<name>]`.
    ShmemNamed(String),
    Heap,
    Stack,
    /// `[stack:<tid>]` on old kernels.
    ThreadStack(u32),
    Vdso,
    Vvar,
    Vsyscall,
    /// Any other `[...]` pseudo path.
    Pseudo(String),
    /// `/memfd:<name>`; `deleted` is almost always true.
    Memfd {
        name: String,
        deleted: bool,
    },
    File {
        path: String,
        deleted: bool,
    },
}

impl Backing {
    /// Memory that does not come from a file: anonymous, heap, stack.
    pub fn is_anonymous(&self) -> bool {
        matches!(
            self,
            Backing::Anon
                | Backing::AnonNamed(_)
                | Backing::ShmemNamed(_)
                | Backing::Heap
                | Backing::Stack
                | Backing::ThreadStack(_)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
    /// `s` (shared) instead of `p` (private, copy-on-write).
    pub shared: bool,
}

impl fmt::Display for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = |b: bool, ch: char| if b { ch } else { '-' };
        write!(
            f,
            "{}{}{}{}",
            c(self.read, 'r'),
            c(self.write, 'w'),
            c(self.exec, 'x'),
            if self.shared { 's' } else { 'p' }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    pub perms: Perms,
    pub offset: u64,
    pub dev: (u32, u32),
    pub inode: u64,
    pub backing: Backing,
    /// 1-based line in the input.
    pub line: usize,
}

impl Mapping {
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:x}-{:x} {} {:08x} {:02x}:{:02x} {}",
            self.start, self.end, self.perms, self.offset, self.dev.0, self.dev.1, self.inode
        )?;
        let path = match &self.backing {
            Backing::Anon => return Ok(()),
            Backing::AnonNamed(n) => format!("[anon:{n}]"),
            Backing::ShmemNamed(n) => format!("[anon_shmem:{n}]"),
            Backing::Heap => "[heap]".into(),
            Backing::Stack => "[stack]".into(),
            Backing::ThreadStack(t) => format!("[stack:{t}]"),
            Backing::Vdso => "[vdso]".into(),
            Backing::Vvar => "[vvar]".into(),
            Backing::Vsyscall => "[vsyscall]".into(),
            Backing::Pseudo(p) => p.clone(),
            Backing::Memfd { name, deleted } => {
                format!("/memfd:{name}{}", if *deleted { " (deleted)" } else { "" })
            }
            Backing::File { path, deleted } => {
                format!("{path}{}", if *deleted { " (deleted)" } else { "" })
            }
        };
        write!(f, "                          {path}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    /// 1-based byte column where the bad field starts.
    pub column: usize,
    pub reason: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {}, column {}: {}",
            self.line, self.column, self.reason
        )
    }
}

impl std::error::Error for ParseError {}

/// Splits off the next whitespace-separated field; returns (field, column, rest).
fn field(s: &str, base: usize) -> Option<(&str, usize, &str, usize)> {
    let trimmed = s.trim_start_matches(' ');
    let skipped = s.len() - trimmed.len();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(' ').unwrap_or(trimmed.len());
    let col = base + skipped;
    Some((&trimmed[..end], col, &trimmed[end..], col + end))
}

fn hex(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn parse_backing(p: &str) -> Backing {
    let (p, deleted) = match p.strip_suffix(" (deleted)") {
        Some(rest) => (rest, true),
        None => (p, false),
    };
    if let Some(name) = p.strip_prefix("/memfd:") {
        return Backing::Memfd {
            name: name.to_string(),
            deleted,
        };
    }
    if p.starts_with('[') && p.ends_with(']') && !deleted {
        let inner = &p[1..p.len() - 1];
        return match inner {
            "heap" => Backing::Heap,
            "stack" => Backing::Stack,
            "vdso" => Backing::Vdso,
            "vvar" => Backing::Vvar,
            "vsyscall" => Backing::Vsyscall,
            _ => {
                if let Some(n) = inner.strip_prefix("anon:") {
                    Backing::AnonNamed(n.to_string())
                } else if let Some(n) = inner.strip_prefix("anon_shmem:") {
                    Backing::ShmemNamed(n.to_string())
                } else if let Some(t) = inner.strip_prefix("stack:").and_then(|t| t.parse().ok()) {
                    Backing::ThreadStack(t)
                } else {
                    Backing::Pseudo(p.to_string())
                }
            }
        };
    }
    Backing::File {
        path: p.to_string(),
        deleted,
    }
}

/// Parses one line (without the newline).
pub fn parse_line(line: &str, lineno: usize) -> Result<Mapping, ParseError> {
    let err = |column, reason| ParseError {
        line: lineno,
        column,
        reason,
    };
    let (range, c, rest, n) = field(line, 1).ok_or(err(1, "empty line"))?;
    let (lo, hi) = range
        .split_once('-')
        .ok_or(err(c, "address range needs start-end"))?;
    let start = hex(lo).ok_or(err(c, "bad start address"))?;
    let end = hex(hi).ok_or(err(c + lo.len() + 1, "bad end address"))?;
    if end < start {
        return Err(err(c, "end address below start"));
    }
    let (perms_s, c, rest, n) = field(rest, n).ok_or(err(n, "missing permissions"))?;
    let b = perms_s.as_bytes();
    if b.len() != 4
        || !matches!(b[0], b'r' | b'-')
        || !matches!(b[1], b'w' | b'-')
        || !matches!(b[2], b'x' | b'-')
        || !matches!(b[3], b'p' | b's')
    {
        return Err(err(c, "permissions must look like rwxp"));
    }
    let perms = Perms {
        read: b[0] == b'r',
        write: b[1] == b'w',
        exec: b[2] == b'x',
        shared: b[3] == b's',
    };
    let (off_s, c, rest, n) = field(rest, n).ok_or(err(n, "missing offset"))?;
    let offset = hex(off_s).ok_or(err(c, "bad offset"))?;
    let (dev_s, c, rest, n) = field(rest, n).ok_or(err(n, "missing device"))?;
    let (maj, min) = dev_s
        .split_once(':')
        .ok_or(err(c, "device needs major:minor"))?;
    let dev = (
        u32::from_str_radix(maj, 16).map_err(|_| err(c, "bad device major"))?,
        u32::from_str_radix(min, 16).map_err(|_| err(c, "bad device minor"))?,
    );
    let (inode_s, c, rest, _) = field(rest, n).ok_or(err(n, "missing inode"))?;
    let inode = inode_s.parse().map_err(|_| err(c, "bad inode"))?;
    // Everything after the inode, minus the alignment padding, is the path;
    // it may contain spaces.
    let path = rest.trim_start_matches(' ');
    let backing = if path.is_empty() {
        Backing::Anon
    } else {
        parse_backing(path)
    };
    Ok(Mapping {
        start,
        end,
        perms,
        offset,
        dev,
        inode,
        backing,
        line: lineno,
    })
}

/// Parses a whole maps file. Blank lines are skipped.
pub fn parse_maps(text: &str) -> Result<Vec<Mapping>, ParseError> {
    text.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| parse_line(l, i + 1))
        .collect()
}
