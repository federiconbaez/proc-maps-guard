//! Audits a process's memory map for code that should not be there:
//! writable and executable pages, executable anonymous memory, code mapped
//! from a memfd or a deleted file, and W^X bypassed by mapping the same file
//! twice. Reads `/proc/<pid>/maps`; never touches the target's memory.

pub mod maps;
pub mod policy;

pub use maps::{parse_maps, Backing, Mapping, ParseError, Perms};
pub use policy::{check, Finding, Policy, Rule, Severity};

use std::io;

/// Reads and parses `/proc/<pid>/maps` (`None` = this process).
pub fn read_maps(pid: Option<u32>) -> io::Result<Vec<Mapping>> {
    let path = match pid {
        Some(p) => format!("/proc/{p}/maps"),
        None => "/proc/self/maps".to_string(),
    };
    let text = std::fs::read_to_string(path)?;
    parse_maps(&text).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
