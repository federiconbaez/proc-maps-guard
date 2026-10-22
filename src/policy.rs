//! Rules over a parsed maps table.

use std::collections::HashMap;
use std::fmt;

use crate::maps::{Backing, Mapping};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Rule {
    /// One mapping that is writable and executable.
    WriteExec,
    /// The same file or memfd mapped shared twice, once writable and once
    /// executable: W^X bypassed through aliasing.
    AliasedWriteExec,
    /// Executable anonymous memory (including heap and stack).
    AnonExec,
    /// Executable memory backed by a memfd: code that never existed on disk.
    MemfdExec,
    /// Executable mapping of a file that has been deleted or replaced.
    DeletedExec,
    /// Executable file mapping outside the configured path prefixes.
    ExecOutsidePrefixes,
}

impl Rule {
    pub fn name(self) -> &'static str {
        match self {
            Rule::WriteExec => "write-exec",
            Rule::AliasedWriteExec => "aliased-write-exec",
            Rule::AnonExec => "anon-exec",
            Rule::MemfdExec => "memfd-exec",
            Rule::DeletedExec => "deleted-exec",
            Rule::ExecOutsidePrefixes => "exec-outside-prefixes",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Rule::WriteExec | Rule::AliasedWriteExec => Severity::Critical,
            Rule::AnonExec | Rule::MemfdExec => Severity::High,
            Rule::DeletedExec | Rule::ExecOutsidePrefixes => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}

/// What is allowed. The default allows nothing and checks no prefixes.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// `[anon:<name>]` regions that may be executable (a JIT's code cache).
    pub allow_anon_exec: Vec<String>,
    /// `[anon:<name>]` regions that may even be writable and executable.
    pub allow_write_exec: Vec<String>,
    /// If set, executable files must live under one of these prefixes.
    pub exec_prefixes: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub rule: Rule,
    pub mapping: Mapping,
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} line {}: {} [{}]",
            self.rule.severity(),
            self.rule.name(),
            self.mapping.line,
            self.detail,
            self.mapping
        )
    }
}

fn anon_name(b: &Backing) -> Option<&str> {
    match b {
        Backing::AnonNamed(n) => Some(n),
        _ => None,
    }
}

/// Applies every rule. Findings come out in maps order, then rule order.
pub fn check(maps: &[Mapping], policy: &Policy) -> Vec<Finding> {
    let mut out = Vec::new();
    let allowed =
        |list: &[String], b: &Backing| anon_name(b).is_some_and(|n| list.iter().any(|a| a == n));

    for m in maps {
        let p = m.perms;
        if p.write && p.exec && !allowed(&policy.allow_write_exec, &m.backing) {
            out.push(Finding {
                rule: Rule::WriteExec,
                mapping: m.clone(),
                detail: format!("{} bytes rwx", m.len()),
            });
        }
        if !p.exec {
            continue;
        }
        // An rwx anonymous mapping is already a write-exec finding.
        if m.backing.is_anonymous()
            && !(p.write && !allowed(&policy.allow_write_exec, &m.backing))
            && !allowed(&policy.allow_anon_exec, &m.backing)
            && !allowed(&policy.allow_write_exec, &m.backing)
        {
            out.push(Finding {
                rule: Rule::AnonExec,
                mapping: m.clone(),
                detail: format!("{} bytes of executable anonymous memory", m.len()),
            });
        }
        match &m.backing {
            Backing::Memfd { name, .. } => out.push(Finding {
                rule: Rule::MemfdExec,
                mapping: m.clone(),
                detail: format!("code mapped from memfd '{name}'"),
            }),
            Backing::File {
                path,
                deleted: true,
            } => out.push(Finding {
                rule: Rule::DeletedExec,
                mapping: m.clone(),
                detail: format!("{path} was deleted or replaced on disk"),
            }),
            Backing::File {
                path,
                deleted: false,
            } => {
                if let Some(prefixes) = &policy.exec_prefixes {
                    if !prefixes.iter().any(|pre| path.starts_with(pre.as_str())) {
                        out.push(Finding {
                            rule: Rule::ExecOutsidePrefixes,
                            mapping: m.clone(),
                            detail: format!("{path} is not under an allowed prefix"),
                        });
                    }
                }
            }
            _ => {}
        }
    }

    // Aliasing: group shared file-backed mappings by (dev, inode).
    type FileKey = ((u32, u32), u64);
    let mut by_file: HashMap<FileKey, (Option<&Mapping>, Option<&Mapping>)> = HashMap::new();
    for m in maps.iter().filter(|m| m.inode != 0 && m.perms.shared) {
        let e = by_file.entry((m.dev, m.inode)).or_default();
        if m.perms.write && e.0.is_none() {
            e.0 = Some(m);
        }
        if m.perms.exec && e.1.is_none() {
            e.1 = Some(m);
        }
    }
    let mut aliased: Vec<_> = by_file
        .into_values()
        .filter_map(|(w, x)| match (w, x) {
            (Some(w), Some(x)) if w.line != x.line => Some((w, x)),
            _ => None,
        })
        .collect();
    aliased.sort_by_key(|(_, x)| x.line);
    for (w, x) in aliased {
        out.push(Finding {
            rule: Rule::AliasedWriteExec,
            mapping: x.clone(),
            detail: format!(
                "executable alias of the writable mapping on line {} (same inode {})",
                w.line, w.inode
            ),
        });
    }
    out
}
