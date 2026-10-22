//! maps-guard [--pid N | --file PATH] [--allow-anon-exec NAME]... [--allow-write-exec NAME]...
//!            [--exec-prefix PREFIX]...
//! Exit status: 0 clean, 1 findings, 2 usage or read/parse error.
use std::process::ExitCode;

use proc_maps_guard::{check, parse_maps, Policy};

fn usage() -> ExitCode {
    eprintln!(
        "usage: maps-guard [--pid N | --file PATH] [--allow-anon-exec NAME]... \
         [--allow-write-exec NAME]... [--exec-prefix PREFIX]..."
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let mut source = "/proc/self/maps".to_string();
    let mut policy = Policy::default();
    while let Some(a) = args.next() {
        let Some(v) = args.next() else { return usage() };
        match a.as_str() {
            "--pid" => match v.parse::<u32>() {
                Ok(p) => source = format!("/proc/{p}/maps"),
                Err(_) => return usage(),
            },
            "--file" => source = v,
            "--allow-anon-exec" => policy.allow_anon_exec.push(v),
            "--allow-write-exec" => policy.allow_write_exec.push(v),
            "--exec-prefix" => policy.exec_prefixes.get_or_insert_with(Vec::new).push(v),
            _ => return usage(),
        }
    }
    let text = match std::fs::read_to_string(&source) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{source}: {e}");
            return ExitCode::from(2);
        }
    };
    let maps = match parse_maps(&text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("{source}: {e}");
            return ExitCode::from(2);
        }
    };
    let findings = check(&maps, &policy);
    for f in &findings {
        println!("{f}");
    }
    eprintln!(
        "{source}: {} mappings, {} findings",
        maps.len(),
        findings.len()
    );
    if findings.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
