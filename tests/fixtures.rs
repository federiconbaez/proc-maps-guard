//! The rules against hand-written maps tables.
use proc_maps_guard::{check, parse_maps, Backing, Policy, Rule};

fn load(name: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn rules(findings: &[proc_maps_guard::Finding]) -> Vec<(usize, Rule)> {
    findings.iter().map(|f| (f.mapping.line, f.rule)).collect()
}

#[test]
fn a_normal_process_is_clean() {
    let maps = parse_maps(&load("clean_x86_64.maps")).unwrap();
    assert_eq!(maps.len(), 19);
    assert!(check(&maps, &Policy::default()).is_empty());
    // vdso and vsyscall are executable but not anonymous memory.
    assert!(maps
        .iter()
        .any(|m| m.backing == Backing::Vsyscall && m.perms.exec && !m.perms.read));
    let strict = Policy {
        exec_prefixes: Some(vec!["/usr/".into()]),
        ..Policy::default()
    };
    assert!(check(&maps, &strict).is_empty());
}

#[test]
fn every_rule_fires_where_expected() {
    let maps = parse_maps(&load("suspicious.maps")).unwrap();
    let f = check(&maps, &Policy::default());
    assert_eq!(
        rules(&f),
        vec![
            (3, Rule::WriteExec),
            (4, Rule::WriteExec),
            (5, Rule::AnonExec),
            (6, Rule::AnonExec),
            (7, Rule::MemfdExec),
            (9, Rule::MemfdExec),
            (10, Rule::DeletedExec),
            (9, Rule::AliasedWriteExec),
        ]
    );
    let alias = f.iter().find(|x| x.rule == Rule::AliasedWriteExec).unwrap();
    assert!(alias.detail.contains("line 8"), "{}", alias.detail);
}

#[test]
fn allowlists_and_prefixes() {
    let maps = parse_maps(&load("suspicious.maps")).unwrap();
    let p = Policy {
        allow_anon_exec: vec!["v8-code".into()],
        allow_write_exec: vec![],
        exec_prefixes: Some(vec!["/usr/".into(), "/opt/app/".into()]),
    };
    let f = check(&maps, &p);
    let r = rules(&f);
    assert!(!r.contains(&(5, Rule::AnonExec)), "allowlisted JIT region");
    assert!(
        r.contains(&(6, Rule::AnonExec)),
        "other anon names still flagged"
    );
    assert!(
        r.contains(&(11, Rule::ExecOutsidePrefixes)),
        "path with a space outside prefixes"
    );
    assert!(!r.iter().any(|&(l, _)| l == 1), "/opt/app is allowed");
    // An allowlisted name never hides an unnamed rwx region.
    assert!(r.contains(&(4, Rule::WriteExec)));
}

#[test]
fn severities_are_ordered() {
    use proc_maps_guard::Severity::*;
    assert!(
        Rule::WriteExec.severity() == Critical && Rule::AliasedWriteExec.severity() == Critical
    );
    assert!(Rule::MemfdExec.severity() == High && Rule::DeletedExec.severity() == Medium);
    assert!(Critical > High && High > Medium);
}
