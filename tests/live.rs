//! Creates real suspicious mappings in this process and checks that both the
//! library and the `maps-guard` binary see them, with exact addresses.
use std::ffi::CString;
use std::process::Command;
use std::ptr;

use proc_maps_guard::{check, read_maps, Backing, Finding, Policy, Rule};

const PAGE: usize = 4096;

/// The tests change this process's own memory map; running them in parallel
/// would let one test's mmap shift another's snapshot. Serialize them.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

struct Map(*mut libc::c_void, usize);

impl Map {
    fn anon(len: usize, prot: i32) -> Map {
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                prot,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(
            p,
            libc::MAP_FAILED,
            "mmap: {}",
            std::io::Error::last_os_error()
        );
        Map(p, len)
    }
    fn start(&self) -> u64 {
        self.0 as u64
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        unsafe { libc::munmap(self.0, self.1) };
    }
}

fn findings_at(addr: u64, policy: &Policy) -> Vec<Finding> {
    let maps = read_maps(None).unwrap();
    check(&maps, policy)
        .into_iter()
        .filter(|f| f.mapping.start <= addr && addr < f.mapping.end)
        .collect()
}

fn rules(f: &[Finding]) -> Vec<Rule> {
    f.iter().map(|x| x.rule).collect()
}

#[test]
fn this_test_process_is_clean() {
    let _g = serial();
    let maps = read_maps(None).unwrap();
    let f = check(&maps, &Policy::default());
    assert!(f.is_empty(), "{f:#?}");
}

#[test]
fn rwx_then_rx_then_named() {
    let _g = serial();
    let m = Map::anon(
        3 * PAGE,
        libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
    );
    let f = findings_at(m.start(), &Policy::default());
    assert_eq!(rules(&f), [Rule::WriteExec]);
    // The kernel may merge with a neighbour, but the reported range covers ours.
    assert!(f[0].mapping.start <= m.start() && f[0].mapping.end >= m.start() + 3 * PAGE as u64);

    // W^X done right: drop write, keep exec. Still executable anonymous memory.
    assert_eq!(
        unsafe { libc::mprotect(m.0, m.1, libc::PROT_READ | libc::PROT_EXEC) },
        0
    );
    assert_eq!(
        rules(&findings_at(m.start(), &Policy::default())),
        [Rule::AnonExec]
    );

    // Name the region like a JIT code cache would, then allowlist that name.
    let name = CString::new("c9-jit").unwrap();
    let rc = unsafe {
        libc::prctl(
            libc::PR_SET_VMA,
            libc::PR_SET_VMA_ANON_NAME,
            m.0 as libc::c_ulong,
            m.1,
            name.as_ptr(),
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        assert!(
            std::env::var_os("MAPS_GUARD_REQUIRE_ANON_NAME").is_none(),
            "PR_SET_VMA_ANON_NAME failed: {err}"
        );
        eprintln!("kernel without CONFIG_ANON_VMA_NAME ({err}); named-region part skipped");
        return;
    }
    let f = findings_at(m.start(), &Policy::default());
    assert_eq!(f[0].mapping.backing, Backing::AnonNamed("c9-jit".into()));
    let allow = Policy {
        allow_anon_exec: vec!["c9-jit".into()],
        ..Policy::default()
    };
    assert!(findings_at(m.start(), &allow).is_empty());
    drop(m);
}

#[test]
fn memfd_double_mapping_is_aliased_write_exec() {
    let _g = serial();
    let name = CString::new("alias-test").unwrap();
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    assert!(fd >= 0, "memfd_create: {}", std::io::Error::last_os_error());
    assert_eq!(unsafe { libc::ftruncate(fd, PAGE as i64) }, 0);
    let rw = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    let rx = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_SHARED,
            fd,
            0,
        )
    };
    assert!(rw != libc::MAP_FAILED && rx != libc::MAP_FAILED);
    let (rw, rx) = (Map(rw, PAGE), Map(rx, PAGE));

    // One snapshot for everything below, so line numbers agree.
    let maps = read_maps(None).unwrap();
    let all = check(&maps, &Policy::default());
    let at = |a: u64| {
        all.iter()
            .filter(|x| x.mapping.start <= a && a < x.mapping.end)
            .cloned()
            .collect::<Vec<_>>()
    };
    let f = at(rx.start());
    let mut r = rules(&f);
    r.sort();
    assert_eq!(r, [Rule::AliasedWriteExec, Rule::MemfdExec]);
    assert!(matches!(&f[0].mapping.backing, Backing::Memfd { name, .. } if name == "alias-test"));
    // The writable side alone is not flagged; the alias names it.
    assert!(at(rw.start()).is_empty());
    let alias = f.iter().find(|x| x.rule == Rule::AliasedWriteExec).unwrap();
    let rw_line = maps.iter().find(|m| m.start == rw.start()).unwrap().line;
    assert!(alias.detail.contains(&format!("line {rw_line}")));
    drop((rw, rx));
    unsafe { libc::close(fd) };
}

#[test]
fn executable_file_deleted_while_mapped() {
    let _g = serial();
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!("deleted-exec-{}.bin", std::process::id()));
    std::fs::write(&path, vec![0xC3u8; PAGE]).unwrap();
    let c = CString::new(path.to_str().unwrap()).unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    assert!(fd >= 0);
    let p = unsafe {
        libc::mmap(
            ptr::null_mut(),
            PAGE,
            libc::PROT_READ | libc::PROT_EXEC,
            libc::MAP_PRIVATE,
            fd,
            0,
        )
    };
    assert_ne!(
        p,
        libc::MAP_FAILED,
        "mmap exec (noexec mount?): {}",
        std::io::Error::last_os_error()
    );
    let m = Map(p, PAGE);
    unsafe { libc::close(fd) };
    let outside = Policy {
        exec_prefixes: Some(vec!["/usr/".into()]),
        ..Policy::default()
    };
    assert_eq!(
        rules(&findings_at(m.start(), &outside)),
        [Rule::ExecOutsidePrefixes]
    );
    std::fs::remove_file(&path).unwrap();
    let f = findings_at(m.start(), &Policy::default());
    assert_eq!(rules(&f), [Rule::DeletedExec]);
    assert!(f[0].detail.contains(path.to_str().unwrap()));
}

#[test]
fn cli_reports_another_process() {
    let _g = serial();
    // This test process is "another process" for the CLI: it is spawned
    // with --pid of the test binary.
    let me = std::process::id().to_string();
    let bin = env!("CARGO_BIN_EXE_maps-guard");
    let m = Map::anon(PAGE, libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC);
    let out = Command::new(bin).args(["--pid", &me]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("critical write-exec"), "{stdout}");
    assert!(stdout.contains("rwxp"), "{stdout}");
    drop(m);

    let out = Command::new(bin)
        .args(["--file", "/nonexistent/maps"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let out = Command::new(bin).arg("--bogus").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    let clean = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/clean_x86_64.maps"
    );
    let out = Command::new(bin).args(["--file", clean]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
}
