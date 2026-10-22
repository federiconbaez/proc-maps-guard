//! Parser details, errors with positions, and round-trips.
use proc_maps_guard::maps::parse_line;
use proc_maps_guard::{parse_maps, Backing, Mapping, Perms};
use proptest::prelude::*;

#[test]
fn fields_and_backings() {
    let m = parse_line(
        "7f2c48000000-7f2c48001000 r-xp 00000000 00:01 4242 /memfd:payload (deleted)",
        7,
    )
    .unwrap();
    assert_eq!(
        (m.start, m.end, m.len(), m.line),
        (0x7f2c48000000, 0x7f2c48001000, 4096, 7)
    );
    assert_eq!(
        m.perms,
        Perms {
            read: true,
            write: false,
            exec: true,
            shared: false
        }
    );
    assert_eq!((m.dev, m.inode), ((0, 1), 4242));
    assert_eq!(
        m.backing,
        Backing::Memfd {
            name: "payload".into(),
            deleted: true
        }
    );

    let cases = [
        ("", Backing::Anon),
        ("[heap]", Backing::Heap),
        ("[stack]", Backing::Stack),
        ("[stack:1234]", Backing::ThreadStack(1234)),
        ("[vdso]", Backing::Vdso),
        ("[vvar]", Backing::Vvar),
        ("[vsyscall]", Backing::Vsyscall),
        (
            "[anon:glibc.malloc]",
            Backing::AnonNamed("glibc.malloc".into()),
        ),
        ("[anon_shmem:ring]", Backing::ShmemNamed("ring".into())),
        ("[uprobes]", Backing::Pseudo("[uprobes]".into())),
        (
            "/a b/c (deleted)",
            Backing::File {
                path: "/a b/c".into(),
                deleted: true,
            },
        ),
        (
            "/usr/lib/x.so",
            Backing::File {
                path: "/usr/lib/x.so".into(),
                deleted: false,
            },
        ),
    ];
    for (path, want) in cases {
        let line = format!("1000-2000 rw-p 00000000 08:02 0          {path}");
        assert_eq!(parse_line(&line, 1).unwrap().backing, want, "{path:?}");
    }
    // 32-bit style short addresses and an 8-hex-digit device major work too.
    let m = parse_line("08048000-08049000 r-xp 00000000 103:02 12 /bin/x", 1).unwrap();
    assert_eq!((m.start, m.dev), (0x08048000, (0x103, 2)));
}

#[test]
fn errors_point_at_the_field() {
    let cases = [
        ("", 1, "empty line"),
        ("zz-10 r-xp 0 00:00 0", 1, "bad start address"),
        ("10-zz r-xp 0 00:00 0", 4, "bad end address"),
        ("20-10 r-xp 0 00:00 0", 1, "end address below start"),
        ("10 r-xp 0 00:00 0", 1, "address range needs start-end"),
        ("10-20 rwz 0 00:00 0", 7, "permissions must look like rwxp"),
        ("10-20 rwxq 0 00:00 0", 7, "permissions must look like rwxp"),
        ("10-20 rwxp", 11, "missing offset"),
        ("10-20 rwxp g 00:00 0", 12, "bad offset"),
        ("10-20 rwxp 0 0000 0", 14, "device needs major:minor"),
        ("10-20 rwxp 0 00:00", 19, "missing inode"),
        ("10-20 rwxp 0 00:00 -1", 20, "bad inode"),
        ("10-11111111111111111 rwxp 0 00:00 0", 4, "bad end address"),
    ];
    for (line, col, reason) in cases {
        let e = parse_line(line, 5).unwrap_err();
        assert_eq!((e.line, e.column, e.reason), (5, col, reason), "{line:?}");
    }
    let e = parse_maps("1000-2000 r--p 0 00:00 0\n\nbroken\n").unwrap_err();
    assert_eq!(e.line, 3);
}

#[test]
fn this_process_parses() {
    let text = std::fs::read_to_string("/proc/self/maps").unwrap();
    let maps = parse_maps(&text).unwrap();
    assert!(maps.len() > 5);
    assert!(maps.iter().any(|m| m.backing == Backing::Stack));
    // Entries are sorted and do not overlap.
    assert!(maps.windows(2).all(|w| w[0].end <= w[1].start));
}

fn backing() -> impl Strategy<Value = Backing> {
    let name = "[a-z][a-z0-9._-]{0,12}";
    let path = "/[a-z]{1,6}(/[a-z .]{1,8}){0,3}";
    prop_oneof![
        Just(Backing::Anon),
        Just(Backing::Heap),
        Just(Backing::Stack),
        Just(Backing::Vdso),
        name.prop_map(Backing::AnonNamed),
        (name, any::<bool>()).prop_map(|(name, deleted)| Backing::Memfd { name, deleted }),
        (path, any::<bool>()).prop_map(|(p, deleted)| Backing::File {
            path: p.trim_end().to_string(),
            deleted
        }),
    ]
}

proptest! {
    #[test]
    fn display_parse_round_trip(
        start in 0u64..(1 << 47), len in 1u64..(1 << 30),
        r in any::<bool>(), w in any::<bool>(), x in any::<bool>(), s in any::<bool>(),
        offset in any::<u32>(), maj in 0u32..0x1000, min in 0u32..0x100, inode in any::<u64>(),
        backing in backing(),
    ) {
        let m = Mapping {
            start, end: start + len,
            perms: Perms { read: r, write: w, exec: x, shared: s },
            offset: offset as u64, dev: (maj, min), inode, backing, line: 1,
        };
        let line = m.to_string();
        prop_assert_eq!(parse_line(&line, 1).unwrap(), m);
    }

    #[test]
    fn arbitrary_text_never_panics(s in "\\PC{0,120}") {
        let _ = parse_maps(&s);
    }
}
