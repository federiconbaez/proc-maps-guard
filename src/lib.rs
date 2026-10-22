//! Parser for /proc/<pid>/maps. Rules come next.

pub mod maps;

pub use maps::{parse_maps, Backing, Mapping, ParseError, Perms};
