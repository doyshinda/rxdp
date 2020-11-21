#![cfg(target_os = "linux")]

//! Rust bindings for working with XDP programs & eBPF maps, using libbpf.
//!
//! ## Prerequisites
//! * Linux OS
//!
//! ## Examples
//! ### Load an XDP program from an ELF file
//! ```ignore
//! use rxdp;
//!
//! let prog_path = "/path/to/elf/file";
//! let prog = match rxdp::XDPProgram::load_xdp_program_from_file(prog_path, HashSet::new()) {
//!     Ok(prog) => {
//!         println!("Successfully loaded {}", prog_path);
//!         prog
//!     },
//!     Err(err) => panic!("{:?}", err),
//! };
//! ```
//!
//! ### Attach XDP program to an interface
//! ```ignore
//! let dev = "eth0";
//! let flags = rxdp::AttachFlags::SKB_MODE;
//! match prog.attach_to_interface(dev, flags) {
//!     Ok(_) => println!("Successfully attached to {}", dev),
//!     Err(e) => panic!("{:?}", e),
//! }
//!```
//!
//! ### Get access to an underlying eBPF [`Map`](crate::maps::Map)
//! ```ignore
//! let mut m: rxdp::Map<u32, u64> = match rxdp::Map::new(&prog, "map_name") {
//!     Ok(m) => m,
//!     Err(e) => panic!("{:?}", e),
//! };
//!```
//! **NOTE**: the key/value sizes **MUST** match the key/value sizes defined in the eBPF code,
//! otherwise creating the map will fail.
//!
//! ### Perform map operations
//! ```ignore
//! let key = 0u32;
//! let value = 1000u64;
//! m.update(&key, &value, rxdp::MapFlags::BpfAny).unwrap();
//! let got = m.lookup(&key).unwrap();
//! assert_eq!(value, got);
//!
//! // iterate through all items
//! for kv in m.items().unwrap() {
//!     println!("key: {}, value: {}", kv.key, kv.value);
//! }
//!```


mod error;
mod map_types;
mod maps;
mod object;
mod program;
mod result;
mod utils;

pub use error::XDPError;
pub use map_types::MapType;
pub use maps::{Map, MapFlags};
pub use object::load_pinned_object;
pub use program::{AttachFlags, XDPProgram};
pub use result::XDPResult;
