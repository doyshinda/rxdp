#![cfg(target_os = "linux")]

//! Rust bindings for working with XDP programs & eBPF maps.
//!
//! This library has bindings for some of the common, basic operations needed when working with
//! XDP programs & eBPF maps from user-space. It is built on top of [libbpf-sys][1]. At the time
//! of writing, it supports only a subset of all the possibe eBPF map types (see tests directory
//! for a good indication of which maps are supported).
//!
//! ## Prerequisites
//! * Linux OS
//! * libbpf-sys [dependencies][2]
//!
//! [1]: https://github.com/alexforster/libbpf-sys
//! [2]: https://github.com/alexforster/libbpf-sys#building
//!
//! ## Examples
//! ### Create an object from an ELF file
//! ```ignore
//! use rxdp;
//!
//! let obj_path = "/path/to/elf/file";
//! let obj = match rxdp::XDPObject::new(obj_path) {
//!     Ok(obj) => {
//!         println!("Successfully created object from {}", obj_path);
//!         obj
//!     },
//!     Err(err) => panic!("{:?}", err),
//! };
//! ```
//!
//! ### Set the pinned maps.
//! Maps that have already been pinned will be loaded from the fs, provided the map name
//! matches the name in the fs. Any new maps in the HashSet will set the pin path so that
//! once the program is loaded, they will get automatically pinned.
//! ```ignore
//! let mut pinned_maps = HashSet::new();
//! let pin_path = None; // Will default to /sys/fs/bpf
//! pinned_maps.insert("my_map_name".to_string());
//! obj.pinned_maps(pinned_maps, pin_path).unwrap();
//! ```
//!
//! ### Load the object (programs + maps) into the kernel.
//! This will consume the [`XDPObject`](crate::object::XDPObject) created above and return
//! an [`XDPLoadedObject`](crate::object::XDPLoadedObject).
//! ```ignore
//! let obj = obj.load().unwrap();
//! ```
//!
//! ### Get a reference to a specific XDP program and attach it to an interface
//! ```ignore
//! let dev = "eth0";
//! let flags = rxdp::AttachFlags::SKB_MODE;
//!
//! let prog = obj.get_program("prog_name").unwrap();
//! match prog.attach_to_interface(dev, flags) {
//!     Ok(_) => println!("Successfully attached to {}", dev),
//!     Err(e) => panic!("{:?}", e),
//! }
//!```
//!
//! ### Get access to an underlying eBPF [`Map`](crate::maps::Map)
//! ```ignore
//! let m: rxdp::Map<u32, u64> = match rxdp::Map::new(&obj, "map_name") {
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
//!
//! ### Batching support (kernel dependent)
//! If the kernel supports it, you can do batch operations for update/lookups. You can see if
//! batching is supported:
//! ```ignore
//! let m: rxdp::Map<u32, u64> = match rxdp::Map::new(&obj, "map_name").unwrap();
//! println!("batching supported: {}", m.batching_supported());
//! ```

#![doc(html_root_url = "https://docs.rs/rxdp/0.1.0")]

mod error;
mod map_flags;
mod map_types;
mod maps;
mod object;
mod program;
mod result;
mod utils;

pub use error::XDPError;
pub use map_flags::MapFlags;
pub use map_types::MapType;
pub use maps::{BatchResult, Map, KeyValue};
pub use object::{load_pinned_object, XDPLoadedObject, XDPObject};
pub use program::{AttachFlags, XDPProgram};
pub use result::XDPResult;
