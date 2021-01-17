# rxdp
Rust bindings for working with XDP programs & eBPF maps.

This library has bindings for some of the common, basic operations needed when working with XDP programs & eBPF maps from user-space. It is built on top of [libbpf-sys](https://github.com/alexforster/libbpf-sys). At the time of writing, it supports only a subset of all the possibe eBPF map types (see tests directory for a good indication of which maps are supported).


## Prerequisites
* Linux OS
* libbpf-sys [dependencies](https://github.com/alexforster/libbpf-sys#building)

## Examples
### Create an object from an ELF file
```rust
use rxdp;

let obj_path = "/path/to/elf/file";
let obj = match rxdp::XDPObject::new(obj_path) {
    Ok(obj) => {
        println!("Successfully created object from {}", obj_path);
        obj
    },
    Err(err) => panic!("{:?}", err),
};
```

### Set the pinned maps.
Maps that have already been pinned will be loaded from the fs, provided the map name
matches the name in the fs. Any new maps in the HashSet will set the pin path so that
once the program is loaded, they will get automatically pinned.
```rust
let mut pinned_maps = HashSet::new();
pinned_maps.insert("my_map_name".to_string());
obj.pinned_maps(pinned_maps).unwrap();
```

### Load the object (programs + maps) into the kernel.
This will consume the `XDPObject` created above and return an `XDPLoadedObject`.
```rust
let obj = obj.load().unwrap();
```

### Get a reference to an XDP program and attach it to an interface
```rust
let dev = "eth0";
let flags = rxdp::AttachFlags::SKB_MODE;

let prog = obj.get_program("prog_name").unwrap();
match prog.attach_to_interface(dev, flags) {
    Ok(_) => println!("Successfully attached to {}", dev),
    Err(e) => panic!("{:?}", e),
}
```

### Get access to an underlying eBPF `Map`
```rust
let mut m: rxdp::Map<u32, u64> = match rxdp::Map::new(&obj, "map_name") {
    Ok(m) => m,
    Err(e) => panic!("{:?}", e),
};
```
**NOTE**: the key/value sizes **MUST** match the key/value sizes defined in the eBPF code, otherwise creating the map will fail.

### Perform map operations
```rust
let key = 0u32;
let value = 1000u64;
m.update(&key, &value, rxdp::MapFlags::BpfAny).unwrap();
let got = m.lookup(&key).unwrap();
assert_eq!(value, got);

// iterate through all items
for kv in m.items().unwrap() {
    println!("key: {}, value: {}", kv.key, kv.value);
}
```

## Testing
Running tests requires root access, so it's best to run them in a Docker container:
```sh
make docker-test
```

## Benchmarks
Running benchmarks requires root access, so it's best to run them in a Docker container:
```sh
make docker-bench
```

## Licensing
This crate is released under MIT license and has the following third party depedencies:
|                | Website                                                                        | License                                  | Linkage |
|----------------|--------------------------------------------------------------------------------|------------------------------------------|---------|
| **libbpf-sys** | [github.com/alexforster/libbpf-sys](https://github.com/alexforster/libbpf-sys) | `BSD-2-Clause`                           | Static  |
| **libbpf**     | [github.com/libbpf/libbpf](https://github.com/libbpf/libbpf/)                  | `LGPL-2.1-only OR BSD-2-Clause`          | Static  |
| **libelf**     | [sourceware.org/elfutils](https://sourceware.org/elfutils/)                    | `LGPL-2.1-or-later OR LGPL-3.0-or-later` | Dynamic |
| **zlib**       | [zlib.net](https://www.zlib.net/)                                              | `Zlib`                                   | Dynamic |
