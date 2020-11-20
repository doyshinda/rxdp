use std::collections::HashSet;
mod error;
mod map_types;
mod maps;
mod program;
mod result;
mod utils;

pub use error::XDPError;
pub use map_types::MapType;
pub use maps::{Map, MapFlags};
pub use program::{AttachFlags, XDPProgram};
pub use result::XDPResult;

pub fn load_xdp_program_from_file(file_path: &str, maps_to_pin: HashSet<String>)
    -> XDPResult<XDPProgram>
{
    let (object, fd) = unsafe {
        let obj = libbpf_sys::bpf_object__open(utils::str_to_cstring(file_path)?.as_ptr());
        if obj.is_null() {
            return Err(XDPError::new("Error opening ELF file"));
        }

        let mut map: *mut libbpf_sys::bpf_map = std::ptr::null_mut();
        map = libbpf_sys::bpf_map__next(map, obj);
        while !map.is_null() {
            let map_name = libbpf_sys::bpf_map__name(map);
            let r_map_name = utils::cstring_to_str(map_name);
            if maps_to_pin.contains(&r_map_name) {
                let pin_path = utils::str_to_cstring(&format!("/sys/fs/bpf/{}", r_map_name))?;
                println!("pining map: {}", r_map_name);
                let rc = libbpf_sys::bpf_map__set_pin_path(map, pin_path.as_ptr());
                if rc < 0 {
                    return Err(XDPError::new("error setting pin path"));
                }
            }
            map = libbpf_sys::bpf_map__next(map, obj);
        }

        let rc = libbpf_sys::bpf_object__load(obj);
        if rc < 0 {
            return Err(XDPError::new("Error loading object"));
        }

        let mut prog: *mut libbpf_sys::bpf_program = std::ptr::null_mut();
        prog = libbpf_sys::bpf_program__next(prog, obj);
        if prog.is_null() {
            return Err(XDPError::new("Error finding program"));
        }
        let fd = libbpf_sys::bpf_program__fd(prog);
        (obj, fd)
    };

    Ok(XDPProgram::new(object, fd))
}
