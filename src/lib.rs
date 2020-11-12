mod error;
mod maps;
mod program;
mod result;
mod utils;
mod map_types;

pub use error::XDPError;
pub use maps::{Map, MapFlags};
pub use map_types::{MapType};
pub use program::{XDPProgram, AttachFlags};
use result::XDPResult;

pub fn load_xdp_program_from_file(file_path: &str) -> XDPResult<XDPProgram> {
    let mut object: *mut libbpf_sys::bpf_object = std::ptr::null_mut();
    let mut fd = -1;

    let rc = unsafe {
        libbpf_sys::bpf_prog_load(
            utils::str_to_cstring(file_path)?.as_ptr(),
            libbpf_sys::BPF_PROG_TYPE_XDP,
            &mut object,
            &mut fd,
        )
    };
    if rc != 0 || fd < 0 {
        return Err(XDPError::new("Error loading XDP program"));
    }

    Ok(XDPProgram::new(object, fd))
}
