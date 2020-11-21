use crate::error::XDPError;
use crate::result::XDPResult;
use crate::utils;

/// Load a pinned object from a path. Returns the object fd.
pub fn load_pinned_object(pin_path: &str) -> XDPResult<i32> {
    let s = utils::str_to_cstring(pin_path)?;
    let prog_fd = unsafe { libbpf_sys::bpf_obj_get(s.as_ptr()) };

    if prog_fd < 0 {
        return Err(XDPError::new("Error retrieving pinned object"));
    }

    Ok(prog_fd)
}
