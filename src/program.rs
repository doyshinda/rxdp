use std::collections::HashSet;

use crate::error::XDPError;
use crate::result::XDPResult;
use crate::utils;
use std::{cell::RefCell, os::raw::c_int};

/// Convenience wrapper around an XDP program
pub struct XDPProgram {
    pub(crate) object: *const libbpf_sys::bpf_object,
    fd: c_int,
    flags: RefCell<u32>,
}

bitflags::bitflags! {
    /// Flags that control how the XDP program is attached to the interface.
    pub struct AttachFlags: u32 {
        const UPDATE_IF_NOEXIST = libbpf_sys::XDP_FLAGS_UPDATE_IF_NOEXIST;
        const SKB_MODE = libbpf_sys::XDP_FLAGS_SKB_MODE;
        const DRV_MODE = libbpf_sys::XDP_FLAGS_DRV_MODE;
        const HW_MODE = libbpf_sys::XDP_FLAGS_HW_MODE;
        const REPLACE = libbpf_sys::XDP_FLAGS_REPLACE;
        const MODES = libbpf_sys::XDP_FLAGS_MODES;
        const MASK = libbpf_sys::XDP_FLAGS_MASK;
    }
}

impl XDPProgram {
    fn new(object: *const libbpf_sys::bpf_object, fd: c_int) -> XDPProgram {
        XDPProgram {
            object,
            fd,
            flags: RefCell::new(0u32),
        }
    }

    /// Attaches the XDP program to an interface
    pub fn attach_to_interface(&self, interface_name: &str, flags: AttachFlags) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, self.fd, flags.bits()) };
        if rc < 0 {
            return Err(XDPError::new("Error attaching to interface"));
        }

        *self.flags.borrow_mut() = flags.bits();
        Ok(())
    }

    /// Detaches the XDP program from an interface
    pub fn detach(&self, interface_name: &str) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, -1, *self.flags.borrow()) };
        if rc < 0 {
            Err(XDPError::new("Error attaching to interface"))
        } else {
            Ok(())
        }
    }

    /// Loads an XDP program from an ELF file. Pins the requested maps to `/sys/fs/bpf/`.
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
                return Err(XDPError::new("Error finding program in ELF file"));
            }
            let fd = libbpf_sys::bpf_program__fd(prog);
            (obj, fd)
        };

        Ok(XDPProgram::new(object, fd))
    }
}
