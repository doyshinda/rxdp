use crate::error::XDPError;
use crate::result::XDPResult;
use crate::utils;
use std::{cell::RefCell, os::raw::c_int};

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
    pub fn new(object: *const libbpf_sys::bpf_object, fd: c_int) -> XDPProgram {
        XDPProgram {
            object,
            fd,
            flags: RefCell::new(0u32),
        }
    }

    pub fn attach_to_interface(&self, interface_name: &str, flags: AttachFlags) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, self.fd, flags.bits()) };
        if rc < 0 {
            return Err(XDPError::new("Error attaching to interface"));
        }

        *self.flags.borrow_mut() = flags.bits();
        Ok(())
    }

    pub fn detach(&self, interface_name: &str) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, -1, *self.flags.borrow()) };
        if rc < 0 {
            Err(XDPError::new("Error attaching to interface"))
        } else {
            Ok(())
        }
    }
}
