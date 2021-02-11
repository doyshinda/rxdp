use crate::error::XDPError;
use crate::result::XDPResult;
use crate::utils;

use errno::{set_errno, Errno};
use std::{cell::RefCell, os::raw::c_int};

/// Convenience wrapper around an XDP program
#[allow(dead_code)]
pub struct XDPProgram {
    prog: *const libbpf_sys::bpf_program,
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
    /// Returns the file descriptor for this program.
    pub fn fd(&self) -> i32 {
        self.fd
    }

    pub(crate) fn new(prog: *mut libbpf_sys::bpf_program) -> XDPResult<XDPProgram> {
        let fd = unsafe { libbpf_sys::bpf_program__fd(prog) };
        if fd < 0 {
            fail!("Error getting program fd");
        }
        Ok(XDPProgram {
            prog,
            fd,
            flags: RefCell::new(0u32),
        })
    }

    /// Attaches the XDP program to an interface
    pub fn attach_to_interface(&self, interface_name: &str, flags: AttachFlags) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, self.fd, flags.bits()) };
        if rc < 0 {
            set_errno(Errno(rc * -1));
            fail!("Error attaching to interface");
        }

        *self.flags.borrow_mut() = flags.bits();
        Ok(())
    }

    /// Detaches the XDP program from an interface
    pub fn detach(&self, interface_name: &str) -> XDPResult<()> {
        let if_index = utils::lookup_interface_by_name(interface_name)?;
        let rc = unsafe { libbpf_sys::bpf_set_link_xdp_fd(if_index, -1, *self.flags.borrow()) };
        if rc < 0 {
            fail!("Error attaching to interface");
        }
        Ok(())
    }
}
