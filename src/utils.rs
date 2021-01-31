use crate::error::XDPError;
use crate::result::XDPResult;
use libc::if_nametoindex;
use std::{
    convert::TryInto,
    ffi::{CStr, CString},
    os::raw::c_char,
};

pub(crate) fn str_to_cstring(s: &str) -> XDPResult<CString> {
    match CString::new(s) {
        Ok(c) => Ok(c),
        Err(e) => {
            let error_msg = format!("Error creating C string: {:?}", e);
            Err(XDPError::new(&error_msg))
        }
    }
}

pub(crate) fn lookup_interface_by_name(name: &str) -> XDPResult<i32> {
    let index = unsafe { if_nametoindex(str_to_cstring(name)?.as_ptr()) };
    if index == 0 {
        return Err(XDPError::new(&format!(
            "Error finding interface index for {}",
            name
        )));
    }

    match (index as i32).try_into() {
        Ok(i) => Ok(i),
        Err(e) => Err(XDPError::new(&format!(
            "Error converting interface index to 'i32': {}",
            e
        ))),
    }
}

pub(crate) fn cstring_to_str(char_ptr: *const c_char) -> String {
    let cs = unsafe { CStr::from_ptr(char_ptr) };
    match cs.to_str() {
        Ok(s) => String::from(s),
        Err(_) => String::new(),
    }
}

// Returns the number of possible cpus
pub(crate) fn num_cpus() -> XDPResult<usize> {
    let contents = match std::fs::read_to_string("/sys/devices/system/cpu/possible") {
        Ok(c) => c,
        Err(e) => {
            let err_msg = format!("Error getting the number of cpus: {:?}", e);
            return Err(XDPError::new(&err_msg));
        }
    };

    if contents.trim() == "0" {
        return Ok(1);
    }

    let parts: Vec<&str> = contents.trim().split("-").collect();
    if parts.len() != 2 {
        return Err(XDPError::new("Unable to determine number of cpus"));
    }

    let lower = parts[0].parse::<u32>().unwrap_or(0);
    let upper = parts[1].parse::<u32>().unwrap_or(0);

    if upper == 0 {
        return Err(XDPError::new("Unable to determine number of cpus"));
    }

    Ok((upper - lower) as usize + 1 as usize)
}
