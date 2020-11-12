use libc::if_nametoindex;
use std::{
    convert::TryInto,
    ffi::{CString, CStr},
    os::raw::c_char,
};
use crate::error::XDPError;
use crate::result::XDPResult;

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
    let index = unsafe {if_nametoindex(str_to_cstring(name)?.as_ptr())};
    if index == 0 {
        return Err(XDPError::new(&format!("Error finding interface index for {}", name)));
    }

    match (index as i32).try_into() {
        Ok(i) => Ok(i),
        Err(e) => Err(XDPError::new(&format!("Error converting interface index to 'i32': {}", e))),
    }
}

pub(crate) fn cstring_to_str(char_ptr: *const c_char) -> String {
    let cs = unsafe { CStr::from_ptr(char_ptr) };
    match cs.to_str() {
        Ok(s) => String::from(s),
        Err(_) => String::new(),
    }
}
