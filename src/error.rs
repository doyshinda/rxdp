use errno::{errno, set_errno, Errno};
use std::fmt;

/// Error information about the attempted BPF operation
/// # Example
/// ```
/// # use errno::{Errno, set_errno};
/// # use rxdp::XDPError;
/// set_errno(Errno(22));
///
/// let e = XDPError::new("My error message");
/// assert_eq!(e.code(), 22);
/// assert_eq!(e.description(), "My error message: Invalid argument");
///```
#[derive(Debug)]
pub struct XDPError {
    code: i32,
    description: String,
}

impl XDPError {
    pub fn new(err_msg: &str) -> Self {
        let mut e = errno();

        // Re-map ENOTSUPP -> ENOTSUP
        if e.0 == 524 {
            e = Errno(95)
        }
        XDPError {
            description: format!("{}: {}", err_msg, e),
            code: e.0,
        }
    }

    pub fn code(&self) -> i32 {
        self.code
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}

impl fmt::Display for XDPError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [errno: {}]", self.description, self.code)
    }
}

pub(crate) fn reset_errno() {
    set_errno(Errno(0));
}

pub(crate) fn get_errno() -> i32 {
    errno().0
}
