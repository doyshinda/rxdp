#![macro_use]

macro_rules! fail {
    ( $n:tt ) => { return Err(XDPError::new($n)) };
    ( $n:literal, $( $arg:tt )* ) => { return Err(XDPError::new(&format!($n, $($arg)*))) };
}
