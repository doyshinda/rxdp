use crossbeam_channel::{unbounded, Receiver, Sender};
use errno::{set_errno, Errno};
use std::marker::PhantomData;

use crate::map_common as mc;
use crate::perf_event_handler::EventHandler;
use crate::{MapType, XDPError, XDPLoadedObject, XDPResult};

/// Used for working with a perf eBPF map.
pub struct PerfMap<T> {
    map_fd: i32,
    _t: PhantomData<T>,
}

/// The event sent from eBPF.
#[derive(Debug)]
pub struct PerfEvent<T> {
    /// The cpu that generated this event.
    pub cpu: i32,
    /// The event type.
    pub event: EventType<T>,
}

/// Event type from eBPF perf event map.
#[derive(Debug)]
pub enum EventType<T> {
    /// The data as generated by the eBPF code.
    Sample(T),
    /// How many events were lost because they weren't read by user-space fast enough.
    Lost(u64),
}

impl<T: 'static + Copy + Send> PerfMap<T> {
    /// Get access to the eBPF map `map_name`.
    ///
    /// # Errors
    ///
    /// Returns an error in the following cases:
    /// * The requested key size doesn't match the key size defined in the ELF file.
    /// * The map_type is not `MapType::PerfEventArray`.
    pub fn new(xdp: &XDPLoadedObject, map_name: &str) -> XDPResult<PerfMap<T>> {
        let (map_fd, _vsize, mtype, _max_entries) = mc::validate_map::<i32>(xdp, map_name)?;
        let map_type: MapType = mtype.into();
        if map_type != MapType::PerfEventArray {
            set_errno(Errno(22));
            fail!("Improper map type, must be MapType::PerfEventArray");
        }
        Ok(PerfMap {
            map_fd,
            _t: PhantomData,
        })
    }

    /// Start polling the underlying eBPF map for events, waiting up to `time_ms` milliseconds
    /// for an event. Returns the receiver side of an unbounded channel, which will receive all
    /// events.
    pub fn start_polling(&mut self, time_ms: i32) -> Receiver<PerfEvent<T>> {
        let (s, r): (Sender<PerfEvent<T>>, Receiver<PerfEvent<T>>) = unbounded();
        let fd = self.map_fd;
        std::thread::spawn(move || {
            let mut e = EventHandler::new(s, fd);
            e.poll(time_ms);
        });
        r
    }
}
