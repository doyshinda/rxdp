use crossbeam_channel::Sender;
use libbpf_sys as bpf;
use std::os::raw::c_void;

use crate::perf_map::{EventType, PerfEvent};

pub(crate) struct EventHandler<T> {
    sender: Sender<PerfEvent<T>>,
    pb: *mut bpf::perf_buffer,
    map_fd: i32,
}

impl<T: Copy> EventHandler<T> {
    pub(crate) fn new(s: Sender<PerfEvent<T>>, map_fd: i32) -> EventHandler<T> {
        EventHandler {
            sender: s,
            pb: std::ptr::null_mut(),
            map_fd,
        }
    }

    fn init_perf_buffer(&mut self) {
        let pb_opts = bpf::perf_buffer_opts {
            sample_cb: Some(EventHandler::<T>::sample_event),
            lost_cb: Some(EventHandler::<T>::lost_event),
            ctx: self as *mut _ as *mut c_void,
        };

        self.pb = unsafe { bpf::perf_buffer__new(self.map_fd, 8, &pb_opts) };
    }

    pub(crate) fn poll(&mut self, time_ms: i32) {
        self.init_perf_buffer();
        loop {
            unsafe { bpf::perf_buffer__poll(self.pb, time_ms) };
        }
    }

    fn send_perf_event(&self, cpu: i32, event: EventType<T>) {
        self.sender.send(PerfEvent { cpu, event }).ok();
    }

    fn handle_sample_event(&self, cpu: i32, data: *mut c_void, _size: u32) {
        let r: &mut T = unsafe { &mut *(data as *mut T) };
        self.send_perf_event(cpu, EventType::Sample(*r));
    }

    fn handle_lost_event(&self, cpu: i32, cnt: u64) {
        self.send_perf_event(cpu, EventType::Lost(cnt));
    }

    #[no_mangle]
    unsafe extern "C" fn sample_event(ctx: *mut c_void, cpu: i32, data: *mut c_void, size: u32) {
        let handler: &mut EventHandler<T> = &mut *(ctx as *mut EventHandler<T>);
        handler.handle_sample_event(cpu, data, size);
    }

    #[no_mangle]
    unsafe extern "C" fn lost_event(ctx: *mut c_void, cpu: i32, cnt: u64) {
        let handler: &mut EventHandler<T> = &mut *(ctx as *mut EventHandler<T>);
        handler.handle_lost_event(cpu, cnt);
    }
}

impl<T> Drop for EventHandler<T> {
    fn drop(&mut self) {
        unsafe { bpf::perf_buffer__free(self.pb) }
    }
}
